//! A deliberately narrow tar reader.
//!
//! A bundle is an artifact pulled from a registry and unpacked on every node in
//! the fleet, so extraction is a security boundary. Rather than use a general
//! tar library and try to sanitise what comes out, this reads only what a
//! policy bundle legitimately is — regular files with ordinary relative names —
//! and refuses everything else outright: absolute paths, `..` components,
//! symlinks, hard links, device nodes, setuid bits.
//!
//! Refusing is better than sanitising. A bundle containing `../../etc/passwd`
//! is either broken or hostile, and silently rewriting the path would hide
//! both.

use super::Error;

const BLOCK: usize = 512;

/// One file from a bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// A relative path with no `.` or `..` components.
    pub path: String,
    pub content: Vec<u8>,
}

/// Read a POSIX tar, returning its regular files in archive order.
pub fn extract(archive: &[u8], max_total: usize) -> Result<Vec<Entry>, Error> {
    let mut entries = Vec::new();
    let mut offset = 0;
    let mut total = 0usize;

    while offset + BLOCK <= archive.len() {
        let header = &archive[offset..offset + BLOCK];
        // Two consecutive zero blocks end the archive; one is enough for us.
        if header.iter().all(|b| *b == 0) {
            break;
        }
        offset += BLOCK;

        let name = field(header, 0, 100)?;
        let prefix = field(header, 345, 155).unwrap_or_default();
        let size = octal(header, 124, 12)?;
        let type_flag = header[156];

        // GNU long-name entries and PAX headers carry metadata, not content.
        // A policy bundle has no need for either.
        match type_flag {
            b'0' | 0 => {}
            b'5' => {
                // A directory entry carries no content; directories are created
                // from file paths anyway.
                offset += size.div_ceil(BLOCK) * BLOCK;
                continue;
            }
            other => {
                return Err(Error::Rejected(format!(
                "bundle entry {name:?} has type {:?}, and a bundle may contain only regular files",
                other as char
            )))
            }
        }

        // Reject a setuid, setgid or sticky bit before it ever reaches disk.
        let mode = octal(header, 100, 8)?;
        if mode & 0o7000 != 0 {
            return Err(Error::Rejected(format!(
                "bundle entry {name:?} sets mode {mode:o}, which is not allowed"
            )));
        }

        let path = if prefix.is_empty() {
            name
        } else {
            format!("{prefix}/{name}")
        };
        let path = check_path(&path)?;

        total += size;
        if total > max_total {
            return Err(Error::Rejected(format!(
                "bundle unpacks to more than the {max_total} byte limit"
            )));
        }
        if offset + size > archive.len() {
            return Err(Error::Malformed(format!(
                "bundle entry {path:?} claims {size} bytes but the archive ends first"
            )));
        }

        entries.push(Entry {
            path,
            content: archive[offset..offset + size].to_vec(),
        });
        offset += size.div_ceil(BLOCK) * BLOCK;
    }

    if entries.is_empty() {
        return Err(Error::Rejected("bundle contains no files".into()));
    }
    Ok(entries)
}

/// Accept only a relative path made of ordinary segments.
fn check_path(raw: &str) -> Result<String, Error> {
    let path = raw.trim_start_matches("./");
    if path.is_empty() {
        return Err(Error::Rejected(
            "bundle contains an entry with no name".into(),
        ));
    }
    if path.starts_with('/') {
        return Err(Error::Rejected(format!(
            "bundle entry {raw:?} is an absolute path"
        )));
    }
    if path.contains('\\') || path.contains('\0') {
        return Err(Error::Rejected(format!(
            "bundle entry {raw:?} contains a character not allowed in a path"
        )));
    }
    for segment in path.split('/') {
        if segment.is_empty() {
            return Err(Error::Rejected(format!(
                "bundle entry {raw:?} has an empty path segment"
            )));
        }
        if segment == "." || segment == ".." {
            return Err(Error::Rejected(format!(
                "bundle entry {raw:?} tries to escape the bundle directory"
            )));
        }
    }
    Ok(path.to_string())
}

fn field(header: &[u8], at: usize, len: usize) -> Result<String, Error> {
    let slice = &header[at..at + len];
    let end = slice.iter().position(|b| *b == 0).unwrap_or(len);
    std::str::from_utf8(&slice[..end])
        .map(|s| s.trim().to_string())
        .map_err(|_| Error::Malformed("bundle header is not valid UTF-8".into()))
}

fn octal(header: &[u8], at: usize, len: usize) -> Result<usize, Error> {
    let text = field(header, at, len)?;
    let text = text.trim_matches(|c: char| c == ' ' || c == '\0');
    if text.is_empty() {
        return Ok(0);
    }
    usize::from_str_radix(text, 8)
        .map_err(|_| Error::Malformed(format!("bundle header field {text:?} is not octal")))
}

#[cfg(test)]
pub mod testkit {
    //! Building tars, for tests. Nothing in svidlet writes one.

    use super::BLOCK;

    pub fn build(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        for (name, content) in files {
            out.extend_from_slice(&header(name, content.len(), b'0', 0o644));
            out.extend_from_slice(content);
            let padding = (BLOCK - content.len() % BLOCK) % BLOCK;
            out.extend(std::iter::repeat_n(0u8, padding));
        }
        out.extend(std::iter::repeat_n(0u8, BLOCK * 2));
        out
    }

    /// A tar with one entry of an arbitrary type flag and mode, for the cases
    /// a normal archiver will not produce.
    pub fn build_raw(name: &str, content: &[u8], type_flag: u8, mode: u32) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&header(name, content.len(), type_flag, mode));
        out.extend_from_slice(content);
        let padding = (BLOCK - content.len() % BLOCK) % BLOCK;
        out.extend(std::iter::repeat_n(0u8, padding));
        out.extend(std::iter::repeat_n(0u8, BLOCK * 2));
        out
    }

    fn header(name: &str, size: usize, type_flag: u8, mode: u32) -> [u8; BLOCK] {
        let mut block = [0u8; BLOCK];
        let bytes = name.as_bytes();
        block[..bytes.len().min(100)].copy_from_slice(&bytes[..bytes.len().min(100)]);
        write_octal(&mut block[100..108], mode as usize);
        write_octal(&mut block[108..116], 0);
        write_octal(&mut block[116..124], 0);
        write_octal(&mut block[124..136], size);
        write_octal(&mut block[136..148], 0);
        block[156] = type_flag;
        block[257..262].copy_from_slice(b"ustar");
        block[263..265].copy_from_slice(b"00");

        // The checksum is computed with the checksum field read as spaces.
        block[148..156].fill(b' ');
        let sum: usize = block.iter().map(|b| *b as usize).sum();
        write_octal(&mut block[148..155], sum);
        block[155] = b' ';
        block
    }

    fn write_octal(field: &mut [u8], value: usize) {
        let text = format!("{:0width$o}", value, width = field.len() - 1);
        field[..text.len()].copy_from_slice(text.as_bytes());
        field[field.len() - 1] = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::testkit::{build, build_raw};
    use super::*;

    const LIMIT: usize = 10 * 1024 * 1024;

    #[test]
    fn regular_files_come_out_in_order_with_their_content() {
        let tar = build(&[
            ("bundle.toml", b"schema = 1\n"),
            ("rules/allow.rego", b"allow := true"),
        ]);
        let entries = extract(&tar, LIMIT).unwrap();

        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].path, "bundle.toml");
        assert_eq!(entries[0].content, b"schema = 1\n");
        assert_eq!(entries[1].path, "rules/allow.rego");
        assert_eq!(entries[1].content, b"allow := true");
    }

    #[test]
    fn a_leading_dot_slash_is_normalised_away() {
        let entries = extract(&build(&[("./bundle.toml", b"x")]), LIMIT).unwrap();
        assert_eq!(entries[0].path, "bundle.toml");
    }

    #[test]
    fn content_of_every_length_survives_block_padding() {
        for size in [0usize, 1, 511, 512, 513, 1024, 2000] {
            let content: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
            let entries = extract(&build(&[("a", &content), ("b", b"tail")]), LIMIT).unwrap();
            assert_eq!(entries[0].content, content, "size {size}");
            assert_eq!(entries[1].content, b"tail", "size {size}");
        }
    }

    #[test]
    fn paths_that_escape_the_bundle_are_refused() {
        for bad in [
            "../etc/passwd",
            "a/../../etc/passwd",
            "/etc/passwd",
            "a//b",
            "a/./b",
            "..",
        ] {
            let err = extract(&build(&[(bad, b"x")]), LIMIT).unwrap_err();
            assert!(
                matches!(err, Error::Rejected(_)),
                "{bad:?} should be rejected, got {err}"
            );
        }
    }

    #[test]
    fn only_regular_files_are_accepted() {
        // Symlink, hard link, character device, fifo.
        for type_flag in [b'1', b'2', b'3', b'4', b'6'] {
            let tar = build_raw("evil", b"", type_flag, 0o644);
            let err = extract(&tar, LIMIT).unwrap_err();
            assert!(
                matches!(err, Error::Rejected(_)),
                "type {} should be rejected",
                type_flag as char
            );
        }

        // A directory entry is skipped rather than refused: an archiver adding
        // one is ordinary, and the directories are made from file paths anyway.
        let mut tar = build_raw("rules/", b"", b'5', 0o755);
        tar.truncate(tar.len() - BLOCK * 2);
        tar.extend_from_slice(&build(&[("rules/a.rego", b"x")]));
        let entries = extract(&tar, LIMIT).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].path, "rules/a.rego");
    }

    #[test]
    fn setuid_and_friends_are_refused() {
        for mode in [0o4755, 0o2755, 0o1755] {
            let err = extract(&build_raw("a", b"x", b'0', mode), LIMIT).unwrap_err();
            assert!(matches!(err, Error::Rejected(_)), "mode {mode:o}");
        }
        assert!(extract(&build_raw("a", b"x", b'0', 0o644), LIMIT).is_ok());
    }

    #[test]
    fn the_size_limit_is_enforced_across_the_whole_archive() {
        // Neither file alone exceeds the limit; together they do.
        let tar = build(&[("a", &vec![0u8; 600]), ("b", &vec![0u8; 600])]);
        let err = extract(&tar, 1000).unwrap_err();
        assert!(matches!(err, Error::Rejected(_)));
        assert!(err.to_string().contains("1000 byte limit"));

        assert!(extract(&tar, 2000).is_ok());
    }

    #[test]
    fn a_truncated_archive_is_malformed_not_silently_short() {
        let mut tar = build(&[("a", &vec![7u8; 2000])]);
        tar.truncate(600);
        let err = extract(&tar, LIMIT).unwrap_err();
        assert!(matches!(err, Error::Malformed(_)), "{err}");
    }

    #[test]
    fn an_empty_archive_is_rejected() {
        assert!(matches!(
            extract(&[0u8; 1024], LIMIT),
            Err(Error::Rejected(_))
        ));
        assert!(matches!(extract(&[], LIMIT), Err(Error::Rejected(_))));
    }

    #[test]
    fn a_corrupt_header_is_malformed() {
        let mut tar = build(&[("a", b"x")]);
        tar[124..136].copy_from_slice(b"not octal!!!");
        assert!(matches!(extract(&tar, LIMIT), Err(Error::Malformed(_))));
    }
}
