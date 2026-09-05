//! Publishing material into a pod's volume.
//!
//! Each target path is a private tmpfs, so the private key never touches the
//! node's disk. Inside it, files are published the way the kubelet publishes
//! Secret volumes: a versioned directory plus a symlink that is swapped with
//! `rename(2)`.
//!
//! There are **two independent swap chains** in one volume:
//!
//! ```text
//! ..data        -> ..svidlet.N/    tls.crt, tls.key, ca.crt   (written by svidlet)
//! ..policy-data -> ..policy.N/     policy/, policy.revision   (written by svidlet-policy)
//! ```
//!
//! Each writer only ever creates its own versioned directories and renames its
//! own symlink, so the two processes never share mutable state and never need
//! to coordinate. That is what lets identity issuance and policy distribution
//! run as separate processes with separate credentials while still landing in
//! the same CSI volume — see docs/DESIGN.md, "Two processes, one volume".
//!
//! Each chain is atomic on its own: a certificate renewal replaces `tls.crt`,
//! `tls.key` and `ca.crt` as one step, and a policy update replaces the whole
//! policy directory as one step. Neither can be observed half-written, and
//! neither disturbs the other.

use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use crate::config::{CA_FILE, CERT_FILE, KEY_FILE, POLICY_DIR, REVISION_FILE};
use crate::policy::PolicyBundle;

/// The identity chain, written by svidlet.
const DATA_LINK: &str = "..data";
const VERSION_PREFIX: &str = "..svidlet.";

/// The policy chain, written by svidlet-policy.
const POLICY_LINK: &str = "..policy-data";
const POLICY_VERSION_PREFIX: &str = "..policy.";

/// The certificate and its key. One atomic swap.
pub struct Identity {
    pub key_pem: String,
    pub cert_chain_pem: String,
    pub ca_pem: String,
}

#[derive(Debug, Clone, Copy)]
pub struct Modes {
    pub key: u32,
    pub cert: u32,
}

/// Create the target directory and back it with a private tmpfs.
///
/// Idempotent: if the path is already a mount point — as it is when the kubelet
/// retries `NodePublishVolume` — nothing happens.
///
/// `policy_gid` makes the mount group-writable by that group, so the policy
/// daemon can write its own chain into a volume it did not create without
/// running as root. `None` keeps the mount root-only.
pub fn ensure_tmpfs(target: &Path, size: &str, policy_gid: Option<u32>) -> io::Result<()> {
    fs::create_dir_all(target)?;
    if is_mount_point(target)? {
        return Ok(());
    }
    mount_tmpfs(target, size, policy_gid)
}

/// Publish the certificate chain. Atomic, and independent of the policy chain.
pub fn publish_identity(target: &Path, identity: &Identity, modes: Modes) -> io::Result<()> {
    let version = next_version(target, VERSION_PREFIX)?;
    let dir = target.join(format!("{VERSION_PREFIX}{version}"));
    fs::create_dir(&dir)?;
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o755))?;

    write_file(&dir.join(KEY_FILE), identity.key_pem.as_bytes(), modes.key)?;
    write_file(
        &dir.join(CERT_FILE),
        identity.cert_chain_pem.as_bytes(),
        modes.cert,
    )?;
    write_file(&dir.join(CA_FILE), identity.ca_pem.as_bytes(), modes.cert)?;
    fsync_dir(&dir)?;

    // Visible symlinks first, then the swap. They dangle for an instant on the
    // very first publish, which reads as ENOENT — exactly what a reader saw a
    // moment earlier. Doing it the other way round would briefly expose some
    // files and not others, which is the one thing this layout exists to avoid.
    for name in [KEY_FILE, CERT_FILE, CA_FILE] {
        link(target, name, &format!("{DATA_LINK}/{name}"))?;
    }
    swap(target, DATA_LINK, VERSION_PREFIX, version)?;
    fsync_dir(target)?;
    remove_stale_versions(target, VERSION_PREFIX, version)
}

/// Publish a policy bundle. Atomic, and independent of the identity chain.
///
/// Writes the whole directory afresh each time, so a document removed upstream
/// really disappears rather than lingering from the previous revision.
pub fn publish_policy(target: &Path, bundle: &PolicyBundle, mode: u32) -> io::Result<()> {
    let version = next_version(target, POLICY_VERSION_PREFIX)?;
    let dir = target.join(format!("{POLICY_VERSION_PREFIX}{version}"));
    fs::create_dir(&dir)?;
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o755))?;

    let documents = dir.join(POLICY_DIR);
    fs::create_dir(&documents)?;
    fs::set_permissions(&documents, fs::Permissions::from_mode(0o755))?;
    for document in &bundle.documents {
        let path = documents.join(&document.name);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        write_file(&path, &document.content, mode)?;
    }
    // One file to stat, so an application can notice a change without walking
    // the directory.
    write_file(
        &dir.join(REVISION_FILE),
        format!("{}\n", bundle.revision).as_bytes(),
        mode,
    )?;
    fsync_dir(&dir)?;

    // As above: link before swapping, so `policy/` and `policy.revision` become
    // visible in the same instant rather than one before the other.
    for name in [POLICY_DIR, REVISION_FILE] {
        link(target, name, &format!("{POLICY_LINK}/{name}"))?;
    }
    swap(target, POLICY_LINK, POLICY_VERSION_PREFIX, version)?;
    fsync_dir(target)?;
    remove_stale_versions(target, POLICY_VERSION_PREFIX, version)
}

/// The revision currently published, if any. Lets the policy daemon skip a
/// volume that is already up to date without rewriting it.
pub fn published_revision(target: &Path) -> Option<String> {
    fs::read_to_string(target.join(POLICY_LINK).join(REVISION_FILE))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Read back the published certificate chain.
///
/// Used by the trust-bundle refresh, which rewrites `ca.crt` without minting a
/// new key.
pub fn read_identity(target: &Path) -> io::Result<Identity> {
    let base = target.join(DATA_LINK);
    Ok(Identity {
        key_pem: fs::read_to_string(base.join(KEY_FILE))?,
        cert_chain_pem: fs::read_to_string(base.join(CERT_FILE))?,
        ca_pem: fs::read_to_string(base.join(CA_FILE))?,
    })
}

/// Read only the certificate chain.
///
/// Restart recovery needs nothing else, and deliberately does not touch the
/// private key. The policy daemon uses it too: the certificate svidlet
/// published is how it learns a volume's identity, with no IPC between the two
/// processes and no credential shared between them.
pub fn read_cert_chain(target: &Path) -> io::Result<String> {
    fs::read_to_string(target.join(DATA_LINK).join(CERT_FILE))
        // Tolerate a volume published by an older layout, or a partially
        // written one, by falling back to the plain path.
        .or_else(|_| fs::read_to_string(target.join(CERT_FILE)))
}

/// Unmount the tmpfs and remove the target directory.
///
/// Both steps tolerate "already gone": the kubelet retries
/// `NodeUnpublishVolume` until it succeeds, and the call must be idempotent.
pub fn unpublish(target: &Path) -> io::Result<()> {
    if !target.exists() {
        return Ok(());
    }
    if is_mount_point(target).unwrap_or(false) {
        unmount(target)?;
    }
    match fs::remove_dir_all(target) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Swap a chain's data link to a new version. `rename(2)` over an existing
/// symlink is atomic, so a reader sees either the whole old version or the
/// whole new one.
fn swap(target: &Path, link_name: &str, prefix: &str, version: u64) -> io::Result<()> {
    let tmp = target.join(format!("{link_name}_tmp"));
    let _ = fs::remove_file(&tmp);
    std::os::unix::fs::symlink(format!("{prefix}{version}"), &tmp)?;
    fs::rename(&tmp, target.join(link_name))
}

fn link(target: &Path, name: &str, points_to: &str) -> io::Result<()> {
    let path = target.join(name);
    if fs::symlink_metadata(&path).is_err() {
        std::os::unix::fs::symlink(points_to, &path)?;
    }
    Ok(())
}

fn write_file(path: &Path, contents: &[u8], mode: u32) -> io::Result<()> {
    use std::io::Write as _;
    let mut f = fs::File::create(path)?;
    f.write_all(contents)?;
    f.sync_all()?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
}

fn fsync_dir(path: &Path) -> io::Result<()> {
    fs::File::open(path)?.sync_all()
}

/// Version numbers only ever increase, so a reader that already opened the old
/// directory keeps reading a consistent set until it reopens.
fn next_version(target: &Path, prefix: &str) -> io::Result<u64> {
    let mut highest = 0;
    if let Ok(entries) = fs::read_dir(target) {
        for entry in entries.flatten() {
            if let Some(n) = version_of(&entry.file_name().to_string_lossy(), prefix) {
                highest = highest.max(n);
            }
        }
    }
    Ok(highest + 1)
}

fn version_of(name: &str, prefix: &str) -> Option<u64> {
    // "..policy." and "..svidlet." do not prefix each other, so a chain never
    // collects the other chain's directories.
    name.strip_prefix(prefix)?.parse().ok()
}

fn remove_stale_versions(target: &Path, prefix: &str, keep: u64) -> io::Result<()> {
    for entry in fs::read_dir(target)?.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if let Some(n) = version_of(&name, prefix) {
            if n != keep {
                let _ = fs::remove_dir_all(entry.path());
            }
        }
    }
    Ok(())
}

/// True when `path` sits on a different filesystem from its parent.
fn is_mount_point(path: &Path) -> io::Result<bool> {
    use std::os::unix::fs::MetadataExt;
    let here = fs::metadata(path)?;
    let parent = match path.parent() {
        Some(p) => fs::metadata(p)?,
        None => return Ok(true),
    };
    Ok(here.dev() != parent.dev())
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn mount_tmpfs(target: &Path, size: &str, policy_gid: Option<u32>) -> io::Result<()> {
    use std::ffi::CString;

    let target_c = cstring(target.as_os_str().as_encoded_bytes())?;
    let fstype = CString::new("tmpfs").unwrap();
    let source = CString::new("svidlet").unwrap();
    // Group-writable only when a policy group is configured, so the default
    // stays root-only and the second writer is an explicit opt-in.
    let options = match policy_gid {
        Some(gid) => CString::new(format!("size={size},mode=0775,gid={gid}"))?,
        None => CString::new(format!("size={size},mode=0755"))?,
    };
    let flags = libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC;

    // SAFETY: all four pointers are NUL-terminated strings that outlive the call.
    let rc = unsafe {
        libc::mount(
            source.as_ptr(),
            target_c.as_ptr(),
            fstype.as_ptr(),
            flags,
            options.as_ptr() as *const libc::c_void,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn unmount(target: &Path) -> io::Result<()> {
    let target_c = cstring(target.as_os_str().as_encoded_bytes())?;
    // MNT_DETACH so a workload still holding the mount does not block cleanup.
    // SAFETY: target_c is a NUL-terminated string that outlives the call.
    let rc = unsafe { libc::umount2(target_c.as_ptr(), libc::MNT_DETACH) };
    if rc != 0 {
        let err = io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EINVAL) {
            return Err(err);
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn cstring(bytes: &[u8]) -> io::Result<std::ffi::CString> {
    std::ffi::CString::new(bytes).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))
}

/// Non-Linux builds exist so the plugin can be developed and unit-tested on a
/// workstation. There is no tmpfs to mount; the directory is used directly and
/// the caller is expected to warn.
#[cfg(not(target_os = "linux"))]
fn mount_tmpfs(_target: &Path, _size: &str, _policy_gid: Option<u32>) -> io::Result<()> {
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn unmount(_target: &Path) -> io::Result<()> {
    Ok(())
}

pub const TMPFS_SUPPORTED: bool = cfg!(target_os = "linux");

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::PolicyDocument;
    use std::path::PathBuf;

    const MODES: Modes = Modes {
        key: 0o640,
        cert: 0o644,
    };

    fn identity(tag: &str) -> Identity {
        Identity {
            key_pem: format!("KEY-{tag}\n"),
            cert_chain_pem: format!("CERT-{tag}\n"),
            ca_pem: format!("CA-{tag}\n"),
        }
    }

    fn bundle(revision: &str, docs: &[(&str, &str)]) -> PolicyBundle {
        PolicyBundle::build(
            revision.into(),
            docs.iter()
                .map(|(n, c)| PolicyDocument {
                    name: (*n).into(),
                    content: c.as_bytes().to_vec(),
                })
                .collect(),
        )
        .unwrap()
    }

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "svidlet-test-{name}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn publishing_then_renewing_swaps_all_three_files_together() {
        let dir = scratch("publish");
        publish_identity(&dir, &identity("1"), MODES).unwrap();

        assert_eq!(fs::read_to_string(dir.join(CERT_FILE)).unwrap(), "CERT-1\n");
        assert_eq!(fs::read_to_string(dir.join(KEY_FILE)).unwrap(), "KEY-1\n");
        assert_eq!(fs::read_to_string(dir.join(CA_FILE)).unwrap(), "CA-1\n");

        publish_identity(&dir, &identity("2"), MODES).unwrap();
        assert_eq!(fs::read_to_string(dir.join(CERT_FILE)).unwrap(), "CERT-2\n");
        assert_eq!(fs::read_to_string(dir.join(KEY_FILE)).unwrap(), "KEY-2\n");

        // The superseded version is collected, so a long-lived volume does not
        // accumulate one directory per renewal.
        let versions = fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with(VERSION_PREFIX))
            .count();
        assert_eq!(versions, 1);

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_key_is_not_world_readable() {
        let dir = scratch("modes");
        publish_identity(&dir, &identity("1"), MODES).unwrap();

        let mode = |name: &str| {
            fs::metadata(dir.join(DATA_LINK).join(name))
                .unwrap()
                .permissions()
                .mode()
                & 0o777
        };
        assert_eq!(mode(KEY_FILE), 0o640);
        assert_eq!(mode(CERT_FILE), 0o644);

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_identity_reads_back_from_the_current_version() {
        let dir = scratch("readback");
        publish_identity(&dir, &identity("1"), MODES).unwrap();
        publish_identity(&dir, &identity("2"), MODES).unwrap();

        let back = read_identity(&dir).unwrap();
        assert_eq!(back.cert_chain_pem, "CERT-2\n");
        assert_eq!(back.key_pem, "KEY-2\n");
        assert_eq!(read_cert_chain(&dir).unwrap(), "CERT-2\n");

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_policy_bundle_publishes_and_reports_its_revision() {
        let dir = scratch("policy");
        publish_policy(
            &dir,
            &bundle("git-r1", &[("authz.rego", "allow"), ("peers.json", "[]")]),
            0o644,
        )
        .unwrap();

        assert_eq!(
            fs::read_to_string(dir.join("policy/authz.rego")).unwrap(),
            "allow"
        );
        assert_eq!(
            fs::read_to_string(dir.join(REVISION_FILE)).unwrap(),
            "git-r1\n"
        );
        assert_eq!(published_revision(&dir).as_deref(), Some("git-r1"));

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_shrinking_bundle_leaves_no_stale_documents() {
        let dir = scratch("policy-shrink");
        publish_policy(&dir, &bundle("r1", &[("a", "1"), ("b", "2")]), 0o644).unwrap();
        assert!(dir.join("policy/b").exists());

        publish_policy(&dir, &bundle("r2", &[("a", "1")]), 0o644).unwrap();
        assert!(dir.join("policy/a").exists());
        assert!(!dir.join("policy/b").exists());
        assert_eq!(published_revision(&dir).as_deref(), Some("r2"));

        fs::remove_dir_all(&dir).unwrap();
    }

    /// The property the two-process split rests on: each writer owns its own
    /// chain, so neither can disturb the other even by accident.
    #[test]
    fn the_two_chains_are_independent() {
        let dir = scratch("independent");

        publish_identity(&dir, &identity("1"), MODES).unwrap();
        publish_policy(&dir, &bundle("r1", &[("authz.rego", "v1")]), 0o644).unwrap();

        // Renewing the certificate leaves the policy exactly where it was --
        // structurally, not because the renewal remembered to preserve it.
        for tag in ["2", "3", "4"] {
            publish_identity(&dir, &identity(tag), MODES).unwrap();
        }
        assert_eq!(
            fs::read_to_string(dir.join("policy/authz.rego")).unwrap(),
            "v1"
        );
        assert_eq!(published_revision(&dir).as_deref(), Some("r1"));

        // And a policy update leaves the certificate alone.
        for revision in ["r2", "r3"] {
            publish_policy(&dir, &bundle(revision, &[("authz.rego", revision)]), 0o644).unwrap();
        }
        assert_eq!(fs::read_to_string(dir.join(CERT_FILE)).unwrap(), "CERT-4\n");
        assert_eq!(fs::read_to_string(dir.join(KEY_FILE)).unwrap(), "KEY-4\n");
        assert_eq!(read_identity(&dir).unwrap().ca_pem, "CA-4\n");

        // Each chain collected only its own superseded versions.
        let count = |prefix: &str| {
            fs::read_dir(&dir)
                .unwrap()
                .flatten()
                .filter(|e| e.file_name().to_string_lossy().starts_with(prefix))
                .count()
        };
        assert_eq!(count(VERSION_PREFIX), 1);
        assert_eq!(count(POLICY_VERSION_PREFIX), 1);

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn policy_can_be_published_before_or_after_the_certificate() {
        // The policy daemon and svidlet start independently, so neither order
        // can be assumed.
        let dir = scratch("either-order");
        publish_policy(&dir, &bundle("r1", &[("a", "1")]), 0o644).unwrap();
        assert!(read_identity(&dir).is_err());
        assert_eq!(published_revision(&dir).as_deref(), Some("r1"));

        publish_identity(&dir, &identity("1"), MODES).unwrap();
        assert_eq!(fs::read_to_string(dir.join(CERT_FILE)).unwrap(), "CERT-1\n");
        assert_eq!(fs::read_to_string(dir.join("policy/a")).unwrap(), "1");

        fs::remove_dir_all(&dir).unwrap();
    }

    /// The first publish must expose every file at once, not one before the
    /// other. Regression: the visible symlinks used to be created after the
    /// swap, so a reader could see the revision file before the policy
    /// directory it describes.
    #[test]
    fn the_first_publish_exposes_every_file_at_the_same_instant() {
        let dir = scratch("first-publish");
        publish_policy(&dir, &bundle("r1", &[("authz.rego", "allow")]), 0o644).unwrap();
        // Both visible names resolve, or neither would have.
        assert!(dir.join(REVISION_FILE).exists());
        assert!(dir.join("policy/authz.rego").exists());

        publish_identity(&dir, &identity("1"), MODES).unwrap();
        for name in [KEY_FILE, CERT_FILE, CA_FILE] {
            assert!(dir.join(name).exists(), "{name} is not visible");
        }

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_volume_with_no_policy_reports_no_revision() {
        let dir = scratch("no-policy");
        publish_identity(&dir, &identity("1"), MODES).unwrap();
        assert_eq!(published_revision(&dir), None);
        assert!(!dir.join("policy").exists());
        assert!(!dir.join(REVISION_FILE).exists());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn unpublishing_is_idempotent() {
        let dir = scratch("unpublish");
        publish_identity(&dir, &identity("1"), MODES).unwrap();
        publish_policy(&dir, &bundle("r1", &[("a", "1")]), 0o644).unwrap();
        unpublish(&dir).unwrap();
        assert!(!dir.exists());
        unpublish(&dir).unwrap();
    }
}
