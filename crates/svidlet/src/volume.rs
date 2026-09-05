//! Publishing certificate material into a pod's volume.
//!
//! Each target path is a private tmpfs, so the private key never touches the
//! node's disk. Inside it, files are published the way the kubelet publishes
//! Secret volumes: a versioned directory plus a `..data` symlink that is
//! swapped with `rename(2)`. A renewal therefore replaces `tls.crt`, `tls.key`
//! and `ca.crt` as one atomic step — a reloading application can never observe
//! a certificate that does not match its key.

use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use crate::config::{CA_FILE, CERT_FILE, KEY_FILE, REVISION_FILE};
use crate::policy::{PolicyBundle, PolicyDocument};

const DATA_LINK: &str = "..data";
const DATA_LINK_TMP: &str = "..data_tmp";
const VERSION_PREFIX: &str = "..svidlet.";

/// Everything published into one pod's volume.
///
/// The certificate and the policy bundle are written together through a single
/// atomic swap, so a workload watching the directory never sees a policy set
/// that does not go with the certificate beside it.
pub struct Material {
    pub key_pem: String,
    pub cert_chain_pem: String,
    pub ca_pem: String,
    /// Authorization policy, when a policy backend is configured. `None` leaves
    /// whatever is already published untouched — a certificate renewal during a
    /// policy-backend outage must not wipe the policy directory.
    pub policy: Option<PolicyBundle>,
}

#[derive(Debug, Clone)]
pub struct Modes {
    pub key: u32,
    pub cert: u32,
    /// Directory name for policy documents, relative to the volume root.
    pub policy_dir: String,
}

/// Create the target directory and back it with a private tmpfs.
///
/// Idempotent: if the path is already a mount point — as it is when the kubelet
/// retries `NodePublishVolume` — nothing happens.
pub fn ensure_tmpfs(target: &Path, size: &str) -> io::Result<()> {
    fs::create_dir_all(target)?;
    if is_mount_point(target)? {
        return Ok(());
    }
    mount_tmpfs(target, size)
}

/// Write a full set of material into `target` and make it visible atomically.
pub fn publish(target: &Path, material: &Material, modes: Modes) -> io::Result<()> {
    let version = next_version(target)?;
    let dir = target.join(format!("{VERSION_PREFIX}{version}"));
    fs::create_dir(&dir)?;
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o755))?;

    write_file(&dir.join(KEY_FILE), material.key_pem.as_bytes(), modes.key)?;
    write_file(
        &dir.join(CERT_FILE),
        material.cert_chain_pem.as_bytes(),
        modes.cert,
    )?;
    write_file(&dir.join(CA_FILE), material.ca_pem.as_bytes(), modes.cert)?;

    let mut visible: Vec<String> = vec![KEY_FILE.into(), CERT_FILE.into(), CA_FILE.into()];
    if let Some(policy) = &material.policy {
        let policy_dir = dir.join(&modes.policy_dir);
        fs::create_dir(&policy_dir)?;
        fs::set_permissions(&policy_dir, fs::Permissions::from_mode(0o755))?;
        for document in &policy.documents {
            write_file(
                &policy_dir.join(&document.name),
                &document.content,
                modes.cert,
            )?;
        }
        fsync_dir(&policy_dir)?;
        // A single file an application can stat to see whether policy moved,
        // without walking the directory.
        write_file(
            &dir.join(REVISION_FILE),
            format!("{}\n", policy.revision).as_bytes(),
            modes.cert,
        )?;
        visible.push(modes.policy_dir.clone());
        visible.push(REVISION_FILE.into());
    }
    fsync_dir(&dir)?;

    // Swap the data link. rename(2) over an existing symlink is atomic, so a
    // reader either sees the whole old version or the whole new one.
    let link_tmp = target.join(DATA_LINK_TMP);
    let _ = fs::remove_file(&link_tmp);
    std::os::unix::fs::symlink(format!("{VERSION_PREFIX}{version}"), &link_tmp)?;
    fs::rename(&link_tmp, target.join(DATA_LINK))?;

    for name in &visible {
        let link = target.join(name);
        if fs::symlink_metadata(&link).is_err() {
            std::os::unix::fs::symlink(format!("{DATA_LINK}/{name}"), &link)?;
        }
    }
    fsync_dir(target)?;

    remove_stale_versions(target, version)
}

/// Read back what is currently published, if anything.
///
/// Used by every rewrite that changes only part of the volume — a trust-bundle
/// refresh, or a policy update that must not disturb the certificate.
pub fn read_published(target: &Path, policy_dir: &str) -> io::Result<Material> {
    let base = target.join(DATA_LINK);
    Ok(Material {
        key_pem: fs::read_to_string(base.join(KEY_FILE))?,
        cert_chain_pem: fs::read_to_string(base.join(CERT_FILE))?,
        ca_pem: fs::read_to_string(base.join(CA_FILE))?,
        policy: read_policy(&base, policy_dir),
    })
}

/// Read the published policy bundle, if there is one.
///
/// Returns `None` when no policy has been published, which is what keeps a
/// certificate renewal from creating an empty policy directory.
fn read_policy(base: &Path, policy_dir: &str) -> Option<PolicyBundle> {
    let dir = base.join(policy_dir);
    if !dir.is_dir() {
        return None;
    }
    let revision = fs::read_to_string(base.join(REVISION_FILE))
        .unwrap_or_default()
        .trim()
        .to_string();

    let mut documents: Vec<PolicyDocument> = fs::read_dir(&dir)
        .ok()?
        .flatten()
        .filter_map(|entry| {
            let content = fs::read(entry.path()).ok()?;
            Some(PolicyDocument {
                name: entry.file_name().to_string_lossy().into_owned(),
                content,
            })
        })
        .collect();
    documents.sort_by(|a, b| a.name.cmp(&b.name));
    Some(PolicyBundle {
        revision,
        documents,
    })
}

/// Read only the certificate chain. Restart recovery needs nothing else, and
/// deliberately does not touch the private key.
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
fn next_version(target: &Path) -> io::Result<u64> {
    let mut highest = 0;
    if let Ok(entries) = fs::read_dir(target) {
        for entry in entries.flatten() {
            if let Some(n) = version_of(&entry.file_name().to_string_lossy()) {
                highest = highest.max(n);
            }
        }
    }
    Ok(highest + 1)
}

fn version_of(name: &str) -> Option<u64> {
    name.strip_prefix(VERSION_PREFIX)?.parse().ok()
}

fn remove_stale_versions(target: &Path, keep: u64) -> io::Result<()> {
    for entry in fs::read_dir(target)?.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if let Some(n) = version_of(&name) {
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
fn mount_tmpfs(target: &Path, size: &str) -> io::Result<()> {
    use std::ffi::CString;

    let target_c = cstring(target.as_os_str().as_encoded_bytes())?;
    let fstype = CString::new("tmpfs").unwrap();
    let source = CString::new("svidlet").unwrap();
    let options = CString::new(format!("size={size},mode=0755"))?;
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
fn mount_tmpfs(_target: &Path, _size: &str) -> io::Result<()> {
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
    use std::path::PathBuf;

    fn material(tag: &str) -> Material {
        Material {
            key_pem: format!("KEY-{tag}\n"),
            cert_chain_pem: format!("CERT-{tag}\n"),
            ca_pem: format!("CA-{tag}\n"),
            policy: None,
        }
    }

    fn with_policy(tag: &str, revision: &str, docs: &[(&str, &str)]) -> Material {
        Material {
            policy: Some(
                PolicyBundle::build(
                    revision.into(),
                    docs.iter()
                        .map(|(n, c)| PolicyDocument {
                            name: (*n).into(),
                            content: c.as_bytes().to_vec(),
                        })
                        .collect(),
                )
                .unwrap(),
            ),
            ..material(tag)
        }
    }

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("svidlet-test-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn modes() -> Modes {
        Modes {
            key: 0o640,
            cert: 0o644,
            policy_dir: "policy".into(),
        }
    }

    #[test]
    fn publish_then_renew_swaps_all_three_files_together() {
        let dir = scratch("publish");
        publish(&dir, &material("1"), modes()).unwrap();

        assert_eq!(fs::read_to_string(dir.join(CERT_FILE)).unwrap(), "CERT-1\n");
        assert_eq!(fs::read_to_string(dir.join(KEY_FILE)).unwrap(), "KEY-1\n");
        assert_eq!(fs::read_to_string(dir.join(CA_FILE)).unwrap(), "CA-1\n");

        publish(&dir, &material("2"), modes()).unwrap();
        assert_eq!(fs::read_to_string(dir.join(CERT_FILE)).unwrap(), "CERT-2\n");
        assert_eq!(fs::read_to_string(dir.join(KEY_FILE)).unwrap(), "KEY-2\n");

        // The superseded version directory is collected, so a long-lived
        // volume does not accumulate one directory per renewal.
        let versions: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with(VERSION_PREFIX))
            .collect();
        assert_eq!(versions.len(), 1);

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn key_is_not_world_readable() {
        let dir = scratch("modes");
        publish(&dir, &material("1"), modes()).unwrap();

        let key = fs::metadata(dir.join(DATA_LINK).join(KEY_FILE)).unwrap();
        assert_eq!(key.permissions().mode() & 0o777, 0o640);
        let cert = fs::metadata(dir.join(DATA_LINK).join(CERT_FILE)).unwrap();
        assert_eq!(cert.permissions().mode() & 0o777, 0o644);

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn read_published_returns_the_current_version() {
        let dir = scratch("readback");
        publish(&dir, &material("1"), modes()).unwrap();
        publish(&dir, &material("2"), modes()).unwrap();

        let back = read_published(&dir, "policy").unwrap();
        assert_eq!(back.cert_chain_pem, "CERT-2\n");
        assert_eq!(read_cert_chain(&dir).unwrap(), "CERT-2\n");

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_policy_bundle_is_published_and_read_back() {
        let dir = scratch("policy");
        publish(
            &dir,
            &with_policy(
                "1",
                "git-r1",
                &[("authz.rego", "allow"), ("peers.json", "[]")],
            ),
            modes(),
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

        let back = read_published(&dir, "policy").unwrap();
        let policy = back.policy.expect("the bundle reads back");
        assert_eq!(policy.revision, "git-r1");
        assert_eq!(policy.documents.len(), 2);
        assert_eq!(policy.documents[0].name, "authz.rego");

        // Publishing without policy leaves the previous bundle unreferenced,
        // so a certificate renewal that carries no policy does not create an
        // empty directory.
        publish(&dir, &material("2"), modes()).unwrap();
        assert!(!dir.join("policy").exists());
        assert!(read_published(&dir, "policy").unwrap().policy.is_none());

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_shrinking_bundle_does_not_leave_stale_documents() {
        let dir = scratch("policy-shrink");
        publish(
            &dir,
            &with_policy("1", "r1", &[("a", "1"), ("b", "2")]),
            modes(),
        )
        .unwrap();
        assert!(dir.join("policy/b").exists());

        publish(&dir, &with_policy("1", "r2", &[("a", "1")]), modes()).unwrap();
        assert!(dir.join("policy/a").exists());
        assert!(!dir.join("policy/b").exists());

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn unpublish_is_idempotent() {
        let dir = scratch("unpublish");
        publish(&dir, &material("1"), modes()).unwrap();
        unpublish(&dir).unwrap();
        assert!(!dir.exists());
        unpublish(&dir).unwrap();
    }
}
