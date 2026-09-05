//! The node-local bundle cache.
//!
//! ```text
//! /var/lib/svidlet/policy/
//!   versions/sha256-…a1/   unpacked bundle
//!   versions/sha256-…9f/   previous
//!   current -> versions/sha256-…a1
//!   rollout.toml           last verified manifest
//!   state.json             ring, digest, last success, last error
//! ```
//!
//! Keeping the previous versions is what makes a rollback cost one polling
//! interval and no network: the digest the manifest reverts to is already
//! unpacked on disk.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::Error;
use crate::policy::{PolicyBundle, PolicyDocument};

const VERSIONS: &str = "versions";
const CURRENT: &str = "current";
const CURRENT_TMP: &str = "current.tmp";
const STATE: &str = "state.json";
const MANIFEST: &str = "rollout.toml";

/// What this node last did, persisted so a restart can report it before the
/// first poll completes.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct State {
    #[serde(default)]
    pub ring: String,
    #[serde(default)]
    pub digest: String,
    /// Unix seconds of the last successful apply.
    #[serde(default)]
    pub applied_at: i64,
    /// Unix seconds of the last successful poll, whether or not it changed
    /// anything. This is what `bundle_age` is measured from.
    #[serde(default)]
    pub last_success: i64,
    #[serde(default)]
    pub last_error: String,
    #[serde(default)]
    pub manifest_etag: String,
}

pub struct Store {
    root: PathBuf,
    keep: usize,
}

impl Store {
    /// `keep` is how many superseded versions stay on disk for rollback.
    pub fn new(root: PathBuf, keep: usize) -> Store {
        Store {
            root,
            keep: keep.max(1),
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn versions_dir(&self) -> PathBuf {
        self.root.join(VERSIONS)
    }

    /// `sha256:abc…` is not a legal directory name everywhere; `sha256-abc…` is.
    fn version_dir(&self, digest: &str) -> PathBuf {
        self.versions_dir().join(digest.replace(':', "-"))
    }

    pub fn prepare(&self) -> Result<(), Error> {
        fs::create_dir_all(self.versions_dir()).map_err(|e| {
            Error::Io(format!(
                "cannot create {}: {e}",
                self.versions_dir().display()
            ))
        })
    }

    pub fn has(&self, digest: &str) -> bool {
        self.version_dir(digest).is_dir()
    }

    /// Unpack a bundle into its version directory.
    ///
    /// Written to a temporary directory and renamed, so a version directory is
    /// never half-populated — a crash mid-write leaves nothing that `has()`
    /// would later claim is usable.
    pub fn write_version(
        &self,
        digest: &str,
        entries: &[super::tarball::Entry],
    ) -> Result<(), Error> {
        let final_dir = self.version_dir(digest);
        if final_dir.exists() {
            return Ok(());
        }
        let staging = self
            .versions_dir()
            .join(format!(".staging-{}", digest.replace(':', "-")));
        let _ = fs::remove_dir_all(&staging);
        fs::create_dir_all(&staging)
            .map_err(|e| Error::Io(format!("cannot create {}: {e}", staging.display())))?;

        for entry in entries {
            let path = staging.join(&entry.path);
            // The tar reader has already refused anything that could escape;
            // this is the belt to that pair of braces.
            if !path.starts_with(&staging) {
                let _ = fs::remove_dir_all(&staging);
                return Err(Error::Rejected(format!(
                    "bundle entry {:?} resolves outside its version directory",
                    entry.path
                )));
            }
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)
                    .map_err(|e| Error::Io(format!("cannot create {}: {e}", parent.display())))?;
            }
            fs::write(&path, &entry.content)
                .map_err(|e| Error::Io(format!("cannot write {}: {e}", path.display())))?;
        }

        fs::rename(&staging, &final_dir).map_err(|e| {
            let _ = fs::remove_dir_all(&staging);
            Error::Io(format!("cannot move {} into place: {e}", staging.display()))
        })
    }

    /// Point `current` at a version. Atomic: a symlink rename either happens or
    /// does not, so no reader ever sees a partial swap.
    pub fn set_current(&self, digest: &str) -> Result<(), Error> {
        if !self.has(digest) {
            return Err(Error::Io(format!("{digest} is not unpacked on this node")));
        }
        let link = self.root.join(CURRENT);
        let tmp = self.root.join(CURRENT_TMP);
        let _ = fs::remove_file(&tmp);
        std::os::unix::fs::symlink(format!("{VERSIONS}/{}", digest.replace(':', "-")), &tmp)
            .map_err(|e| Error::Io(format!("cannot create {}: {e}", tmp.display())))?;
        fs::rename(&tmp, &link)
            .map_err(|e| Error::Io(format!("cannot move {} into place: {e}", link.display())))
    }

    /// Read a version back as a policy bundle, ready to publish into pods.
    pub fn read(&self, digest: &str) -> Result<PolicyBundle, Error> {
        let dir = self.version_dir(digest);
        let mut documents = Vec::new();
        collect(&dir, &dir, &mut documents)?;
        documents.sort_by(|a: &PolicyDocument, b: &PolicyDocument| a.name.cmp(&b.name));
        if documents.is_empty() {
            return Err(Error::Rejected(format!("{digest} unpacked to no files")));
        }
        Ok(PolicyBundle {
            revision: digest.to_string(),
            documents,
        })
    }

    /// Delete superseded versions, keeping `current` and the most recent few.
    pub fn prune(&self, keep_digests: &[&str]) -> usize {
        let keep: Vec<String> = keep_digests
            .iter()
            .take(self.keep + 1)
            .map(|d| d.replace(':', "-"))
            .collect();

        let mut removed = 0;
        let Ok(entries) = fs::read_dir(self.versions_dir()) else {
            return 0;
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with(".staging-") {
                let _ = fs::remove_dir_all(entry.path());
                continue;
            }
            if !keep.contains(&name) && fs::remove_dir_all(entry.path()).is_ok() {
                removed += 1;
            }
        }
        removed
    }

    pub fn load_state(&self) -> State {
        fs::read_to_string(self.root.join(STATE))
            .ok()
            .and_then(|raw| serde_json::from_str(&raw).ok())
            .unwrap_or_default()
    }

    pub fn save_state(&self, state: &State) -> Result<(), Error> {
        let path = self.root.join(STATE);
        let tmp = path.with_extension("json.tmp");
        let body = serde_json::to_vec_pretty(state)
            .map_err(|e| Error::Io(format!("cannot serialise state: {e}")))?;
        fs::write(&tmp, body)
            .map_err(|e| Error::Io(format!("cannot write {}: {e}", tmp.display())))?;
        fs::rename(&tmp, &path)
            .map_err(|e| Error::Io(format!("cannot move {} into place: {e}", path.display())))
    }

    /// Keep the last verified manifest on disk, so an operator can see exactly
    /// what this node believes without reaching for the registry.
    pub fn save_manifest(&self, toml: &[u8]) -> Result<(), Error> {
        let path = self.root.join(MANIFEST);
        let tmp = path.with_extension("toml.tmp");
        fs::write(&tmp, toml)
            .map_err(|e| Error::Io(format!("cannot write {}: {e}", tmp.display())))?;
        fs::rename(&tmp, &path)
            .map_err(|e| Error::Io(format!("cannot move {} into place: {e}", path.display())))
    }
}

fn collect(root: &Path, dir: &Path, out: &mut Vec<PolicyDocument>) -> Result<(), Error> {
    let entries =
        fs::read_dir(dir).map_err(|e| Error::Io(format!("cannot read {}: {e}", dir.display())))?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect(root, &path, out)?;
            continue;
        }
        let name = path
            .strip_prefix(root)
            .map_err(|_| Error::Io("bundle file escaped its directory".into()))?
            .to_string_lossy()
            .replace(std::path::MAIN_SEPARATOR, "/");
        let content = fs::read(&path)
            .map_err(|e| Error::Io(format!("cannot read {}: {e}", path.display())))?;
        out.push(PolicyDocument { name, content });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::tarball::Entry;
    use super::*;

    const A: &str = "sha256:aaaa";
    const B: &str = "sha256:bbbb";
    const C: &str = "sha256:cccc";

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "svidlet-store-{name}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    fn entries(files: &[(&str, &str)]) -> Vec<Entry> {
        files
            .iter()
            .map(|(p, c)| Entry {
                path: (*p).into(),
                content: c.as_bytes().to_vec(),
            })
            .collect()
    }

    #[test]
    fn a_version_is_written_read_back_and_made_current() {
        let root = scratch("roundtrip");
        let store = Store::new(root.clone(), 2);
        store.prepare().unwrap();

        assert!(!store.has(A));
        store
            .write_version(
                A,
                &entries(&[("bundle.toml", "schema = 1"), ("rules/a.rego", "x")]),
            )
            .unwrap();
        assert!(store.has(A));

        let bundle = store.read(A).unwrap();
        assert_eq!(bundle.revision, A);
        let names: Vec<_> = bundle.documents.iter().map(|d| d.name.as_str()).collect();
        assert_eq!(names, ["bundle.toml", "rules/a.rego"]);

        store.set_current(A).unwrap();
        let target = fs::read_link(root.join(CURRENT)).unwrap();
        assert_eq!(target, PathBuf::from("versions/sha256-aaaa"));
        assert_eq!(
            fs::read_to_string(root.join(CURRENT).join("bundle.toml")).unwrap(),
            "schema = 1"
        );

        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn swapping_current_replaces_an_existing_link() {
        let root = scratch("swap");
        let store = Store::new(root.clone(), 2);
        store.prepare().unwrap();
        store.write_version(A, &entries(&[("f", "a")])).unwrap();
        store.write_version(B, &entries(&[("f", "b")])).unwrap();

        store.set_current(A).unwrap();
        assert_eq!(
            fs::read_to_string(root.join(CURRENT).join("f")).unwrap(),
            "a"
        );
        store.set_current(B).unwrap();
        assert_eq!(
            fs::read_to_string(root.join(CURRENT).join("f")).unwrap(),
            "b"
        );

        // Rolling back needs no network: the old version is still unpacked.
        store.set_current(A).unwrap();
        assert_eq!(
            fs::read_to_string(root.join(CURRENT).join("f")).unwrap(),
            "a"
        );

        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_version_that_was_never_unpacked_cannot_be_made_current() {
        let root = scratch("missing");
        let store = Store::new(root.clone(), 2);
        store.prepare().unwrap();
        assert!(matches!(store.set_current(A), Err(Error::Io(_))));
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn writing_a_version_twice_is_a_no_op() {
        let root = scratch("twice");
        let store = Store::new(root.clone(), 2);
        store.prepare().unwrap();
        store.write_version(A, &entries(&[("f", "first")])).unwrap();
        store
            .write_version(A, &entries(&[("f", "second")]))
            .unwrap();
        // Content addressed: the same digest is the same bytes, so the first
        // write stands and the second costs nothing.
        assert_eq!(store.read(A).unwrap().documents[0].content, b"first");
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn pruning_keeps_the_current_and_the_configured_history() {
        let root = scratch("prune");
        let store = Store::new(root.clone(), 1);
        store.prepare().unwrap();
        for digest in [A, B, C] {
            store
                .write_version(digest, &entries(&[("f", "x")]))
                .unwrap();
        }

        // Keep C (current) and B (one of history); A goes.
        assert_eq!(store.prune(&[C, B, A]), 1);
        assert!(store.has(C));
        assert!(store.has(B));
        assert!(!store.has(A));

        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn pruning_clears_abandoned_staging_directories() {
        let root = scratch("staging");
        let store = Store::new(root.clone(), 2);
        store.prepare().unwrap();
        // As a crash mid-unpack would leave behind.
        fs::create_dir_all(store.versions_dir().join(".staging-sha256-dddd")).unwrap();
        store.write_version(A, &entries(&[("f", "x")])).unwrap();

        store.prune(&[A]);
        assert!(!store.versions_dir().join(".staging-sha256-dddd").exists());
        assert!(store.has(A));

        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn state_survives_a_restart_and_a_missing_file_is_not_an_error() {
        let root = scratch("state");
        let store = Store::new(root.clone(), 2);
        store.prepare().unwrap();

        // Nothing written yet.
        assert_eq!(store.load_state(), State::default());

        let state = State {
            ring: "canary".into(),
            digest: A.into(),
            applied_at: 1000,
            last_success: 1200,
            last_error: String::new(),
            manifest_etag: "\"abc\"".into(),
        };
        store.save_state(&state).unwrap();
        assert_eq!(store.load_state(), state);

        // Corrupt state reads as default rather than stopping the node.
        fs::write(root.join(STATE), "{not json").unwrap();
        assert_eq!(store.load_state(), State::default());

        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn the_verified_manifest_is_kept_for_an_operator_to_read() {
        let root = scratch("manifest");
        let store = Store::new(root.clone(), 2);
        store.prepare().unwrap();
        store.save_manifest(b"schema = 1\n").unwrap();
        assert_eq!(
            fs::read_to_string(root.join(MANIFEST)).unwrap(),
            "schema = 1\n"
        );
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn an_empty_version_is_refused_when_read() {
        let root = scratch("empty");
        let store = Store::new(root.clone(), 2);
        store.prepare().unwrap();
        fs::create_dir_all(store.version_dir(A)).unwrap();
        assert!(matches!(store.read(A), Err(Error::Rejected(_))));
        fs::remove_dir_all(&root).unwrap();
    }
}
