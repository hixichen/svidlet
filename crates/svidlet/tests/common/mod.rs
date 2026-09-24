//! Helpers shared by the integration tests that publish real volumes.

#![allow(dead_code)]

use std::path::{Path, PathBuf};

/// Remove a test directory, unmounting anything svidlet mounted under it first.
///
/// Running as root on Linux, publishing mounts a real tmpfs at the target and
/// exposing binds it into the policy farm; `remove_dir_all` on a live mount
/// point fails with `EBUSY`. Deepest mounts go first, so a farm bind mount of a
/// tmpfs is released before the tmpfs itself. Elsewhere nothing is mounted and
/// this is plain `remove_dir_all`.
pub fn remove_tree(dir: &Path) {
    #[cfg(target_os = "linux")]
    if let (Ok(table), Ok(root)) = (
        std::fs::read_to_string("/proc/self/mountinfo"),
        std::fs::canonicalize(dir),
    ) {
        let mut points: Vec<PathBuf> = table
            .lines()
            .filter_map(|line| line.split(' ').nth(4))
            .map(PathBuf::from)
            .filter(|p| p.starts_with(&root))
            .collect();
        points.sort_by_key(|p| std::cmp::Reverse(p.components().count()));
        for point in points {
            let _ = std::process::Command::new("umount")
                .arg("-l")
                .arg(&point)
                .status();
        }
    }
    std::fs::remove_dir_all(dir).unwrap();
}

/// Device and inode of a path, following symlinks.
///
/// A farm entry is a bind mount on Linux and a symlink elsewhere; in both
/// cases it is the same directory as the volume, which is what this compares.
/// Canonicalising paths would only work for the symlink.
pub fn file_id(path: &Path) -> (u64, u64) {
    use std::os::unix::fs::MetadataExt;
    let m = std::fs::metadata(path).unwrap();
    (m.dev(), m.ino())
}
