//! Helpers shared by the integration tests.

use std::path::Path;

/// Remove a fixture's directory, unmounting anything under it first.
///
/// Run as root, publishing mounts a real tmpfs (and the farm a bind mount)
/// under the fixture, and `remove_dir_all` then fails with EBUSY.
pub fn remove_tree(root: &Path) {
    let root = std::fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
    let table = std::fs::read_to_string("/proc/self/mountinfo").unwrap_or_default();
    let mut points: Vec<String> = table
        .lines()
        .filter_map(|line| line.split(' ').nth(4))
        .filter(|p| Path::new(p).starts_with(&root))
        .map(str::to_string)
        .collect();
    // Deepest first, so a bind mount inside a tmpfs goes before the tmpfs.
    points.sort_by_key(|p| std::cmp::Reverse(p.len()));
    for point in points {
        let c = std::ffi::CString::new(point).unwrap();
        // SAFETY: a NUL-terminated path that outlives the call.
        unsafe { libc::umount2(c.as_ptr(), libc::MNT_DETACH) };
    }
    std::fs::remove_dir_all(&root).unwrap();
}

/// Whether two paths name the same file. A farm entry is a bind mount on
/// Linux run as root and a symlink elsewhere; both resolve to the same inode,
/// but only the symlink also canonicalises to the same path.
#[allow(dead_code)]
pub fn same_file(a: &Path, b: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    match (std::fs::metadata(a), std::fs::metadata(b)) {
        (Ok(a), Ok(b)) => (a.dev(), a.ino()) == (b.dev(), b.ino()),
        _ => false,
    }
}
