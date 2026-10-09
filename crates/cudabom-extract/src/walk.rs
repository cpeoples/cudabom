//! Directory walking and top-level target dispatch.
//!
//! A directory target is walked recursively with symlinks never followed, and
//! with `node_modules`, `.git`, and other noise directories skipped by default
//! (spec Section 4). A file target is read (size-capped), hashed, and expanded
//! by content kind. Everything is threaded through the shared [`Budget`].

use std::path::Path;

use cudabom_core::{Budget, Error, Location, Result};
use sha2::{Digest, Sha256};
use walkdir::WalkDir;

use crate::{expand_bytes, ScannedFile};

/// Directory names skipped during a recursive walk. `node_modules` is excluded
/// by default per the spec; VCS/metadata dirs never contain scan targets.
const SKIP_DIRS: &[&str] = &["node_modules", ".git", ".hg", ".svn"];

/// Walk a top-level target (file or directory), invoking `visit` per leaf file.
pub(crate) fn walk_target<F>(target: &Path, budget: &mut Budget, visit: &mut F) -> Result<()>
where
    F: FnMut(ScannedFile) -> Result<()>,
{
    let meta = std::fs::symlink_metadata(target)
        .map_err(|e| Error::input(format!("cannot stat {}: {e}", target.display())))?;

    if meta.is_dir() {
        walk_directory(target, budget, visit)
    } else if meta.is_file() {
        // The top-level path becomes the logical root name (its file name).
        let name = target.file_name().map_or_else(
            || target.display().to_string(),
            |n| n.to_string_lossy().into_owned(),
        );
        read_and_expand_file(target, name, budget, visit, true)
    } else if meta.file_type().is_symlink() {
        // A symlink passed *directly* as the top-level target is a normal user
        // action, e.g. scanning `libcudart.so.12`, which NVIDIA ships as a
        // symlink chain to `libcudart.so.12.4.99`. Resolve it (following the
        // link) and, if it lands on a regular file, scan that file under the
        // symlink's own name. This does not weaken the no-follow guarantee for
        // symlinks encountered *inside* a walked directory tree: that path
        // still uses `follow_links(false)` so a link cannot redirect the walk
        // outside the tree.
        let resolved = std::fs::metadata(target).map_err(|e| {
            Error::input(format!("cannot resolve symlink {}: {e}", target.display()))
        })?;
        if resolved.is_file() {
            let name = target.file_name().map_or_else(
                || target.display().to_string(),
                |n| n.to_string_lossy().into_owned(),
            );
            read_and_expand_file(target, name, budget, visit, true)
        } else {
            // Symlink to a directory or special file: refuse, as before.
            Err(Error::input(format!(
                "unsupported target (symlink does not resolve to a regular file): {}",
                target.display()
            )))
        }
    } else {
        // A special file (socket, device, fifo) passed directly: refuse.
        Err(Error::input(format!(
            "unsupported target (not a regular file or directory): {}",
            target.display()
        )))
    }
}

fn walk_directory<F>(root: &Path, budget: &mut Budget, visit: &mut F) -> Result<()>
where
    F: FnMut(ScannedFile) -> Result<()>,
{
    // follow_links(false): symlinks are never traversed, so a symlink inside
    // the tree cannot redirect the walk outside it.
    let walker = WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| !is_skipped_dir(e));

    for entry in walker {
        let entry = entry.map_err(|e| Error::input(format!("directory walk error: {e}")))?;
        // Only regular files; skip directories and any symlink (not followed).
        if !entry.file_type().is_file() {
            continue;
        }
        let logical = entry
            .path()
            .strip_prefix(root)
            .unwrap_or_else(|_| entry.path())
            .to_string_lossy()
            .replace('\\', "/");
        read_and_expand_file(entry.path(), logical, budget, visit, false)?;
    }
    Ok(())
}

fn is_skipped_dir(entry: &walkdir::DirEntry) -> bool {
    entry.file_type().is_dir()
        && entry
            .file_name()
            .to_str()
            .is_some_and(|name| SKIP_DIRS.contains(&name))
}

/// Read a file from disk with the per-file size cap enforced up front (via its
/// metadata length), hash it, account the bytes, and expand by content kind.
///
/// `explicit` is true only for a target the user named directly (a file or
/// resolved symlink argument). A file discovered by walking a directory is not
/// explicit: a malformed archive among many files must not abort the whole
/// walk, whereas a directly-named malformed file is still reported loudly.
fn read_and_expand_file<F>(
    path: &Path,
    logical_path: String,
    budget: &mut Budget,
    visit: &mut F,
    explicit: bool,
) -> Result<()>
where
    F: FnMut(ScannedFile) -> Result<()>,
{
    let meta = std::fs::metadata(path)
        .map_err(|e| Error::input(format!("cannot stat {}: {e}", path.display())))?;
    let len = meta.len();

    // On-disk files are not compressed input, so only the per-file size cap
    // applies (ratio check uses compressed==0 to skip).
    budget.limits().check_member(len, 0)?;
    budget.consume(len)?;

    let bytes = std::fs::read(path)
        .map_err(|e| Error::input(format!("cannot read {}: {e}", path.display())))?;

    let location = Location {
        path: logical_path,
        sha256: Some(hex_sha256(&bytes)),
        layer_digest: None,
    };

    // Top-level file is depth 0; nested archive members increment from there.
    // A directory-walked file (`!explicit`) is treated as tolerant from the
    // root so a single malformed archive in the tree does not abort the scan.
    expand_bytes(bytes, location, 0, !explicit, budget, visit)
}

/// Lowercase hex sha256 of `bytes`.
pub(crate) fn hex_sha256(bytes: &[u8]) -> String {
    cudabom_core::hex_lower(&Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_of_empty_is_known_vector() {
        // The SHA-256 of the empty input is a fixed, well-known value.
        assert_eq!(
            hex_sha256(&[]),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sha256_of_abc_is_known_vector() {
        assert_eq!(
            hex_sha256(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn top_level_symlink_to_regular_file_is_followed() {
        // NVIDIA ships `libcudart.so` -> `libcudart.so.12` -> `libcudart.so.X`
        // symlink chains. A symlink passed directly as the top-level target
        // must resolve to its regular-file target and be scanned, not refused.
        use std::io::Write as _;

        let dir = std::env::temp_dir().join(format!(
            "cudabom-walk-symlink-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let real = dir.join("real.bin");
        std::fs::File::create(&real)
            .unwrap()
            .write_all(b"hello")
            .unwrap();
        let link = dir.join("link.bin");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&real, &link).unwrap();

        #[cfg(unix)]
        {
            let mut budget = cudabom_core::Limits::default().budget();
            let mut seen = Vec::new();
            let res = walk_target(&link, &mut budget, &mut |f: ScannedFile| {
                seen.push(f.location.path.clone());
                Ok(())
            });
            assert!(res.is_ok(), "symlink target should be followed: {res:?}");
            assert_eq!(seen.len(), 1, "exactly one file scanned");
            // Logical name is the symlink's own name, not its target's.
            assert_eq!(seen[0], "link.bin");
        }

        std::fs::remove_dir_all(&dir).ok();
    }
}
