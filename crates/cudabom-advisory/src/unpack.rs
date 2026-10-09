//! Shared helpers for safely unpacking downloaded archives: sha256 sidecar
//! parsing, path-traversal rejection, wrapper-directory stripping, and the
//! bounded gzip-tar extraction driver. These are used by both the CSAF fetch
//! path (`fetch`) and the data-bundle path (`data`), which unpack gzip-tar
//! archives under the same safety rules.

use std::io::Read;
use std::path::{Component, Path};

use crate::fetch::{FetchError, UnpackLimits};

/// Extract the sha256 digest from a checksum sidecar file. The sidecar may be a
/// bare digest or a `‹digest›  ‹filename›` line; the first 64-char hex token is
/// returned.
pub(crate) fn parse_sha256_sidecar(bytes: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(bytes).ok()?;
    text.split_whitespace()
        .find(|tok| tok.len() == 64 && tok.bytes().all(|b| b.is_ascii_hexdigit()))
        .map(str::to_string)
}

/// True if `path` can be safely joined under a destination directory: it must
/// be relative and contain no `..`, root, or drive-prefix components.
pub(crate) fn is_safe_path(path: &Path) -> bool {
    if path.is_absolute() {
        return false;
    }
    for component in path.components() {
        match component {
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return false,
            Component::Normal(_) | Component::CurDir => {}
        }
    }
    true
}

/// Strip the first path component (the archive's `‹repo›-‹tag›/` wrapper
/// directory) and return the remainder as a forward-slash string.
pub(crate) fn strip_leading_component(path: &Path) -> String {
    let mut comps = path.components();
    comps.next();
    comps.as_path().to_string_lossy().replace('\\', "/")
}

/// Drive a bounded, path-safe extraction of a gzip-tar archive.
///
/// For every entry that is path-safe (no absolute/`..`/root/prefix component)
/// and accepted by `accept`, this reads the entry body under the per-file and
/// total-size limits and hands the wrapper-stripped inner path and bytes to
/// `sink`. The wrapper directory (`‹repo›-‹tag›/`) is stripped before both
/// callbacks see the path. Entry-count, per-file, and total-byte limits are
/// enforced here so neither caller re-implements them.
///
/// `accept` receives the inner path and whether the entry is a directory, and
/// returns `true` to extract it. Returning `false` skips the entry without
/// reading its body.
pub(crate) fn extract_gzip_tar<A, S>(
    gzip_tar: &[u8],
    limits: &UnpackLimits,
    mut accept: A,
    mut sink: S,
) -> Result<(), FetchError>
where
    A: FnMut(&str, bool) -> bool,
    S: FnMut(&str, Vec<u8>) -> Result<(), FetchError>,
{
    let decoder = flate2::read::GzDecoder::new(gzip_tar);
    let mut archive = tar::Archive::new(decoder);
    let entries = archive
        .entries()
        .map_err(|e| FetchError::Archive(e.to_string()))?;

    let mut total: u64 = 0;
    let mut count: usize = 0;

    for entry in entries {
        let mut entry = entry.map_err(|e| FetchError::Archive(e.to_string()))?;

        count += 1;
        if count > limits.max_entries {
            return Err(FetchError::LimitExceeded(format!(
                "more than {} entries",
                limits.max_entries
            )));
        }

        let path = entry
            .path()
            .map_err(|e| FetchError::Archive(e.to_string()))?;
        if !is_safe_path(&path) {
            continue;
        }
        let is_dir = entry.header().entry_type().is_dir();
        let inner = strip_leading_component(&path);
        if !accept(&inner, is_dir) {
            continue;
        }

        // Reject on the untrusted header first, then enforce again on the
        // bytes actually read (the header size is not trusted).
        if entry.header().size().unwrap_or(0) > limits.max_file_bytes {
            return Err(too_large(limits.max_file_bytes));
        }
        let mut buf = Vec::new();
        entry
            .by_ref()
            .take(limits.max_file_bytes.saturating_add(1))
            .read_to_end(&mut buf)
            .map_err(|e| FetchError::Archive(e.to_string()))?;
        if buf.len() as u64 > limits.max_file_bytes {
            return Err(too_large(limits.max_file_bytes));
        }

        total = total.saturating_add(buf.len() as u64);
        if total > limits.max_total_bytes {
            return Err(FetchError::LimitExceeded(format!(
                "total extracted size exceeds {} bytes",
                limits.max_total_bytes
            )));
        }

        sink(&inner, buf)?;
    }

    Ok(())
}

/// The per-file size-limit error, shared by the header and post-read checks.
fn too_large(limit: u64) -> FetchError {
    FetchError::LimitExceeded(format!("entry exceeds {limit} bytes"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_sidecar_digest() {
        let digest = "a".repeat(64);
        assert_eq!(
            parse_sha256_sidecar(digest.as_bytes()),
            Some(digest.clone())
        );
        let line = format!("{digest}  file.tar.gz\n");
        assert_eq!(parse_sha256_sidecar(line.as_bytes()), Some(digest));
        assert_eq!(parse_sha256_sidecar(b"not-a-digest"), None);
    }

    #[test]
    fn safe_path_rejects_traversal_and_absolute() {
        assert!(is_safe_path(Path::new("repo/a.json")));
        assert!(!is_safe_path(Path::new("/etc/a.json")));
        assert!(!is_safe_path(Path::new("../a.json")));
    }

    #[test]
    fn strips_wrapper_directory() {
        assert_eq!(
            strip_leading_component(Path::new("repo-abc123/fingerprints/x.json")),
            "fingerprints/x.json"
        );
    }
}
