//! Path sanitization for archive entries.
//!
//! Archive entry names are attacker-controlled. Before an entry path is used,
//! even just to build a logical [`cudabom_core::Location`], it is validated
//! so a crafted name cannot escape the artifact's virtual root. cudabom never
//! writes extracted members to disk, so this is defense of the logical path
//! space and of any caller that might later join these names onto a real path.
//!
//! Rejected: absolute paths, Windows drive/UNC paths, and any `..` component
//! (the classic "zip slip" / path-traversal escape). A rejected name returns an
//! error; the archive expanders treat that as "skip this entry and continue"
//! (cudabom never writes members to disk, so an unsafe name cannot escape, and
//! one hostile entry must not abort scanning the rest of a real tree). Callers
//! that join these names onto a real path must still treat the error as fatal.

use cudabom_core::{Error, Result};
use std::io::Read;

/// Read an archive member with a hard ceiling, never trusting its declared
/// size. Reads up to `cap + 1` bytes so a member that produces more than it
/// declared is detected rather than silently truncated, and returns
/// `LimitExceeded` (tagged with `kind`, e.g. `"zip"`) when it overruns. The
/// capacity hint is `declared` clamped to the cap and to `usize`, so a lying
/// header cannot force a huge up-front allocation.
pub(crate) fn read_capped(
    reader: &mut impl Read,
    declared: u64,
    cap: u64,
    kind: &str,
    name: &str,
) -> Result<Vec<u8>> {
    let hint = usize::try_from(declared.min(cap)).unwrap_or(usize::MAX);
    let mut buf = Vec::with_capacity(hint);
    let read = reader
        .take(cap.saturating_add(1))
        .read_to_end(&mut buf)
        .map_err(|e| Error::malformed(format!("{kind} entry {name:?} read error: {e}")))?
        as u64;
    if read > cap {
        return Err(Error::LimitExceeded(format!(
            "{kind} entry {name:?} exceeds per-file cap {cap} during decompression"
        )));
    }
    Ok(buf)
}

/// Normalize and validate an archive entry name into a safe, `/`-separated
/// logical path rooted at the virtual archive root.
///
/// Returns an error if the name is absolute, contains a `..` component, or
/// contains a Windows drive prefix or UNC path. Leading `./` and redundant
/// separators are collapsed. An entry that normalizes to nothing (e.g. `"."`)
/// yields an error so it is not treated as the root itself.
pub(crate) fn sanitize_entry_path(raw: &str) -> Result<String> {
    // Normalize separators: archives may use `\` on Windows-produced files.
    let unified = raw.replace('\\', "/");

    // Absolute POSIX path.
    if unified.starts_with('/') {
        return Err(Error::malformed(format!(
            "unsafe archive entry (absolute path): {raw:?}"
        )));
    }

    // Windows drive-letter (e.g. `C:`) or UNC-ish prefixes.
    if has_windows_prefix(&unified) {
        return Err(Error::malformed(format!(
            "unsafe archive entry (windows drive/UNC path): {raw:?}"
        )));
    }

    let mut parts: Vec<&str> = Vec::new();
    for component in unified.split('/') {
        match component {
            // Skip empty (from `//` or trailing `/`) and current-dir markers.
            "" | "." => {}
            // Any parent-dir component is a traversal attempt: reject outright.
            ".." => {
                return Err(Error::malformed(format!(
                    "unsafe archive entry (path traversal via '..'): {raw:?}"
                )));
            }
            other => parts.push(other),
        }
    }

    if parts.is_empty() {
        return Err(Error::malformed(format!(
            "archive entry has no usable path: {raw:?}"
        )));
    }

    Ok(parts.join("/"))
}

/// Join a sanitized child path under a parent logical path with `/`.
#[must_use]
pub(crate) fn join_logical(parent: &str, child: &str) -> String {
    if parent.is_empty() {
        child.to_string()
    } else {
        format!("{parent}/{child}")
    }
}

/// True if the path begins with a Windows drive letter (`C:...`) or a UNC
/// path (`//server/...`, already unified from `\\server\...`).
fn has_windows_prefix(unified: &str) -> bool {
    // Drive letter: an ASCII alphabetic char followed by ':'.
    let drive = {
        let bytes = unified.as_bytes();
        bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
    };
    // UNC after separator unification looks like a leading "//".
    let unc = unified.starts_with("//");
    drive || unc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_normal_paths() {
        assert_eq!(sanitize_entry_path("a/b/c.so").unwrap(), "a/b/c.so");
        assert_eq!(sanitize_entry_path("./a/./b").unwrap(), "a/b");
        assert_eq!(sanitize_entry_path("a//b").unwrap(), "a/b");
        assert_eq!(
            sanitize_entry_path("pkg-1.0.dist-info/RECORD").unwrap(),
            "pkg-1.0.dist-info/RECORD"
        );
    }

    #[test]
    fn rejects_absolute() {
        assert!(sanitize_entry_path("/etc/passwd").is_err());
    }

    #[test]
    fn rejects_traversal() {
        assert!(sanitize_entry_path("../../etc/passwd").is_err());
        assert!(sanitize_entry_path("a/../../b").is_err());
        assert!(sanitize_entry_path("a/../b").is_err()); // conservative: any `..`
    }

    #[test]
    fn rejects_windows_drive_and_unc() {
        assert!(sanitize_entry_path("C:/Windows/system32").is_err());
        assert!(sanitize_entry_path("\\\\server\\share\\x").is_err());
    }

    #[test]
    fn rejects_backslash_traversal() {
        // Windows-style separators must not smuggle a traversal past the check.
        assert!(sanitize_entry_path("..\\..\\etc\\passwd").is_err());
    }

    #[test]
    fn rejects_empty_and_dot() {
        assert!(sanitize_entry_path("").is_err());
        assert!(sanitize_entry_path(".").is_err());
        assert!(sanitize_entry_path("./").is_err());
    }

    #[test]
    fn join_logical_paths() {
        assert_eq!(join_logical("", "a"), "a");
        assert_eq!(join_logical("wheel.whl", "pkg/x.so"), "wheel.whl/pkg/x.so");
    }
}
