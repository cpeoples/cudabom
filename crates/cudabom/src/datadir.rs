//! Resolution of the per-user data directory that holds the fingerprint
//! database and advisory index a scan reads.
//!
//! cudabom ships as a lone binary; `cudabom update` populates this directory
//! from the published data bundle, and `scan`/`gate`/`vex`/etc. default their
//! `--db`/`--advisories` paths to it when the flags are omitted. Resolution
//! order (first present wins):
//!
//! 1. `CUDABOM_DATA_DIR`: explicit override, for tests and unusual layouts.
//! 2. `SNAP_USER_DATA/cudabom`: set inside a strict-confinement Snap, where the
//!    real `$HOME` is not writable but this per-revision dir is.
//! 3. `XDG_DATA_HOME/cudabom`: the freedesktop base directory, when set.
//! 4. `HOME/.local/share/cudabom`: the XDG default.
//!
//! Within the data directory the layout mirrors the repository:
//! `fingerprints/cuda/*.json` and `advisories/index.json`.

use std::path::{Path, PathBuf};

/// Resolve the cudabom data directory (see module docs). Returns `None` only
/// when no base could be determined (no override, no snap dir, no `XDG_DATA_HOME`,
/// and no `HOME`).
pub(crate) fn data_dir() -> Option<PathBuf> {
    if let Some(dir) = non_empty_env("CUDABOM_DATA_DIR") {
        return Some(PathBuf::from(dir));
    }
    if let Some(snap) = non_empty_env("SNAP_USER_DATA") {
        return Some(Path::new(&snap).join("cudabom"));
    }
    if let Some(xdg) = non_empty_env("XDG_DATA_HOME") {
        return Some(Path::new(&xdg).join("cudabom"));
    }
    if let Some(home) = non_empty_env("HOME") {
        return Some(Path::new(&home).join(".local/share/cudabom"));
    }
    None
}

/// The default fingerprint-database directory within the data dir.
///
/// Prefers the `fingerprints` parent (which `FingerprintDb::from_dir` loads
/// recursively, picking up every per-product subdirectory: `cuda`, `cudnn`,
/// `nccl`, ...). Falls back to the historical `fingerprints/cuda` path for data
/// bundles that predate the multi-product layout. Returns `None` when neither
/// exists.
pub(crate) fn default_db_dir() -> Option<PathBuf> {
    let base = data_dir()?;
    let parent = base.join(cudabom_core::paths::FINGERPRINTS_DIR);
    if parent.is_dir() {
        return Some(parent);
    }
    let legacy = base.join(cudabom_core::paths::CUDA_SHARD_DIR);
    legacy.is_dir().then_some(legacy)
}

/// The default advisory-index file within the data dir
/// (`<data>/advisories/index.json`), when a data dir and that file both exist.
pub(crate) fn default_advisories_file() -> Option<PathBuf> {
    let file = data_dir()?.join(cudabom_core::paths::ADVISORY_INDEX);
    file.is_file().then_some(file)
}

/// Read `name` from the environment, treating an empty value as unset.
fn non_empty_env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.trim().is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The env-var resolution order is a pure function of the inputs; assert it
    /// directly rather than mutating process env (which is racy across tests).
    #[test]
    fn non_empty_env_treats_blank_as_unset() {
        // A present-but-blank value is treated as absent.
        std::env::set_var("CUDABOM_TEST_BLANK", "   ");
        assert_eq!(non_empty_env("CUDABOM_TEST_BLANK"), None);
        std::env::set_var("CUDABOM_TEST_SET", "value");
        assert_eq!(non_empty_env("CUDABOM_TEST_SET").as_deref(), Some("value"));
        std::env::remove_var("CUDABOM_TEST_BLANK");
        std::env::remove_var("CUDABOM_TEST_SET");
    }

    #[test]
    fn override_takes_precedence() {
        std::env::set_var("CUDABOM_DATA_DIR", "/tmp/cudabom-test-data");
        assert_eq!(data_dir(), Some(PathBuf::from("/tmp/cudabom-test-data")));
        std::env::remove_var("CUDABOM_DATA_DIR");
    }
}
