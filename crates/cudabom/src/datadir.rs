//! Resolution of the per-user data directory that holds the fingerprint
//! database and advisory index a scan reads.
//!
//! cudabom ships as a lone binary; `cudabom update` populates this directory
//! from the published data bundle, and `scan`/`gate`/`vex`/etc. default their
//! `--db`/`--advisories` paths to it when the flags are omitted.
//!
//! Resolution is a pure function of the environment (no `dirs`-style crate), so
//! it is trivially testable and never reads an install prefix: the data is
//! mutable, user-refreshable state, so it follows the *user*, not the binary.
//! Two sources apply on every platform and win first:
//!
//! 1. `CUDABOM_DATA_DIR`: explicit override, for tests and unusual layouts.
//! 2. `SNAP_USER_DATA/cudabom`: set inside a strict-confinement Snap, where the
//!    real `$HOME` is not writable but this per-revision dir is.
//!
//! After those, the platform's native per-user data convention applies (first
//! present wins):
//!
//! - **Linux / BSD / other non-macOS, non-Windows targets**: `XDG_DATA_HOME/cudabom`,
//!   then the XDG default `HOME/.local/share/cudabom`.
//! - **macOS**: `XDG_DATA_HOME/cudabom` when a user has opted into XDG, else
//!   the Apple convention `HOME/Library/Application Support/cudabom`.
//! - **Windows**: `LOCALAPPDATA\cudabom`, then `APPDATA\cudabom`, then
//!   `USERPROFILE\AppData\Local\cudabom`.
//!
//! Within the data directory the layout mirrors the repository:
//! `fingerprints/<product>/*.json` and `advisories/index.json`.

use std::path::{Path, PathBuf};

/// The data-subdirectory name under whichever base directory is resolved.
const APP_DIR: &str = "cudabom";

/// Resolve the cudabom data directory (see module docs). Returns `None` only
/// when no base could be determined for the running platform.
pub(crate) fn data_dir() -> Option<PathBuf> {
    // Cross-platform sources that always take precedence.
    if let Some(dir) = non_empty_env("CUDABOM_DATA_DIR") {
        return Some(PathBuf::from(dir));
    }
    if let Some(snap) = non_empty_env("SNAP_USER_DATA") {
        return Some(Path::new(&snap).join(APP_DIR));
    }
    platform_data_dir()
}

/// The native per-user data directory for the target OS. Each OS delegates to a
/// pure `*_from` helper parameterized by an env lookup, so the chains are
/// testable without mutating process environment.
#[cfg(windows)]
fn platform_data_dir() -> Option<PathBuf> {
    windows_from(non_empty_env)
}

#[cfg(target_os = "macos")]
fn platform_data_dir() -> Option<PathBuf> {
    macos_from(non_empty_env)
}

#[cfg(not(any(windows, target_os = "macos")))]
fn platform_data_dir() -> Option<PathBuf> {
    xdg_from(non_empty_env)
}

/// Windows: per-user, machine-local application data under `%LOCALAPPDATA%`
/// (roaming `%APPDATA%` is the fallback for older setups), then a last-resort
/// reconstruction from `%USERPROFILE%`.
#[cfg(any(windows, test))]
fn windows_from(env: impl Fn(&str) -> Option<String>) -> Option<PathBuf> {
    if let Some(local) = env("LOCALAPPDATA") {
        return Some(Path::new(&local).join(APP_DIR));
    }
    if let Some(roaming) = env("APPDATA") {
        return Some(Path::new(&roaming).join(APP_DIR));
    }
    if let Some(profile) = env("USERPROFILE") {
        return Some(Path::new(&profile).join("AppData\\Local").join(APP_DIR));
    }
    None
}

/// macOS: honor an explicit XDG opt-in, else the Apple "Application Support"
/// convention. (`HOME` is effectively always set on macOS; absent it, `None`.)
#[cfg(any(target_os = "macos", test))]
fn macos_from(env: impl Fn(&str) -> Option<String>) -> Option<PathBuf> {
    if let Some(xdg) = env("XDG_DATA_HOME") {
        return Some(Path::new(&xdg).join(APP_DIR));
    }
    let home = env("HOME")?;
    Some(
        Path::new(&home)
            .join("Library")
            .join("Application Support")
            .join(APP_DIR),
    )
}

/// Linux, the BSDs, and any other non-macOS, non-Windows target: the
/// freedesktop XDG base-directory spec. `XDG_DATA_HOME` when set, else the
/// `HOME/.local/share` default.
#[cfg(any(not(any(windows, target_os = "macos")), test))]
fn xdg_from(env: impl Fn(&str) -> Option<String>) -> Option<PathBuf> {
    if let Some(xdg) = env("XDG_DATA_HOME") {
        return Some(Path::new(&xdg).join(APP_DIR));
    }
    let home = env("HOME")?;
    Some(Path::new(&home).join(".local/share").join(APP_DIR))
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

/// The environment variables consulted to resolve the data directory on the
/// running platform, as a human-readable list for error hints. Kept adjacent to
/// [`data_dir`] so the message cannot drift from the resolution logic.
pub(crate) fn resolution_sources() -> &'static str {
    #[cfg(windows)]
    {
        "CUDABOM_DATA_DIR, SNAP_USER_DATA, LOCALAPPDATA, APPDATA, or USERPROFILE"
    }
    #[cfg(not(windows))]
    {
        "CUDABOM_DATA_DIR, SNAP_USER_DATA, XDG_DATA_HOME, or HOME"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// A deterministic env lookup over a fixed map, so the per-OS resolution
    /// chains are tested without mutating (racy) process environment.
    fn env_from<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        let map: HashMap<&str, &str> = pairs.iter().copied().collect();
        move |k| map.get(k).map(|v| (*v).to_string())
    }

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

    #[test]
    fn xdg_prefers_xdg_data_home_then_home_default() {
        assert_eq!(
            xdg_from(env_from(&[
                ("XDG_DATA_HOME", "/x/data"),
                ("HOME", "/home/u")
            ])),
            Some(PathBuf::from("/x/data/cudabom")),
        );
        assert_eq!(
            xdg_from(env_from(&[("HOME", "/home/u")])),
            Some(PathBuf::from("/home/u/.local/share/cudabom")),
        );
        // No HOME and no XDG: unresolvable.
        assert_eq!(xdg_from(env_from(&[])), None);
    }

    #[test]
    fn macos_prefers_xdg_optin_then_application_support() {
        // A user who exports XDG_DATA_HOME on macOS gets XDG behavior.
        assert_eq!(
            macos_from(env_from(&[("XDG_DATA_HOME", "/x"), ("HOME", "/Users/u")])),
            Some(PathBuf::from("/x/cudabom")),
        );
        // Default macOS: Apple's Application Support, not ~/.local/share.
        assert_eq!(
            macos_from(env_from(&[("HOME", "/Users/u")])),
            Some(PathBuf::from(
                "/Users/u/Library/Application Support/cudabom"
            )),
        );
        assert_eq!(macos_from(env_from(&[])), None);
    }

    #[test]
    fn windows_prefers_localappdata_then_appdata_then_userprofile() {
        assert_eq!(
            windows_from(env_from(&[
                ("LOCALAPPDATA", "C:\\Users\\u\\AppData\\Local"),
                ("APPDATA", "C:\\Users\\u\\AppData\\Roaming"),
            ])),
            Some(PathBuf::from("C:\\Users\\u\\AppData\\Local").join("cudabom")),
        );
        assert_eq!(
            windows_from(env_from(&[("APPDATA", "C:\\Users\\u\\AppData\\Roaming")])),
            Some(PathBuf::from("C:\\Users\\u\\AppData\\Roaming").join("cudabom")),
        );
        assert_eq!(
            windows_from(env_from(&[("USERPROFILE", "C:\\Users\\u")])),
            Some(
                PathBuf::from("C:\\Users\\u")
                    .join("AppData\\Local")
                    .join("cudabom")
            ),
        );
        assert_eq!(windows_from(env_from(&[])), None);
    }
}
