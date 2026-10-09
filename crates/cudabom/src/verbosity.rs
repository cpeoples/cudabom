//! A single, lightweight verbosity control shared by every subcommand.
//!
//! cudabom writes machine-readable results to stdout (or `--output`) and keeps
//! all human-facing diagnostics on stderr. This module is the one place that
//! decides how loud those diagnostics are, driven by the global `-v/--verbose`
//! and `-q/--quiet` flags. It intentionally avoids a logging framework: the
//! need is a three-way level, not structured logging, so a process-global atomic
//! plus a few macros keep it dependency-free and trivial to reason about.
//!
//! Levels:
//! - [`Level::Quiet`]: only errors (which always print via `eprintln!`).
//! - [`Level::Normal`]: the default; high-level status lines.
//! - [`Level::Verbose`]: adds per-item detail (each file, each component).
//! - [`Level::Debug`]: `-vv`, adds internal decisions useful when debugging.

use std::sync::atomic::{AtomicU8, Ordering};

/// How much diagnostic detail to emit on stderr.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Level {
    /// Only errors.
    Quiet = 0,
    /// Default: high-level status.
    Normal = 1,
    /// Per-item detail.
    Verbose = 2,
    /// Internal decisions (`-vv`).
    Debug = 3,
}

/// The process-global level, stored as its numeric discriminant. Defaults to
/// [`Level::Normal`] so code paths that never call [`set`] (e.g. unit tests)
/// behave as an ordinary run.
static LEVEL: AtomicU8 = AtomicU8::new(Level::Normal as u8);

/// Set the global verbosity from the parsed global flags. A `--quiet` versus
/// `--verbose` conflict is impossible here because clap marks the two flags
/// mutually exclusive, so the mapping is unambiguous: quiet, then
/// verbose-count, else normal.
pub(crate) fn set(verbose: u8, quiet: bool) {
    let level = if quiet {
        Level::Quiet
    } else {
        match verbose {
            0 => Level::Normal,
            1 => Level::Verbose,
            _ => Level::Debug,
        }
    };
    LEVEL.store(level as u8, Ordering::Relaxed);
}

/// The current global level.
pub(crate) fn level() -> Level {
    match LEVEL.load(Ordering::Relaxed) {
        0 => Level::Quiet,
        1 => Level::Normal,
        2 => Level::Verbose,
        _ => Level::Debug,
    }
}

/// True if the current level is at least `at`.
pub(crate) fn enabled(at: Level) -> bool {
    level() >= at
}

/// Emit a status line at [`Level::Normal`] (shown unless `--quiet`).
macro_rules! status {
    ($($arg:tt)*) => {
        if $crate::verbosity::enabled($crate::verbosity::Level::Normal) {
            eprintln!($($arg)*);
        }
    };
}

/// Emit a detail line at [`Level::Verbose`] (shown with `-v`).
macro_rules! detail {
    ($($arg:tt)*) => {
        if $crate::verbosity::enabled($crate::verbosity::Level::Verbose) {
            eprintln!($($arg)*);
        }
    };
}

/// Emit an internal-decision line at [`Level::Debug`] (shown with `-vv`).
macro_rules! debug {
    ($($arg:tt)*) => {
        if $crate::verbosity::enabled($crate::verbosity::Level::Debug) {
            eprintln!($($arg)*);
        }
    };
}

pub(crate) use {debug, detail, status};

#[cfg(test)]
mod tests {
    use super::*;

    // Both tests mutate the process-global `LEVEL`; serialize them so they do
    // not race when the test binary runs them in parallel.
    static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn flags_map_to_levels() {
        let _guard = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        set(0, false);
        assert_eq!(level(), Level::Normal);
        set(1, false);
        assert_eq!(level(), Level::Verbose);
        set(2, false);
        assert_eq!(level(), Level::Debug);
        set(5, false);
        assert_eq!(level(), Level::Debug);
        set(0, true);
        assert_eq!(level(), Level::Quiet);
        // Restore the default so later tests in this binary are unaffected.
        set(0, false);
    }

    #[test]
    fn enabled_respects_ordering() {
        let _guard = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        set(0, false);
        assert!(enabled(Level::Quiet));
        assert!(enabled(Level::Normal));
        assert!(!enabled(Level::Verbose));
        set(0, false);
    }
}
