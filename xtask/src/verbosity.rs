//! xtask's counterpart to the CLI verbosity control.
//!
//! xtask is a separate binary from the shipped `cudabom` CLI and shares no
//! library with it, so it carries its own tiny verbosity switch rather than
//! taking a dependency just for logging. The behavior mirrors the CLI: a global
//! `-v/--verbose` (repeatable) and `-q/--quiet` set one process-wide level that
//! gates status output on stderr. Machine-relevant output (written files) is
//! unaffected.

use std::sync::atomic::{AtomicU8, Ordering};

/// Diagnostic verbosity for xtask.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Level {
    /// Only errors.
    Quiet = 0,
    /// Default: high-level status.
    Normal = 1,
    /// Per-item detail (each archive, each component).
    Verbose = 2,
    /// Internal decisions.
    Debug = 3,
}

static LEVEL: AtomicU8 = AtomicU8::new(Level::Normal as u8);

/// Parse the global verbosity flags out of `args`, set the process level, and
/// return `args` with those flags removed so task-specific parsing is not
/// confused by them. Recognized anywhere in the argument list:
/// `-q`/`--quiet`, `-v`/`--verbose` (repeatable), and `-vv` for debug.
pub(crate) fn take_flags(args: Vec<String>) -> Vec<String> {
    let mut quiet = false;
    let mut verbose: u8 = 0;
    let mut rest = Vec::with_capacity(args.len());
    for arg in args {
        match arg.as_str() {
            "-q" | "--quiet" => quiet = true,
            "-v" | "--verbose" => verbose = verbose.saturating_add(1),
            // Allow bundled short forms like `-vv`.
            s if s.len() > 1
                && s.starts_with('-')
                && !s.starts_with("--")
                && s[1..].chars().all(|c| c == 'v') =>
            {
                let count = u8::try_from(s.len() - 1).unwrap_or(u8::MAX);
                verbose = verbose.saturating_add(count);
            }
            _ => rest.push(arg),
        }
    }
    set(verbose, quiet);
    rest
}

/// Set the level directly (used by [`take_flags`] and tests).
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

/// The current level.
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

/// Status line at [`Level::Normal`].
macro_rules! status {
    ($($arg:tt)*) => {
        if $crate::verbosity::enabled($crate::verbosity::Level::Normal) {
            eprintln!($($arg)*);
        }
    };
}

/// Per-item detail at [`Level::Verbose`].
macro_rules! detail {
    ($($arg:tt)*) => {
        if $crate::verbosity::enabled($crate::verbosity::Level::Verbose) {
            eprintln!($($arg)*);
        }
    };
}

pub(crate) use {detail, status};

#[cfg(test)]
mod tests {
    use super::*;

    // Both tests mutate the process-global `LEVEL`; serialize them so they do
    // not race when the test binary runs them in parallel.
    static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn take_flags_extracts_and_sets_level() {
        let _guard = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let rest = take_flags(vec![
            "corpus".into(),
            "-v".into(),
            "fetch".into(),
            "--quiet".into(),
        ]);
        // Quiet wins when both are present.
        assert_eq!(level(), Level::Quiet);
        assert_eq!(rest, vec!["corpus".to_string(), "fetch".to_string()]);
        set(0, false);
    }

    #[test]
    fn bundled_v_flags_count() {
        let _guard = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let rest = take_flags(vec!["-vv".into(), "bundle".into()]);
        assert_eq!(level(), Level::Debug);
        assert_eq!(rest, vec!["bundle".to_string()]);
        set(0, false);
    }
}
