//! Documented process exit codes for cudabom.
//!
//! These are part of the tool's public contract (spec Section 10) and are
//! referenced by the GitHub Action and CI examples. Keep this the single
//! source of truth; the CLI maps every outcome onto one of these.

use std::process::ExitCode;

/// The exit code taxonomy. The numeric values are stable API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitStatus {
    /// Success.
    Success = 0,
    /// Policy violation, or affected findings when `--fail-on` is set.
    Findings = 1,
    /// Usage error (bad flags/arguments).
    Usage = 2,
    /// Input error (target missing/unreadable/unsupported).
    Input = 3,
    /// Internal error (a bug in cudabom).
    Internal = 4,
}

impl From<ExitStatus> for ExitCode {
    fn from(status: ExitStatus) -> Self {
        ExitCode::from(status as u8)
    }
}

impl ExitStatus {
    /// The numeric code, for tests and documentation.
    pub const fn code(self) -> u8 {
        self as u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_match_the_documented_contract() {
        assert_eq!(ExitStatus::Success.code(), 0);
        assert_eq!(ExitStatus::Findings.code(), 1);
        assert_eq!(ExitStatus::Usage.code(), 2);
        assert_eq!(ExitStatus::Input.code(), 3);
        assert_eq!(ExitStatus::Internal.code(), 4);
    }
}
