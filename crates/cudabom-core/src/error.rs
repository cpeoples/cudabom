//! The shared error type for cudabom.
//!
//! Downstream crates convert their own failures into [`Error`] so the CLI can
//! map a single error taxonomy onto the documented process exit codes (see
//! `cudabom`). Variants are deliberately coarse: they distinguish only what
//! the exit-code contract needs, carrying detail as a message string rather
//! than structured fields.

use std::fmt;

/// Convenience alias used throughout the workspace.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Top-level error taxonomy.
///
/// The grouping mirrors the CLI exit-code contract: input problems, malformed
/// artifacts, and internal invariants are distinguishable so the front end can
/// choose the right exit code without string-matching messages.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The target could not be read or is not a supported input kind.
    #[error("input error: {0}")]
    Input(String),

    /// A parser rejected malformed or hostile bytes. Parsers must return this
    /// rather than panic (see `docs/threat-model.md`).
    #[error("malformed artifact: {0}")]
    Malformed(String),

    /// A configured safety limit was exceeded during extraction/parsing.
    #[error("safety limit exceeded: {0}")]
    LimitExceeded(String),

    /// An internal invariant was violated. These are bugs, not user error.
    #[error("internal error: {0}")]
    Internal(String),
}

impl Error {
    /// Build an [`Error::Input`] from anything printable.
    pub fn input(msg: impl fmt::Display) -> Self {
        Self::Input(msg.to_string())
    }

    /// Build an [`Error::Malformed`] from anything printable.
    pub fn malformed(msg: impl fmt::Display) -> Self {
        Self::Malformed(msg.to_string())
    }
}
