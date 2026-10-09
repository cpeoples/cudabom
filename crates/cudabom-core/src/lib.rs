//! Shared domain types for cudabom.
//!
//! `cudabom-core` is the dependency-light center of the workspace. It defines
//! the vocabulary every other crate speaks: [`Artifact`], [`Location`],
//! [`Component`], [`Evidence`], [`Confidence`], and [`Finding`], plus the
//! tunable safety [`Limits`] that bound how the extractor and parsers behave
//! when fed hostile input.
//!
//! Nothing here performs I/O, parsing, or analysis; those live in the parser,
//! identify, advisory, sbom, and report crates. Keeping the types here free of
//! heavy dependencies lets the whole workspace share a stable, serializable
//! contract. See `docs/evidence-model.md` for the evidence and confidence
//! semantics these types encode.

pub mod config;
pub mod error;
pub mod model;
pub mod paths;

pub use config::{Budget, Limits};
pub use error::{Error, Result};
pub use model::{
    Artifact, ArtifactKind, Component, Confidence, Evidence, EvidenceKind, Finding, Location,
    Relationship,
};

/// The cudabom native output schema version.
///
/// This is the **output contract** version for `cudabom scan --format json`,
/// bumped only when that JSON changes in a backwards-incompatible way. It is
/// deliberately **decoupled** from the crate/release version (`CARGO_PKG_VERSION`,
/// defined once in `[workspace.package]`): the tool can ship many releases
/// without changing its output schema. Do not treat this as the release version.
pub const SCHEMA_VERSION: &str = "0.1.0";

/// The canonical tool name, used as the default HTTP `User-Agent` for every
/// network fetch and anywhere else cudabom identifies itself as a client.
/// Single-sourced here so the user-agent cannot drift between crates. (SARIF
/// driver name, SBOM namespace, and the clap binary name are distinct identity
/// surfaces and intentionally defined at their own sites.)
pub const TOOL_NAME: &str = "cudabom";

/// Lowercase hex encoding of a byte slice. The single implementation shared by
/// every crate that renders a digest, build-id, or raw bytes as hex.
#[must_use]
pub fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}
