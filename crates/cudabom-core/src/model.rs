//! The cudabom domain model.
//!
//! These are the serializable types that flow through the pipeline:
//!
//! ```text
//! Artifact --> Location --> Evidence --> Component (+ Confidence, Relationship) --> Finding
//! ```
//!
//! See `docs/evidence-model.md` for the authoritative definitions of the
//! evidence and confidence semantics these types encode.

use serde::{Deserialize, Serialize};

/// A top-level thing cudabom was asked to scan (a wheel, a `.so`, an image
/// tarball, a directory, ...).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Artifact {
    /// Display identifier (usually the path or image reference).
    pub name: String,
    /// What kind of input this is.
    pub kind: ArtifactKind,
    /// sha256 of the artifact bytes, when it is a single file.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
}

/// The supported input kinds. Extended as extractors land (see spec Section 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum ArtifactKind {
    /// Python wheel (`.whl`).
    Wheel,
    /// Source distribution (`.tar.gz`).
    Sdist,
    /// A single ELF object, shared library, archive, or executable.
    Elf,
    /// A directory walked recursively.
    Directory,
    /// A `docker save` tarball or OCI image layout.
    ContainerImage,
    /// A standalone GPU code object (`.cubin`, `.fatbin`, `.ptx`).
    GpuCode,
    /// An input whose kind could not be determined.
    Unknown,
}

/// Where inside an [`Artifact`] a piece of [`Evidence`] was observed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Location {
    /// Path of the containing file relative to the artifact root.
    pub path: String,
    /// sha256 of the containing file.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// For container images: the layer digest this file came from.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub layer_digest: Option<String>,
}

/// A single observation that supports (or complicates) an identity claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    /// What was observed.
    pub kind: EvidenceKind,
    /// Where it was observed.
    pub location: Location,
    /// The raw observed value (e.g. a SONAME string), for explainability.
    pub detail: String,
}

/// The catalogue of evidence types (spec Section 7.1).
///
/// Marked `#[non_exhaustive]` because new evidence types are added as parsers
/// gain the ability to observe them; each must be validated against real
/// binaries before it is trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum EvidenceKind {
    Soname,
    FileName,
    NeededEntry,
    VersionString,
    SymbolVersionNode,
    ExportedSymbolSet,
    InternalSymbolSet,
    KnownFileHash,
    BuildId,
    FatbinProducer,
    CodeSimilarity,
    DeclaredSbom,
    /// The target machine architecture of the identified binary (e.g.
    /// `X86_64`, `Aarch64`), read from the ELF `e_machine` or PE COFF machine.
    /// Not an identity signal on its own, but it disambiguates otherwise
    /// identical findings (notably `linux-x86_64` vs `linux-sbsa` builds that
    /// share a SONAME) and records which ABI a `Likely` SONAME match came from.
    Architecture,
}

impl EvidenceKind {
    /// The canonical kebab-case token (matches the serde representation).
    /// Shared by renderers so emitted evidence tokens cannot drift from a
    /// variant rename.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            EvidenceKind::Soname => "soname",
            EvidenceKind::FileName => "file-name",
            EvidenceKind::NeededEntry => "needed-entry",
            EvidenceKind::VersionString => "version-string",
            EvidenceKind::SymbolVersionNode => "symbol-version-node",
            EvidenceKind::ExportedSymbolSet => "exported-symbol-set",
            EvidenceKind::InternalSymbolSet => "internal-symbol-set",
            EvidenceKind::KnownFileHash => "known-file-hash",
            EvidenceKind::BuildId => "build-id",
            EvidenceKind::FatbinProducer => "fatbin-producer",
            EvidenceKind::CodeSimilarity => "code-similarity",
            EvidenceKind::DeclaredSbom => "declared-sbom",
            EvidenceKind::Architecture => "architecture",
        }
    }
}

/// How confident cudabom is in an identity + version claim (spec Section 7.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    /// CUDA-related signals exist but identity cannot be established.
    Unknown,
    /// Identity well supported; version incomplete or a supported range only.
    Likely,
    /// Known-hash/build-id match, or two agreeing strong evidence items.
    Exact,
}

impl Confidence {
    /// The canonical lowercase token (matches the serde representation).
    /// Shared by every renderer so SARIF, Markdown, and SBOM output cannot
    /// drift apart.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Confidence::Unknown => "unknown",
            Confidence::Likely => "likely",
            Confidence::Exact => "exact",
        }
    }
}

/// How a [`Component`] relates to the [`Artifact`] (spec Section 7.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum Relationship {
    /// The component's bytes are embedded in this file/artifact.
    EmbeddedCopy,
    /// Component code was statically linked into another binary.
    StaticallyLinked,
    /// A `NEEDED` dependency supplied elsewhere.
    DynamicDependency,
    /// Listed in an SBOM but not found in the bytes.
    DeclaredOnly,
}

impl Relationship {
    /// The canonical kebab-case token (matches the serde representation).
    /// Shared by every renderer so output cannot drift apart.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Relationship::EmbeddedCopy => "embedded-copy",
            Relationship::StaticallyLinked => "statically-linked",
            Relationship::DynamicDependency => "dynamic-dependency",
            Relationship::DeclaredOnly => "declared-only",
        }
    }
}

/// An identified CUDA component and how it was identified.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Component {
    /// Canonical component name (e.g. `cudart`, `cublas`, `cudnn`).
    pub name: String,
    /// Exact version or supported range, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Every version this match could be, when a single strong signal (a file
    /// hash or GNU build-id) is shared by more than one release.
    ///
    /// NVIDIA frequently ships the byte-identical `.so` across several patch
    /// releases (e.g. one `libnppc.so` build-id covers up to a dozen `npp`
    /// versions). The match is still *exact* about the bytes, which is why the
    /// confidence stays `Exact`, but it cannot single out one micro version.
    /// Rather than silently reporting only the lowest, `version` holds the
    /// representative (lowest, deterministic) and this field holds the complete
    /// sorted set so the ambiguity is explicit and advisory correlation can span
    /// all of them. Empty/absent when the signal pins exactly one version.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub candidate_versions: Vec<String>,
    /// How the component relates to the artifact.
    pub relationship: Relationship,
}

/// A component identification plus its confidence, supporting evidence, and any
/// conflicts. This is the unit reported to the user and rendered to every
/// output format.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    /// Stable identifier used by `cudabom explain <finding-id>`.
    pub id: String,
    /// The identified component.
    pub component: Component,
    /// Confidence in the identification.
    pub confidence: Confidence,
    /// Every observation that fed this finding.
    pub evidence: Vec<Evidence>,
    /// Notes on conflicting evidence, if any.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conflicts: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn confidence_orders_unknown_below_exact() {
        assert!(Confidence::Unknown < Confidence::Likely);
        assert!(Confidence::Likely < Confidence::Exact);
    }

    #[test]
    fn confidence_serializes_lowercase() {
        assert_eq!(
            serde_json::to_string(&Confidence::Exact).unwrap(),
            "\"exact\""
        );
    }

    #[test]
    fn evidence_kind_as_str_matches_serde() {
        for kind in [
            EvidenceKind::Soname,
            EvidenceKind::FileName,
            EvidenceKind::NeededEntry,
            EvidenceKind::VersionString,
            EvidenceKind::SymbolVersionNode,
            EvidenceKind::ExportedSymbolSet,
            EvidenceKind::InternalSymbolSet,
            EvidenceKind::KnownFileHash,
            EvidenceKind::BuildId,
            EvidenceKind::FatbinProducer,
            EvidenceKind::CodeSimilarity,
            EvidenceKind::DeclaredSbom,
            EvidenceKind::Architecture,
        ] {
            let serde = serde_json::to_string(&kind).unwrap();
            assert_eq!(format!("\"{}\"", kind.as_str()), serde);
        }
    }
}
