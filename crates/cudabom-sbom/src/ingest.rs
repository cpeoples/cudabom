//! Reading *declared* CycloneDX documents (SBOM and VEX).
//!
//! cudabom's own emitter ([`crate::cyclonedx`]) is serialize-only and uses
//! `&'static str` for fixed fields, so it cannot round-trip as a reader. This
//! module is the deliberate counterpart: a small, permissive **deserialize**
//! model for the subset of CycloneDX a third-party declaration carries that
//! cudabom reconciles against its own discoveries.
//!
//! The target is NVIDIA NGC's published artifacts, which are CycloneDX JSON for
//! both the SBOM (`components`) and the VEX (`vulnerabilities` with
//! `analysis.state` and `affects`). The model is intentionally lenient: unknown
//! fields are ignored (no `deny_unknown_fields`) so it tolerates the full
//! CycloneDX surface and spec-version drift, reading only what it needs.

use serde::Deserialize;

/// A parsed declared CycloneDX document (SBOM and/or VEX).
///
/// A single document may be an SBOM (only `components`), a VEX (only
/// `vulnerabilities`), or both; each list is read independently.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct DeclaredBom {
    /// The declared components (the SBOM inventory).
    #[serde(default)]
    pub components: Vec<DeclaredComponent>,
    /// The declared vulnerability statements (the VEX analysis).
    #[serde(default)]
    pub vulnerabilities: Vec<DeclaredVulnerability>,
}

/// One declared component from a CycloneDX SBOM.
#[derive(Debug, Clone, Deserialize)]
pub struct DeclaredComponent {
    /// Component name as declared (e.g. `cuda-cudart`, `libcublas`).
    pub name: String,
    /// Declared version, when present.
    #[serde(default)]
    pub version: Option<String>,
    /// Package URL, when present (e.g. `pkg:deb/...` or `pkg:pypi/...`).
    #[serde(default)]
    pub purl: Option<String>,
    /// Stable reference used by VEX `affects[].ref`, when present.
    #[serde(rename = "bom-ref", default)]
    pub bom_ref: Option<String>,
}

/// One declared vulnerability statement from a CycloneDX VEX.
#[derive(Debug, Clone, Deserialize)]
pub struct DeclaredVulnerability {
    /// The vulnerability identifier (CVE id, GHSA id, ...).
    pub id: String,
    /// The impact analysis (VEX state + optional justification/detail).
    #[serde(default)]
    pub analysis: Option<DeclaredAnalysis>,
    /// The components this statement is about.
    #[serde(default)]
    pub affects: Vec<DeclaredAffects>,
}

/// The `analysis` object of a declared vulnerability.
#[derive(Debug, Clone, Deserialize)]
pub struct DeclaredAnalysis {
    /// VEX state as declared, e.g. `not_affected`, `in_triage`, `exploitable`,
    /// `resolved`, `false_positive`. Kept as the raw string; interpretation is
    /// left to the reconciler so no state is silently dropped.
    #[serde(default)]
    pub state: Option<String>,
    /// The justification (e.g. `code_not_reachable`), when present.
    #[serde(default)]
    pub justification: Option<String>,
    /// Free-text detail, when present.
    #[serde(default)]
    pub detail: Option<String>,
}

/// A component reference within a vulnerability's `affects` list.
#[derive(Debug, Clone, Deserialize)]
pub struct DeclaredAffects {
    /// The `bom-ref` (or bare name) of the affected component.
    #[serde(rename = "ref", default)]
    pub bom_ref: Option<String>,
    /// The affected versions, when enumerated.
    #[serde(default)]
    pub versions: Vec<DeclaredVersion>,
}

/// A single version entry inside `affects[].versions`.
#[derive(Debug, Clone, Deserialize)]
pub struct DeclaredVersion {
    /// The exact version string, when present.
    #[serde(default)]
    pub version: Option<String>,
}

/// Errors from reading a declared CycloneDX document.
#[derive(Debug)]
pub enum IngestError {
    /// The bytes were not valid JSON, or not a CycloneDX-shaped object.
    Parse(String),
}

impl std::fmt::Display for IngestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Parse(m) => write!(f, "declared CycloneDX parse error: {m}"),
        }
    }
}

impl std::error::Error for IngestError {}

impl DeclaredBom {
    /// Parse a declared CycloneDX document from JSON bytes.
    ///
    /// Lenient by design: any CycloneDX spec version and unmodeled fields are
    /// tolerated; only `components` and `vulnerabilities` are read.
    ///
    /// # Errors
    /// Returns [`IngestError::Parse`] if the bytes are not a JSON object.
    pub fn from_json(bytes: &[u8]) -> Result<Self, IngestError> {
        serde_json::from_slice(bytes).map_err(|e| IngestError::Parse(e.to_string()))
    }

    /// Merge another declared document into this one (e.g. a separate SBOM file
    /// and VEX file for the same image). Components and vulnerabilities are
    /// concatenated; de-duplication is the reconciler's concern.
    pub fn merge(&mut self, other: DeclaredBom) {
        self.components.extend(other.components);
        self.vulnerabilities.extend(other.vulnerabilities);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An NGC-shaped VEX document (CycloneDX 1.4), trimmed from the documented
    /// example: `analysis.state` + `affects[].ref` + `versions`.
    const VEX: &str = r#"{
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "version": 1,
        "metadata": { "component": { "type": "container", "name": "pytorch:26.01-py3" } },
        "vulnerabilities": [
            {
                "bom-ref": "abc",
                "id": "GHSA-xm59-rqc7-hhvf",
                "analysis": { "state": "not_affected", "justification": "code_not_reachable", "detail": "linux only" },
                "affects": [ { "ref": "nbconvert", "versions": [ { "version": "7.16.6" } ] } ]
            }
        ],
        "$schema": "http://cyclonedx.org/schema/bom-1.4.schema.json"
    }"#;

    /// An NGC-shaped SBOM document with a couple of components.
    const SBOM: &str = r#"{
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "components": [
            { "type": "library", "bom-ref": "c1", "name": "cuda-cudart", "version": "12.4.127", "purl": "pkg:generic/cuda-cudart@12.4.127" },
            { "type": "library", "name": "libcublas", "version": "12.4.5.8" }
        ]
    }"#;

    #[test]
    fn parses_vex_analysis_and_affects() {
        let bom = DeclaredBom::from_json(VEX.as_bytes()).unwrap();
        assert_eq!(bom.vulnerabilities.len(), 1);
        let v = &bom.vulnerabilities[0];
        assert_eq!(v.id, "GHSA-xm59-rqc7-hhvf");
        let a = v.analysis.as_ref().unwrap();
        assert_eq!(a.state.as_deref(), Some("not_affected"));
        assert_eq!(a.justification.as_deref(), Some("code_not_reachable"));
        assert_eq!(v.affects[0].bom_ref.as_deref(), Some("nbconvert"));
        assert_eq!(v.affects[0].versions[0].version.as_deref(), Some("7.16.6"));
    }

    #[test]
    fn parses_sbom_components() {
        let bom = DeclaredBom::from_json(SBOM.as_bytes()).unwrap();
        assert_eq!(bom.components.len(), 2);
        assert_eq!(bom.components[0].name, "cuda-cudart");
        assert_eq!(bom.components[0].version.as_deref(), Some("12.4.127"));
        assert_eq!(bom.components[0].bom_ref.as_deref(), Some("c1"));
        assert_eq!(bom.components[1].version.as_deref(), Some("12.4.5.8"));
    }

    #[test]
    fn tolerates_unknown_fields_and_missing_lists() {
        // A document with neither list, plus unmodeled fields, parses to empty.
        let bom = DeclaredBom::from_json(br#"{ "bomFormat": "CycloneDX", "extra": {} }"#).unwrap();
        assert!(
            bom.components.is_empty(),
            "a document with no component list parses to empty"
        );
        assert!(
            bom.vulnerabilities.is_empty(),
            "a document with no vulnerability list parses to empty"
        );
    }

    #[test]
    fn rejects_non_json() {
        assert!(matches!(
            DeclaredBom::from_json(b"not json"),
            Err(IngestError::Parse(_))
        ));
    }

    #[test]
    fn merge_concatenates() {
        let mut a = DeclaredBom::from_json(SBOM.as_bytes()).unwrap();
        let b = DeclaredBom::from_json(VEX.as_bytes()).unwrap();
        a.merge(b);
        assert_eq!(a.components.len(), 2);
        assert_eq!(a.vulnerabilities.len(), 1);
    }
}
