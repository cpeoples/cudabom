//! CycloneDX 1.6 document types (the subset cudabom emits).
//!
//! These mirror the CycloneDX 1.6 JSON schema field names exactly (via serde
//! rename where needed) so the output validates against the published schema.
//! Only the fields cudabom populates are modeled; optional fields we do not set
//! are omitted rather than emitted as null, keeping the document clean.
//!
//! Reference: CycloneDX 1.6 JSON schema (`bom-1.6.schema.json`).

use serde::Serialize;

/// The top-level CycloneDX BOM document.
#[derive(Debug, Clone, Serialize)]
pub struct Bom {
    #[serde(rename = "bomFormat")]
    pub bom_format: &'static str,
    #[serde(rename = "specVersion")]
    pub spec_version: &'static str,
    #[serde(rename = "serialNumber")]
    pub serial_number: String,
    pub version: u32,
    pub metadata: Metadata,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub components: Vec<Component>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub dependencies: Vec<Dependency>,
    /// VEX vulnerabilities, when emitting a VEX document. Omitted for a plain
    /// SBOM.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub vulnerabilities: Vec<Vulnerability>,
}

/// A CycloneDX vulnerability entry (used for VEX).
#[derive(Debug, Clone, Serialize)]
pub struct Vulnerability {
    /// The vulnerability identifier (e.g. a CVE id).
    pub id: String,
    /// Where the identifier comes from.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<Source>,
    /// The impact analysis (VEX state and justification).
    pub analysis: Analysis,
    /// The components this statement is about.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub affects: Vec<Affects>,
}

/// A vulnerability source.
#[derive(Debug, Clone, Serialize)]
pub struct Source {
    pub name: String,
}

/// CycloneDX vulnerability impact analysis.
#[derive(Debug, Clone, Serialize)]
pub struct Analysis {
    /// VEX state: `exploitable`, `not_affected`, `in_triage`, `resolved`, etc.
    pub state: &'static str,
    /// Free-text detail explaining the state.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// The components a vulnerability statement affects.
#[derive(Debug, Clone, Serialize)]
pub struct Affects {
    /// bom-ref of the affected component.
    #[serde(rename = "ref")]
    pub bom_ref: String,
}

/// BOM metadata: when it was produced, by what tool, and what it describes.
#[derive(Debug, Clone, Serialize)]
pub struct Metadata {
    /// RFC 3339 timestamp. Optional so output can be made reproducible.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
    pub tools: Tools,
    /// The artifact this BOM describes (the scan target).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub component: Option<Component>,
}

/// The `metadata.tools` object (CycloneDX 1.5+ shape with `components`).
#[derive(Debug, Clone, Serialize)]
pub struct Tools {
    pub components: Vec<Component>,
}

/// A CycloneDX component.
#[derive(Debug, Clone, Serialize)]
pub struct Component {
    /// Component type: cudabom emits `library` for CUDA components and
    /// `application` for the scanned artifact and the tool.
    #[serde(rename = "type")]
    pub component_type: &'static str,
    /// Stable reference used by the `dependencies` graph.
    #[serde(rename = "bom-ref", skip_serializing_if = "Option::is_none")]
    pub bom_ref: Option<String>,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Package URL, when one can be derived.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purl: Option<String>,
    /// cudabom-specific facts (confidence, evidence, relationship) carried as
    /// namespaced properties so they survive in any CycloneDX consumer.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub properties: Vec<Property>,
}

/// A CycloneDX name/value property.
#[derive(Debug, Clone, Serialize)]
pub struct Property {
    pub name: String,
    pub value: String,
}

/// A dependency edge: `ref` depends on each entry in `dependsOn`.
#[derive(Debug, Clone, Serialize)]
pub struct Dependency {
    #[serde(rename = "ref")]
    pub bom_ref: String,
    #[serde(rename = "dependsOn", skip_serializing_if = "Vec::is_empty")]
    pub depends_on: Vec<String>,
}
