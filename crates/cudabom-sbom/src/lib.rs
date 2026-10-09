//! SBOM and VEX integration for cudabom.
//!
//! Responsibility: emit standalone CycloneDX 1.6 SBOMs from cudabom findings.
//! Enriching an existing SBOM, the PEP 770 declared-SBOM reader, and VEX
//! generation build on this foundation and land with the advisory work.
//!
//! The emitter is deterministic: components are sorted, the serial number is
//! derived from the content, and the timestamp is caller-supplied (omitted for
//! reproducible output). Every CUDA-specific fact (confidence, evidence,
//! relationship) is carried as a namespaced CycloneDX property so it survives
//! in any downstream consumer.

mod cyclonedx;
mod ingest;

use cudabom_core::Finding;
use sha2::{Digest, Sha256};

pub use cyclonedx::{
    Affects, Analysis, Bom, Component, Dependency, Metadata, Property, Source, Tools, Vulnerability,
};
pub use ingest::{
    DeclaredAffects, DeclaredAnalysis, DeclaredBom, DeclaredComponent, DeclaredVersion,
    DeclaredVulnerability, IngestError,
};

/// Property namespace for cudabom-specific data in the SBOM.
const NS: &str = "cudabom";

/// `bom-ref` prefix for the scanned subject.
const SUBJECT_REF: &str = "cudabom:subject";

/// Findings borrowed and ordered by `id` for deterministic output.
fn sorted_findings(findings: &[Finding]) -> Vec<&Finding> {
    let mut sorted: Vec<&Finding> = findings.iter().collect();
    sorted.sort_by(|a, b| a.id.cmp(&b.id));
    sorted
}

/// The stable `bom-ref` for a finding's component.
fn finding_bom_ref(finding: &Finding) -> String {
    format!("cudabom:finding:{}", finding.id)
}

/// Options controlling SBOM emission.
#[derive(Debug, Clone, Default)]
pub struct SbomOptions {
    /// Name of the scanned artifact (becomes `metadata.component`).
    pub subject_name: Option<String>,
    /// sha256 of the scanned artifact, when it is a single file.
    pub subject_sha256: Option<String>,
    /// RFC 3339 timestamp. When `None`, the timestamp is omitted so the output
    /// is byte-for-byte reproducible.
    pub timestamp: Option<String>,
    /// The tool version to record in `metadata.tools`.
    pub tool_version: String,
}

/// Build a CycloneDX 1.6 BOM from cudabom findings.
#[must_use]
pub fn to_bom(findings: &[Finding], options: &SbomOptions) -> Bom {
    let subject_ref = SUBJECT_REF.to_string();

    // One component per finding, sorted by finding id for deterministic order.
    let sorted = sorted_findings(findings);

    let mut components = Vec::with_capacity(sorted.len());
    // Every embedded/static copy and every dependency edge the subject points
    // at. They are collected into one list because the final `Dependency` is
    // sorted anyway, so distinguishing the two edge kinds here would be moot.
    let mut all_deps = Vec::new();

    for finding in &sorted {
        let bom_ref = finding_bom_ref(finding);
        components.push(component_for(finding, &bom_ref));
        all_deps.push(bom_ref);
    }

    // The subject depends on everything it embeds or requires.
    all_deps.sort();
    let dependencies = if all_deps.is_empty() {
        Vec::new()
    } else {
        vec![cyclonedx::Dependency {
            bom_ref: subject_ref.clone(),
            depends_on: all_deps,
        }]
    };

    let subject = options.subject_name.as_ref().map(|name| {
        let mut properties = Vec::new();
        if let Some(sha) = &options.subject_sha256 {
            properties.push(prop("subject:sha256", sha));
        }
        cyclonedx::Component {
            component_type: "application",
            bom_ref: Some(subject_ref),
            name: name.clone(),
            version: None,
            purl: None,
            properties,
        }
    });

    let metadata = cyclonedx::Metadata {
        timestamp: options.timestamp.clone(),
        tools: cyclonedx::Tools {
            components: vec![cyclonedx::Component {
                component_type: "application",
                bom_ref: None,
                name: "cudabom".to_string(),
                version: Some(options.tool_version.clone()),
                purl: None,
                properties: Vec::new(),
            }],
        },
        component: subject,
    };

    let serial_number = derive_serial(&components);

    cyclonedx::Bom {
        bom_format: "CycloneDX",
        spec_version: "1.6",
        serial_number,
        version: 1,
        metadata,
        components,
        dependencies,
        vulnerabilities: Vec::new(),
    }
}

/// Serialize a BOM to pretty JSON.
///
/// # Errors
/// Returns an error only if serialization fails (should not happen for the
/// closed set of types here).
pub fn to_json(findings: &[Finding], options: &SbomOptions) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(&to_bom(findings, options))
}

/// A VEX-style advisory verdict for a finding, in neutral form. The SBOM crate
/// does not depend on `cudabom-advisory`; the caller maps advisory matches into
/// this shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VexVerdict {
    /// The vulnerability/advisory identifier (e.g. a CVE id).
    pub advisory_id: String,
    /// The component name the verdict concerns (matched to a finding).
    pub component: String,
    /// The verdict.
    pub state: VexState,
    /// A short justification, carried into `analysis.detail`.
    pub justification: String,
}

/// The VEX outcomes cudabom emits, mapped to CycloneDX `analysis.state`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VexState {
    /// The component version is within an affected range.
    Affected,
    /// The component version is outside all affected ranges.
    NotAffected,
    /// The available evidence cannot resolve applicability.
    UnderInvestigation,
}

impl VexState {
    /// The CycloneDX `analysis.state` token for this verdict.
    ///
    /// `affected` maps to `exploitable` (the version is in an affected range),
    /// `not_affected` to CycloneDX `not_affected`, and an unresolved verdict to
    /// `in_triage`.
    fn cyclonedx_state(self) -> &'static str {
        match self {
            Self::Affected => "exploitable",
            Self::NotAffected => "not_affected",
            Self::UnderInvestigation => "in_triage",
        }
    }
}

/// Build a CycloneDX 1.6 VEX document: the SBOM of findings plus a
/// `vulnerabilities` array carrying the advisory verdicts.
///
/// A verdict's `affects` references the bom-ref of the finding whose component
/// name matches; verdicts with no matching finding are still emitted (with an
/// empty `affects`) so a claim is never silently dropped.
#[must_use]
pub fn to_vex(findings: &[Finding], verdicts: &[VexVerdict], options: &SbomOptions) -> Bom {
    let mut bom = to_bom(findings, options);

    // Map component name -> the bom-refs of findings for that component, so a
    // verdict can point at the exact component entries.
    let mut refs_by_component: std::collections::BTreeMap<&str, Vec<String>> =
        std::collections::BTreeMap::new();
    let sorted = sorted_findings(findings);
    for finding in &sorted {
        let bom_ref = finding_bom_ref(finding);
        refs_by_component
            .entry(finding.component.name.as_str())
            .or_default()
            .push(bom_ref);
    }

    // Deterministic verdict order: advisory id, then component.
    let mut sorted_verdicts: Vec<&VexVerdict> = verdicts.iter().collect();
    sorted_verdicts.sort_by(|a, b| {
        a.advisory_id
            .cmp(&b.advisory_id)
            .then(a.component.cmp(&b.component))
    });

    let mut vulnerabilities = Vec::with_capacity(sorted_verdicts.len());
    for v in sorted_verdicts {
        let affects = refs_by_component
            .get(v.component.as_str())
            .into_iter()
            .flatten()
            .map(|bom_ref| cyclonedx::Affects {
                bom_ref: bom_ref.clone(),
            })
            .collect();
        vulnerabilities.push(cyclonedx::Vulnerability {
            id: v.advisory_id.clone(),
            source: Some(cyclonedx::Source {
                name: "NVIDIA".to_string(),
            }),
            analysis: cyclonedx::Analysis {
                state: v.state.cyclonedx_state(),
                detail: Some(v.justification.clone()),
            },
            affects,
        });
    }

    bom.vulnerabilities = vulnerabilities;
    bom
}

/// Serialize a VEX BOM to pretty JSON.
///
/// # Errors
/// Returns an error only if serialization fails.
pub fn to_vex_json(
    findings: &[Finding],
    verdicts: &[VexVerdict],
    options: &SbomOptions,
) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(&to_vex(findings, verdicts, options))
}

/// The result of enriching an existing CycloneDX document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrichOutcome {
    /// The enriched document, pretty-printed JSON.
    pub json: String,
    /// How many cudabom components were added.
    pub added: usize,
    /// How many findings were skipped because an equivalent component already
    /// existed in the input SBOM.
    pub skipped: usize,
}

/// Errors from enriching an existing SBOM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnrichError {
    /// The input was not valid JSON.
    Parse(String),
    /// The input JSON was not a CycloneDX-shaped object.
    NotCycloneDx(String),
    /// Serializing the enriched document failed.
    Serialize(String),
}

impl std::fmt::Display for EnrichError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Parse(m) => write!(f, "input SBOM is not valid JSON: {m}"),
            Self::NotCycloneDx(m) => write!(f, "input is not a CycloneDX document: {m}"),
            Self::Serialize(m) => write!(f, "cannot serialize enriched SBOM: {m}"),
        }
    }
}

impl std::error::Error for EnrichError {}

/// Enrich an existing CycloneDX SBOM (given as JSON bytes) with cudabom's
/// discovered components.
///
/// The input is parsed as generic JSON so that fields cudabom does not model are
/// preserved exactly. cudabom components are appended to `components[]`, each
/// carrying its namespaced facts as properties; a finding is skipped when the
/// input already contains a component with the same purl, or the same
/// name+version. cudabom is also added to `metadata.tools.components` so the
/// provenance of the additions is recorded.
///
/// # Errors
/// Returns [`EnrichError`] when the input is not valid JSON, is not a
/// CycloneDX object, or the result cannot be serialized.
pub fn enrich(
    input: &[u8],
    findings: &[Finding],
    tool_version: &str,
) -> Result<EnrichOutcome, EnrichError> {
    let mut doc: serde_json::Value =
        serde_json::from_slice(input).map_err(|e| EnrichError::Parse(e.to_string()))?;

    let obj = doc
        .as_object_mut()
        .ok_or_else(|| EnrichError::NotCycloneDx("top level is not a JSON object".to_string()))?;

    // Sanity-check it looks like CycloneDX; do not hard-fail on spec version so
    // we can enrich 1.4/1.5/1.6 documents.
    if obj.get("bomFormat").and_then(|v| v.as_str()) != Some("CycloneDX") {
        return Err(EnrichError::NotCycloneDx(
            "missing \"bomFormat\": \"CycloneDX\"".to_string(),
        ));
    }

    // Index existing components by purl and by name@version to avoid duplicates.
    let mut existing_purls = std::collections::BTreeSet::new();
    let mut existing_name_versions = std::collections::BTreeSet::new();
    if let Some(components) = obj.get("components").and_then(|v| v.as_array()) {
        for c in components {
            if let Some(purl) = c.get("purl").and_then(|v| v.as_str()) {
                existing_purls.insert(purl.to_string());
            }
            if let Some(name) = c.get("name").and_then(|v| v.as_str()) {
                let version = c.get("version").and_then(|v| v.as_str()).unwrap_or("");
                existing_name_versions.insert(format!("{name}@{version}"));
            }
        }
    }

    // Build cudabom components (sorted, deterministic), skipping duplicates.
    let sorted = sorted_findings(findings);

    let mut added = 0usize;
    let mut skipped = 0usize;
    let mut new_components = Vec::new();
    for finding in &sorted {
        let purl = purl_for(finding);
        let name = &finding.component.name;
        let version = finding.component.version.as_deref().unwrap_or("");
        let name_version = format!("{name}@{version}");

        let dup_by_purl = purl.as_ref().is_some_and(|p| existing_purls.contains(p));
        let dup_by_name = existing_name_versions.contains(&name_version);
        if dup_by_purl || dup_by_name {
            skipped += 1;
            continue;
        }

        let bom_ref = finding_bom_ref(finding);
        let component = component_for(finding, &bom_ref);
        new_components.push(
            serde_json::to_value(&component).map_err(|e| EnrichError::Serialize(e.to_string()))?,
        );
        added += 1;
    }

    // Append the new components.
    let components = obj
        .entry("components")
        .or_insert_with(|| serde_json::Value::Array(Vec::new()));
    if let Some(arr) = components.as_array_mut() {
        arr.extend(new_components);
    } else {
        return Err(EnrichError::NotCycloneDx(
            "\"components\" is present but not an array".to_string(),
        ));
    }

    // Record cudabom in metadata.tools.components (best-effort; only when the
    // metadata.tools.components array shape is present or absent, never
    // clobbering a differently-shaped tools value).
    record_tool(obj, tool_version);

    let json =
        serde_json::to_string_pretty(&doc).map_err(|e| EnrichError::Serialize(e.to_string()))?;
    Ok(EnrichOutcome {
        json,
        added,
        skipped,
    })
}

/// Add cudabom to `metadata.tools.components` if that array shape is in use (or
/// metadata/tools are absent). If `metadata.tools` uses a different, legacy
/// shape we do not recognize, we leave it untouched rather than corrupt it.
fn record_tool(obj: &mut serde_json::Map<String, serde_json::Value>, tool_version: &str) {
    use serde_json::Value;

    let tool_entry = serde_json::json!({
        "type": "application",
        "name": "cudabom",
        "version": tool_version,
    });

    let metadata = obj
        .entry("metadata")
        .or_insert_with(|| Value::Object(serde_json::Map::new()));
    let Some(metadata) = metadata.as_object_mut() else {
        return;
    };
    let tools = metadata
        .entry("tools")
        .or_insert_with(|| Value::Object(serde_json::Map::new()));
    let Some(tools) = tools.as_object_mut() else {
        // `tools` is present but not the object-with-components shape (e.g. the
        // deprecated array-of-tools form): do not modify it.
        return;
    };
    let components = tools
        .entry("components")
        .or_insert_with(|| Value::Array(Vec::new()));
    if let Some(arr) = components.as_array_mut() {
        // Avoid adding cudabom twice on repeated enrichment.
        let already = arr
            .iter()
            .any(|c| c.get("name").and_then(|v| v.as_str()) == Some("cudabom"));
        if !already {
            arr.push(tool_entry);
        }
    }
}

/// Map one finding to a CycloneDX component with cudabom facts as properties.
fn component_for(finding: &Finding, bom_ref: &str) -> cyclonedx::Component {
    let mut properties = vec![
        prop("confidence", finding.confidence.as_str()),
        prop("relationship", finding.component.relationship.as_str()),
        prop("findingId", &finding.id),
    ];

    // The originating file (from the first evidence item's location), so every
    // SBOM component traces back to the binary it was found in: the SBOM-side
    // of the per-binary composition view.
    if let Some(ev) = finding.evidence.first() {
        properties.push(prop("sourceFile", &ev.location.path));
    }

    // Each evidence item as a property, so the support is visible in the SBOM.
    for (i, ev) in finding.evidence.iter().enumerate() {
        properties.push(prop(
            &format!("evidence.{i}"),
            &format!("{}: {}", ev.kind.as_str(), ev.detail),
        ));
    }
    for (i, conflict) in finding.conflicts.iter().enumerate() {
        properties.push(prop(&format!("conflict.{i}"), conflict));
    }

    cyclonedx::Component {
        component_type: "library",
        bom_ref: Some(bom_ref.to_string()),
        name: finding.component.name.clone(),
        version: finding.component.version.clone(),
        purl: purl_for(finding),
        properties,
    }
}

/// Derive a package URL for a CUDA component when the version is known.
///
/// Uses the `generic` purl type namespaced to `nvidia`, since CUDA libraries
/// are not published to a package registry with a canonical purl type. When the
/// version is unknown, no purl is emitted (a versionless purl would be
/// misleading).
fn purl_for(finding: &Finding) -> Option<String> {
    let version = finding.component.version.as_ref()?;
    Some(format!(
        "pkg:generic/nvidia/{}@{}",
        finding.component.name, version
    ))
}

/// Derive a deterministic RFC 4122 urn:uuid serial number from the components.
///
/// The SBOM must be reproducible, so the serial is a function of its content
/// rather than random. We hash the component names+versions and format the
/// digest as a v4-shaped UUID urn (the version/variant nibbles are set so the
/// string is a well-formed UUID, even though it is content-derived).
fn derive_serial(components: &[cyclonedx::Component]) -> String {
    let mut hasher = Sha256::new();
    for c in components {
        hasher.update(c.name.as_bytes());
        hasher.update([0]);
        if let Some(v) = &c.version {
            hasher.update(v.as_bytes());
        }
        hasher.update([0]);
    }
    let digest = hasher.finalize();
    let b = &digest[..16];
    // Format as UUID, forcing version 4 and RFC 4122 variant bits.
    let uuid = format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-4{:x}{:02x}-{:x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0], b[1], b[2], b[3],
        b[4], b[5],
        b[6] & 0x0f, b[7],
        (b[8] & 0x3f) | 0x80, b[9],
        b[10], b[11], b[12], b[13], b[14], b[15],
    );
    format!("urn:uuid:{uuid}")
}

fn prop(name: &str, value: &str) -> cyclonedx::Property {
    cyclonedx::Property {
        name: format!("{NS}:{name}"),
        value: value.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cudabom_core::{Component, Confidence, Evidence, EvidenceKind, Location, Relationship};

    fn finding(name: &str, version: Option<&str>, rel: Relationship, conf: Confidence) -> Finding {
        Finding {
            id: format!("path::{name}"),
            component: Component {
                name: name.to_string(),
                version: version.map(ToString::to_string),
                candidate_versions: Vec::new(),
                relationship: rel,
            },
            confidence: conf,
            evidence: vec![Evidence {
                kind: EvidenceKind::Soname,
                location: Location {
                    path: "lib/libcudart.so.12".to_string(),
                    sha256: None,
                    layer_digest: None,
                },
                detail: "libcudart.so.12".to_string(),
            }],
            conflicts: Vec::new(),
        }
    }

    fn opts() -> SbomOptions {
        SbomOptions {
            subject_name: Some("wheel.whl".to_string()),
            subject_sha256: Some("deadbeef".to_string()),
            timestamp: None,
            tool_version: "0.0.0".to_string(),
        }
    }

    #[test]
    fn emits_valid_shape() {
        let findings = vec![finding(
            "cudart",
            Some("12.4.1"),
            Relationship::EmbeddedCopy,
            Confidence::Exact,
        )];
        let bom = to_bom(&findings, &opts());
        assert_eq!(bom.bom_format, "CycloneDX");
        assert_eq!(bom.spec_version, "1.6");
        assert_eq!(bom.version, 1);
        assert!(bom.serial_number.starts_with("urn:uuid:"));
        assert_eq!(bom.components.len(), 1);
        assert_eq!(bom.components[0].name, "cudart");
        assert_eq!(
            bom.components[0].purl.as_deref(),
            Some("pkg:generic/nvidia/cudart@12.4.1")
        );
        // The subject depends on the embedded component.
        assert_eq!(bom.dependencies.len(), 1);
        assert_eq!(bom.dependencies[0].depends_on.len(), 1);
    }

    #[test]
    fn json_is_deterministic() {
        let findings = vec![
            finding(
                "cublas",
                Some("12.x"),
                Relationship::DynamicDependency,
                Confidence::Unknown,
            ),
            finding(
                "cudart",
                Some("12.4.1"),
                Relationship::EmbeddedCopy,
                Confidence::Exact,
            ),
        ];
        let a = to_json(&findings, &opts()).unwrap();
        let b = to_json(&findings, &opts()).unwrap();
        assert_eq!(a, b);
        // Reordering the input does not change the output (sorted internally).
        let mut rev = findings.clone();
        rev.reverse();
        let c = to_json(&rev, &opts()).unwrap();
        assert_eq!(a, c);
    }

    #[test]
    fn versionless_component_has_no_purl() {
        let findings = vec![finding(
            "cudnn",
            None,
            Relationship::DynamicDependency,
            Confidence::Unknown,
        )];
        let bom = to_bom(&findings, &opts());
        assert!(bom.components[0].purl.is_none());
    }

    #[test]
    fn confidence_and_relationship_are_properties() {
        let findings = vec![finding(
            "cudart",
            Some("12.4.1"),
            Relationship::EmbeddedCopy,
            Confidence::Exact,
        )];
        let bom = to_bom(&findings, &opts());
        let props = &bom.components[0].properties;
        assert!(props
            .iter()
            .any(|p| p.name == "cudabom:confidence" && p.value == "exact"));
        assert!(props
            .iter()
            .any(|p| p.name == "cudabom:relationship" && p.value == "embedded-copy"));
        assert!(props
            .iter()
            .any(|p| p.name.starts_with("cudabom:evidence.")));
    }

    #[test]
    fn empty_findings_produce_minimal_valid_bom() {
        let bom = to_bom(&[], &opts());
        assert!(
            bom.components.is_empty(),
            "no findings => no components in the BOM"
        );
        assert!(
            bom.dependencies.is_empty(),
            "no findings => no dependencies in the BOM"
        );
        // Still a valid, serializable document.
        assert!(to_json(&[], &opts()).is_ok());
    }

    fn verdict(advisory: &str, component: &str, state: VexState) -> VexVerdict {
        VexVerdict {
            advisory_id: advisory.to_string(),
            component: component.to_string(),
            state,
            justification: "test".to_string(),
        }
    }

    #[test]
    fn vex_emits_vulnerabilities_pointing_at_components() {
        let findings = vec![finding(
            "cudart",
            Some("12.3"),
            Relationship::EmbeddedCopy,
            Confidence::Exact,
        )];
        let verdicts = vec![verdict("CVE-2025-0001", "cudart", VexState::Affected)];
        let bom = to_vex(&findings, &verdicts, &opts());

        assert_eq!(bom.vulnerabilities.len(), 1);
        let vuln = &bom.vulnerabilities[0];
        assert_eq!(vuln.id, "CVE-2025-0001");
        assert_eq!(vuln.analysis.state, "exploitable");
        assert_eq!(vuln.source.as_ref().unwrap().name, "NVIDIA");
        // The affects ref matches the finding's component bom-ref.
        assert_eq!(vuln.affects.len(), 1);
        assert_eq!(vuln.affects[0].bom_ref, "cudabom:finding:path::cudart");
    }

    #[test]
    fn vex_states_map_correctly() {
        let findings = vec![finding(
            "cudart",
            Some("12.5"),
            Relationship::EmbeddedCopy,
            Confidence::Exact,
        )];
        for (state, expected) in [
            (VexState::Affected, "exploitable"),
            (VexState::NotAffected, "not_affected"),
            (VexState::UnderInvestigation, "in_triage"),
        ] {
            let verdicts = vec![verdict("CVE-1", "cudart", state)];
            let bom = to_vex(&findings, &verdicts, &opts());
            assert_eq!(bom.vulnerabilities[0].analysis.state, expected);
        }
    }

    #[test]
    fn vex_verdict_without_matching_finding_is_still_emitted() {
        // A verdict for a component we did not find still produces a statement,
        // with an empty `affects`: never silently dropped.
        let findings = vec![finding(
            "cudart",
            Some("12.3"),
            Relationship::EmbeddedCopy,
            Confidence::Exact,
        )];
        let verdicts = vec![verdict("CVE-9", "cudnn", VexState::UnderInvestigation)];
        let bom = to_vex(&findings, &verdicts, &opts());
        assert_eq!(bom.vulnerabilities.len(), 1);
        assert!(
            bom.vulnerabilities[0].affects.is_empty(),
            "a vulnerability with no affected refs has an empty affects list"
        );
    }

    #[test]
    fn vex_json_is_deterministic_and_sorted() {
        let findings = vec![finding(
            "cudart",
            Some("12.3"),
            Relationship::EmbeddedCopy,
            Confidence::Exact,
        )];
        let verdicts = vec![
            verdict("CVE-B", "cudart", VexState::Affected),
            verdict("CVE-A", "cudart", VexState::NotAffected),
        ];
        let a = to_vex_json(&findings, &verdicts, &opts()).unwrap();
        let b = to_vex_json(&findings, &verdicts, &opts()).unwrap();
        assert_eq!(a, b);
        let bom = to_vex(&findings, &verdicts, &opts());
        // Sorted by advisory id: CVE-A before CVE-B.
        assert_eq!(bom.vulnerabilities[0].id, "CVE-A");
        assert_eq!(bom.vulnerabilities[1].id, "CVE-B");
    }

    #[test]
    fn plain_sbom_has_no_vulnerabilities_field() {
        let findings = vec![finding(
            "cudart",
            Some("12.3"),
            Relationship::EmbeddedCopy,
            Confidence::Exact,
        )];
        let json = to_json(&findings, &opts()).unwrap();
        // `vulnerabilities` is omitted when empty.
        assert!(!json.contains("vulnerabilities"));
    }

    #[test]
    fn enrich_adds_new_components_and_records_tool() {
        let input = r#"{
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "components": [
                { "type": "library", "name": "numpy", "version": "1.26.0" }
            ]
        }"#;
        let findings = vec![finding(
            "cudart",
            Some("12.4.1"),
            Relationship::EmbeddedCopy,
            Confidence::Exact,
        )];
        let outcome = enrich(input.as_bytes(), &findings, "0.1.0").unwrap();
        assert_eq!(outcome.added, 1);
        assert_eq!(outcome.skipped, 0);

        let doc: serde_json::Value = serde_json::from_str(&outcome.json).unwrap();
        let components = doc["components"].as_array().unwrap();
        // Original numpy + added cudart.
        assert_eq!(components.len(), 2);
        assert!(components.iter().any(|c| c["name"] == "cudart"));
        // Preserved the original.
        assert!(components.iter().any(|c| c["name"] == "numpy"));
        // cudabom recorded as a tool.
        let tools = doc["metadata"]["tools"]["components"].as_array().unwrap();
        assert!(tools.iter().any(|t| t["name"] == "cudabom"));
    }

    #[test]
    fn enrich_skips_duplicate_by_purl() {
        let input = r#"{
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1,
            "components": [
                { "type": "library", "name": "cudart", "version": "12.4.1", "purl": "pkg:generic/nvidia/cudart@12.4.1" }
            ]
        }"#;
        let findings = vec![finding(
            "cudart",
            Some("12.4.1"),
            Relationship::EmbeddedCopy,
            Confidence::Exact,
        )];
        let outcome = enrich(input.as_bytes(), &findings, "0.1.0").unwrap();
        assert_eq!(outcome.added, 0);
        assert_eq!(outcome.skipped, 1);
        let doc: serde_json::Value = serde_json::from_str(&outcome.json).unwrap();
        assert_eq!(doc["components"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn enrich_preserves_unknown_fields() {
        let input = r#"{
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 3,
            "serialNumber": "urn:uuid:11111111-1111-4111-8111-111111111111",
            "customField": { "keep": "me" },
            "components": []
        }"#;
        let outcome = enrich(input.as_bytes(), &[], "0.1.0").unwrap();
        let doc: serde_json::Value = serde_json::from_str(&outcome.json).unwrap();
        // Unknown field and existing serial number are preserved.
        assert_eq!(doc["customField"]["keep"], "me");
        assert_eq!(
            doc["serialNumber"],
            "urn:uuid:11111111-1111-4111-8111-111111111111"
        );
        assert_eq!(doc["version"], 3);
    }

    #[test]
    fn enrich_rejects_non_cyclonedx() {
        let input = r#"{ "hello": "world" }"#;
        assert!(matches!(
            enrich(input.as_bytes(), &[], "0.1.0"),
            Err(EnrichError::NotCycloneDx(_))
        ));
    }

    #[test]
    fn enrich_rejects_invalid_json() {
        assert!(matches!(
            enrich(b"not json", &[], "0.1.0"),
            Err(EnrichError::Parse(_))
        ));
    }

    #[test]
    fn enrich_does_not_clobber_legacy_tools_array() {
        // metadata.tools as the deprecated array-of-tools form: leave untouched.
        let input = r#"{
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "version": 1,
            "metadata": { "tools": [ { "name": "syft" } ] },
            "components": []
        }"#;
        let findings = vec![finding(
            "cudart",
            Some("12.4.1"),
            Relationship::EmbeddedCopy,
            Confidence::Exact,
        )];
        let outcome = enrich(input.as_bytes(), &findings, "0.1.0").unwrap();
        let doc: serde_json::Value = serde_json::from_str(&outcome.json).unwrap();
        // The component was still added.
        assert_eq!(outcome.added, 1);
        // The legacy tools array is unchanged (still an array with just syft).
        let tools = doc["metadata"]["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0]["name"], "syft");
    }
}
