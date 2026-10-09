//! SARIF 2.1.0 rendering.
//!
//! Emits a SARIF log that code-scanning tooling (GitHub, etc.) can ingest. The
//! structure follows the OASIS SARIF 2.1.0 schema: a single `run` whose
//! `tool.driver` declares the rules, and a `results` array mapping findings and
//! advisory verdicts to those rules.
//!
//! Rule design:
//! - One rule per identification confidence (`cudabom/identified/exact`,
//!   `.../likely`, `.../unknown`) so results are groupable.
//! - One rule per advisory verdict (`cudabom/advisory/affected`,
//!   `.../not-affected`, `.../under-investigation`).
//!
//! Severity mapping (SARIF `level`): an `affected` advisory verdict is
//! `error`; an `under_investigation` verdict and an `Exact`/`Likely`
//! identification are `warning`; everything else is `note`. cudabom does not
//! itself assign CVSS; `level` reflects actionability, not intrinsic severity.

use serde::Serialize;

use crate::input::{Report, Verdict};

/// The SARIF schema URL and version this renderer targets.
const SARIF_SCHEMA: &str =
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json";
const SARIF_VERSION: &str = "2.1.0";
/// The SARIF driver name. Single-sourced from the shared tool identity.
const TOOL_NAME: &str = cudabom_core::TOOL_NAME;
/// The tool's information URI, taken from the crate's `repository` field (the
/// single `[workspace.package] repository` in `Cargo.toml`) so it cannot drift.
const INFORMATION_URI: &str = env!("CARGO_PKG_REPOSITORY");

/// Render the report as a pretty-printed SARIF 2.1.0 log.
///
/// # Errors
/// Returns an error only if serialization fails, which does not happen for
/// these owned, plain data structures.
pub(crate) fn render(report: &Report<'_>) -> Result<String, serde_json::Error> {
    let log = build_log(report);
    serde_json::to_string_pretty(&log)
}

fn build_log(report: &Report<'_>) -> SarifLog {
    let mut results = Vec::new();

    for finding in report.findings {
        results.push(finding_result(finding));
    }
    if let Some(verdicts) = report.advisories {
        for v in verdicts {
            results.push(advisory_result(v));
        }
    }

    SarifLog {
        schema: SARIF_SCHEMA,
        version: SARIF_VERSION,
        runs: vec![Run {
            tool: Tool {
                driver: Driver {
                    name: TOOL_NAME,
                    version: report.tool_version.to_string(),
                    information_uri: INFORMATION_URI,
                    rules: all_rules(),
                },
            },
            results,
        }],
    }
}

/// The fixed rule catalogue. Kept stable so result `ruleId`s are meaningful.
fn all_rules() -> Vec<ReportingDescriptor> {
    vec![
        rule(
            RULE_IDENTIFIED_EXACT,
            "CUDA component identified (exact)",
            "A CUDA component was identified with exact confidence (known hash, build-id, or two agreeing strong signals).",
        ),
        rule(
            RULE_IDENTIFIED_LIKELY,
            "CUDA component identified (likely)",
            "A CUDA component was identified with likely confidence (well-supported identity, version incomplete or a range).",
        ),
        rule(
            RULE_IDENTIFIED_UNKNOWN,
            "CUDA-related signal (unidentified)",
            "CUDA-related signals were observed but the component identity could not be established.",
        ),
        rule(
            RULE_ADVISORY_AFFECTED,
            "Component affected by advisory",
            "An identified component's version falls within an advisory's affected range.",
        ),
        rule(
            RULE_ADVISORY_NOT_AFFECTED,
            "Component not affected by advisory",
            "An identified component's version is outside an advisory's affected range.",
        ),
        rule(
            RULE_ADVISORY_UNDER_INVESTIGATION,
            "Advisory applicability under investigation",
            "An advisory names the component but the available version evidence cannot resolve applicability.",
        ),
    ]
}

const RULE_IDENTIFIED_EXACT: &str = "cudabom/identified/exact";
const RULE_IDENTIFIED_LIKELY: &str = "cudabom/identified/likely";
const RULE_IDENTIFIED_UNKNOWN: &str = "cudabom/identified/unknown";
const RULE_ADVISORY_AFFECTED: &str = "cudabom/advisory/affected";
const RULE_ADVISORY_NOT_AFFECTED: &str = "cudabom/advisory/not-affected";
const RULE_ADVISORY_UNDER_INVESTIGATION: &str = "cudabom/advisory/under-investigation";

fn finding_result(finding: &cudabom_core::Finding) -> SarifResult {
    use cudabom_core::Confidence;
    let (rule_id, level) = match finding.confidence {
        Confidence::Exact => (RULE_IDENTIFIED_EXACT, "warning"),
        Confidence::Likely => (RULE_IDENTIFIED_LIKELY, "warning"),
        Confidence::Unknown => (RULE_IDENTIFIED_UNKNOWN, "note"),
    };

    let version = finding.component.version.as_deref().unwrap_or("unknown");
    let text = format!(
        "{} {} identified ({}, {}) from {} evidence item(s)",
        finding.component.name,
        version,
        finding.confidence.as_str(),
        finding.component.relationship.as_str(),
        finding.evidence.len(),
    );

    // Use the first evidence location as the result's physical location, if any.
    let location = finding
        .evidence
        .first()
        .map(|e| e.location.path.clone())
        .map(physical_location);

    SarifResult {
        rule_id: rule_id.to_string(),
        level: level.to_string(),
        message: Message { text },
        locations: location.into_iter().collect(),
        help_uri: None,
        properties: Some(ResultProperties {
            confidence: Some(finding.confidence.as_str().to_string()),
            component: Some(finding.component.name.clone()),
            version: finding.component.version.clone(),
            advisory_id: None,
            justification: None,
            references: Vec::new(),
        }),
    }
}

fn advisory_result(v: &crate::input::AdvisoryVerdict) -> SarifResult {
    let (rule_id, level) = match v.verdict {
        Verdict::Affected => (RULE_ADVISORY_AFFECTED, "error"),
        Verdict::NotAffected => (RULE_ADVISORY_NOT_AFFECTED, "note"),
        Verdict::UnderInvestigation => (RULE_ADVISORY_UNDER_INVESTIGATION, "warning"),
    };
    let text = format!(
        "{}: {} is {}: {}",
        v.advisory_id,
        v.component,
        v.verdict.as_str(),
        v.justification,
    );
    SarifResult {
        rule_id: rule_id.to_string(),
        level: level.to_string(),
        message: Message { text },
        locations: Vec::new(),
        help_uri: v.references.first().cloned(),
        properties: Some(ResultProperties {
            confidence: None,
            component: Some(v.component.clone()),
            version: None,
            advisory_id: Some(v.advisory_id.clone()),
            justification: Some(v.justification.clone()),
            references: v.references.clone(),
        }),
    }
}

fn physical_location(path: String) -> SarifLocation {
    SarifLocation {
        physical_location: PhysicalLocation {
            artifact_location: ArtifactLocation { uri: path },
        },
    }
}

fn rule(id: &str, name: &str, description: &str) -> ReportingDescriptor {
    ReportingDescriptor {
        id: id.to_string(),
        name: name.to_string(),
        short_description: Message {
            text: description.to_string(),
        },
    }
}

// --- SARIF serde model (subset of the 2.1.0 schema) ---------------------------

#[derive(Serialize)]
struct SarifLog {
    #[serde(rename = "$schema")]
    schema: &'static str,
    version: &'static str,
    runs: Vec<Run>,
}

#[derive(Serialize)]
struct Run {
    tool: Tool,
    results: Vec<SarifResult>,
}

#[derive(Serialize)]
struct Tool {
    driver: Driver,
}

#[derive(Serialize)]
struct Driver {
    name: &'static str,
    version: String,
    #[serde(rename = "informationUri")]
    information_uri: &'static str,
    rules: Vec<ReportingDescriptor>,
}

#[derive(Serialize)]
struct ReportingDescriptor {
    id: String,
    name: String,
    #[serde(rename = "shortDescription")]
    short_description: Message,
}

#[derive(Serialize)]
struct SarifResult {
    #[serde(rename = "ruleId")]
    rule_id: String,
    level: String,
    message: Message,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    locations: Vec<SarifLocation>,
    #[serde(rename = "helpUri", skip_serializing_if = "Option::is_none")]
    help_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    properties: Option<ResultProperties>,
}

#[derive(Serialize)]
struct Message {
    text: String,
}

#[derive(Serialize)]
struct SarifLocation {
    #[serde(rename = "physicalLocation")]
    physical_location: PhysicalLocation,
}

#[derive(Serialize)]
struct PhysicalLocation {
    #[serde(rename = "artifactLocation")]
    artifact_location: ArtifactLocation,
}

#[derive(Serialize)]
struct ArtifactLocation {
    uri: String,
}

#[derive(Serialize)]
struct ResultProperties {
    #[serde(skip_serializing_if = "Option::is_none")]
    confidence: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    component: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
    #[serde(rename = "advisoryId", skip_serializing_if = "Option::is_none")]
    advisory_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    justification: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    references: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::input::AdvisoryVerdict;
    use cudabom_core::{
        Component, Confidence, Evidence, EvidenceKind, Finding, Location, Relationship,
    };

    fn finding(name: &str, version: Option<&str>, conf: Confidence, path: &str) -> Finding {
        Finding {
            id: format!("f::{name}"),
            component: Component {
                name: name.to_string(),
                version: version.map(ToString::to_string),
                candidate_versions: Vec::new(),
                relationship: Relationship::EmbeddedCopy,
            },
            confidence: conf,
            evidence: vec![Evidence {
                kind: EvidenceKind::Soname,
                location: Location {
                    path: path.to_string(),
                    sha256: None,
                    layer_digest: None,
                },
                detail: "libcudart.so.12".to_string(),
            }],
            conflicts: Vec::new(),
        }
    }

    #[test]
    fn emits_valid_sarif_shell() {
        let findings = vec![finding(
            "cudart",
            Some("12.4.1"),
            Confidence::Exact,
            "lib/libcudart.so.12",
        )];
        let report = Report {
            targets: &["wheel.whl".to_string()],
            findings: &findings,
            advisories: None,
            tool_version: "0.1.0",
        };
        let out = render(&report).unwrap();
        let json: serde_json::Value = serde_json::from_str(&out).unwrap();

        assert_eq!(json["version"], "2.1.0");
        assert!(json["$schema"]
            .as_str()
            .unwrap()
            .contains("sarif-schema-2.1.0"));
        let run = &json["runs"][0];
        assert_eq!(run["tool"]["driver"]["name"], "cudabom");
        assert_eq!(run["tool"]["driver"]["version"], "0.1.0");
        // Six rules are always declared.
        assert_eq!(run["tool"]["driver"]["rules"].as_array().unwrap().len(), 6);

        let result = &run["results"][0];
        assert_eq!(result["ruleId"], "cudabom/identified/exact");
        assert_eq!(result["level"], "warning");
        assert_eq!(
            result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "lib/libcudart.so.12"
        );
        assert_eq!(result["properties"]["version"], "12.4.1");
    }

    #[test]
    fn affected_advisory_is_error_level() {
        let findings = vec![finding(
            "cudart",
            Some("12.3"),
            Confidence::Exact,
            "lib/libcudart.so.12",
        )];
        let verdicts = vec![AdvisoryVerdict {
            advisory_id: "CVE-2025-0001".to_string(),
            component: "cudart".to_string(),
            verdict: Verdict::Affected,
            justification: "exact version within an affected range".to_string(),
            severity: Some("HIGH".to_string()),
            cvss_score: Some(7.5),
            published: Some("2025-01-15".to_string()),
            via_toolkit_release: None,
            description: Some("A flaw in cudart.".to_string()),
            references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2025-0001".to_string()],
        }];
        let report = Report {
            targets: &["wheel.whl".to_string()],
            findings: &findings,
            advisories: Some(&verdicts),
            tool_version: "0.1.0",
        };
        let out = render(&report).unwrap();
        let json: serde_json::Value = serde_json::from_str(&out).unwrap();
        let results = json["runs"][0]["results"].as_array().unwrap();
        // Finding result + advisory result.
        assert_eq!(results.len(), 2);
        let advisory = &results[1];
        assert_eq!(advisory["ruleId"], "cudabom/advisory/affected");
        assert_eq!(advisory["level"], "error");
        assert_eq!(advisory["properties"]["advisoryId"], "CVE-2025-0001");
        assert_eq!(
            advisory["helpUri"],
            "https://nvd.nist.gov/vuln/detail/CVE-2025-0001"
        );
        assert_eq!(
            advisory["properties"]["references"][0],
            "https://nvd.nist.gov/vuln/detail/CVE-2025-0001"
        );
    }

    #[test]
    fn unknown_confidence_is_note_and_has_no_location_when_no_evidence() {
        let mut f = finding("cudart", None, Confidence::Unknown, "x");
        f.evidence.clear();
        let findings = vec![f];
        let report = Report {
            targets: &[],
            findings: &findings,
            advisories: None,
            tool_version: "0.1.0",
        };
        let out = render(&report).unwrap();
        let json: serde_json::Value = serde_json::from_str(&out).unwrap();
        let result = &json["runs"][0]["results"][0];
        assert_eq!(result["level"], "note");
        // No evidence -> no locations array serialized.
        assert!(result.get("locations").is_none());
    }
}
