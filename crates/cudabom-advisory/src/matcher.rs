//! Advisory matching: findings + advisory index -> verdicts.
//!
//! Implements the matching rules from `docs/advisories.md`:
//!
//! - **EXACT** version -> `Affected` or `NotAffected` per the ranges.
//! - **LIKELY** with a major-only range (`12.x`) -> a definitive verdict only
//!   when the *entire* major series is on one side of the boundary; otherwise
//!   `UnderInvestigation`.
//! - **UNKNOWN** version -> no claim (`UnderInvestigation` when the component
//!   name matches an advisory, so the user knows to look; never `Affected`).
//!
//! `NotAffected` is emitted only when positively supported (an EXACT version in
//! a fixed range, or an entire-major exclusion). Absence of any advisory match
//! is *not* returned as `NotAffected`; it produces no verdict at all, so the
//! caller can print the "absence is not proof of safety" caveat.

use cudabom_core::{Confidence, Finding};

use crate::index::{AdvisoryIndex, AffectedComponent, SerdeRange};
use crate::version::Version;

/// The VEX-style verdict for one (finding, advisory) pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// The component version falls in an affected range.
    Affected,
    /// The component version is positively shown to be fixed / not affected.
    NotAffected,
    /// The component matches the advisory but the version evidence cannot
    /// resolve the verdict either way.
    UnderInvestigation,
}

impl Verdict {
    /// The stable lowercase token for this verdict (`affected`,
    /// `not_affected`, `under_investigation`).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Affected => "affected",
            Self::NotAffected => "not_affected",
            Self::UnderInvestigation => "under_investigation",
        }
    }
}

/// A matched advisory for a finding, with the reasoned verdict.
#[derive(Debug, Clone, PartialEq)]
pub struct Match {
    /// The advisory id.
    pub advisory_id: String,
    /// The component the verdict is about.
    pub component: String,
    /// The verdict.
    pub verdict: Verdict,
    /// A short justification string for explainability.
    pub justification: String,
    /// Published severity (free text, e.g. `critical`), copied from the
    /// advisory for convenient reporting. `None` when the advisory carried none.
    pub severity: Option<String>,
    /// CVSS base score (0.0-10.0) copied from the advisory. `None` when absent.
    pub cvss_score: Option<f64>,
    /// Publication date copied from the advisory (CSAF
    /// `initial_release_date`). `None` when absent.
    pub published: Option<String>,
    /// A longer human-readable description of the vulnerability, copied from the
    /// advisory (CSAF notes). `None` when the bulletin carried none. Used to
    /// give a report reader context beyond the bare CVE id.
    pub description: Option<String>,
    /// When the match was reached indirectly (because the scanned library
    /// shipped in this CUDA toolkit release, and the advisory is keyed to the
    /// toolkit rather than the individual library) this records that release
    /// label (e.g. `12.4.1`). `None` for a direct component match.
    pub via_toolkit_release: Option<String>,
    /// Reference URLs copied from the advisory (NVIDIA bulletin pages, the
    /// canonical NVD page for a CVE id, etc.), for linking in reports. Empty
    /// when the advisory carried none.
    pub references: Vec<String>,
}

/// Match one finding against the whole index, returning every relevant verdict.
#[must_use]
pub fn match_finding(finding: &Finding, index: &AdvisoryIndex) -> Vec<Match> {
    let mut matches = Vec::new();
    let name = &finding.component.name;

    for advisory in &index.advisories {
        for affected in &advisory.affected {
            if &affected.component != name {
                continue;
            }
            let verdict = evaluate(finding, affected);
            matches.push(Match {
                advisory_id: advisory.id.clone(),
                component: name.clone(),
                verdict: verdict.0,
                justification: verdict.1,
                severity: advisory.severity.clone(),
                cvss_score: advisory.cvss_score,
                published: advisory.published.clone(),
                description: advisory.description.clone(),
                via_toolkit_release: None,
                references: advisory.references.clone(),
            });
        }
    }
    matches
}

/// Correlate a finding against `cuda-toolkit` advisories *indirectly*, via the
/// CUDA toolkit release(s) that shipped the finding's component version.
///
/// Toolkit-level advisories are keyed to a CUDA release (e.g. `12.4.1`), while a
/// scanned library is keyed to its own version (e.g. cudart `12.4.127`). The
/// `releases` slice is the first-party mapping (from the redist manifest's
/// `release_label`) of *this finding's component version* to its toolkit
/// release(s). For each release, this evaluates the `cuda-toolkit` advisories as
/// if the toolkit itself were the (exact) scanned version, and tags the result
/// with `via_toolkit_release` so the reasoning is transparent.
#[must_use]
pub fn match_finding_via_toolkit(
    finding: &Finding,
    releases: &[String],
    index: &AdvisoryIndex,
) -> Vec<Match> {
    // A component version can ship in more than one toolkit release (e.g. the
    // same cudart in 12.9.1 and 12.9.2). Evaluating every release would report
    // the same (advisory, verdict) once per release: pure noise that also
    // inflates a gate's violation count. Collapse per advisory id, keeping the
    // first affected/under-investigation verdict and recording the toolkit
    // release(s) that reached it, so the reasoning stays transparent without
    // duplication. Releases are processed in sorted order for determinism.
    let mut sorted_releases: Vec<&String> = releases.iter().collect();
    sorted_releases.sort();

    // advisory id -> (index into `matches`, releases that reached it).
    let mut seen: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    let mut release_sets: Vec<Vec<String>> = Vec::new();
    let mut matches: Vec<Match> = Vec::new();

    for release in sorted_releases {
        let toolkit = toolkit_finding(finding, release);
        for advisory in &index.advisories {
            for affected in &advisory.affected {
                if affected.component != "cuda-toolkit" {
                    continue;
                }
                let (verdict, justification) = evaluate(&toolkit, affected);
                // Only surface positive/affected verdicts indirectly; a "not
                // affected by this toolkit CVE" is implied and would be noisy
                // per library. Under-investigation is kept so unresolved
                // toolkit CVEs remain visible.
                if verdict == Verdict::NotAffected {
                    continue;
                }
                if let Some(&idx) = seen.get(&advisory.id) {
                    // Already recorded this advisory via an earlier release:
                    // just note the additional release.
                    release_sets[idx].push(release.clone());
                    continue;
                }
                seen.insert(advisory.id.clone(), matches.len());
                release_sets.push(vec![release.clone()]);
                matches.push(Match {
                    advisory_id: advisory.id.clone(),
                    component: finding.component.name.clone(),
                    verdict,
                    justification,
                    severity: advisory.severity.clone(),
                    cvss_score: advisory.cvss_score,
                    published: advisory.published.clone(),
                    description: advisory.description.clone(),
                    via_toolkit_release: Some(release.clone()),
                    references: advisory.references.clone(),
                });
            }
        }
    }

    // Finalize: fold the contributing release(s) into each justification and
    // the `via_toolkit_release` tag (first release, for the stable field).
    for (m, releases) in matches.iter_mut().zip(release_sets) {
        let via = if releases.len() == 1 {
            format!("via CUDA toolkit release {}", releases[0])
        } else {
            format!("via CUDA toolkit releases {}", releases.join(", "))
        };
        m.justification = format!("{} ({via})", m.justification);
        m.via_toolkit_release = releases.into_iter().next();
    }
    matches
}

/// Build a synthetic EXACT `cuda-toolkit` finding at `release`, reusing the
/// original finding's id lineage for traceability.
fn toolkit_finding(finding: &Finding, release: &str) -> Finding {
    let mut synthetic = finding.clone();
    synthetic.component.name = "cuda-toolkit".to_string();
    synthetic.component.version = Some(release.to_string());
    synthetic.confidence = Confidence::Exact;
    synthetic
}

/// Evaluate a single component's status against a finding, returning the
/// verdict and a justification. A matched component name always yields some
/// verdict (`Affected`, `NotAffected`, or `UnderInvestigation`); it is up to
/// the range logic which one.
fn evaluate(finding: &Finding, affected: &AffectedComponent) -> (Verdict, String) {
    // Parse the finding's version, if any. `12.x` is a major-only range.
    let version_str = finding.component.version.as_deref();

    match finding.confidence {
        Confidence::Exact => evaluate_exact(version_str, affected),
        Confidence::Likely => evaluate_likely(version_str, affected),
        // UNKNOWN identity: the component name matched an advisory, so flag it
        // for investigation, but never claim affected/not-affected.
        Confidence::Unknown => (
            Verdict::UnderInvestigation,
            "component matched but identity/version is unknown".to_string(),
        ),
    }
}

/// EXACT: a precise version we can test directly against the ranges.
fn evaluate_exact(version_str: Option<&str>, affected: &AffectedComponent) -> (Verdict, String) {
    let Some(version) = version_str.and_then(Version::parse) else {
        // EXACT identity but the version string is missing/unparseable: flag
        // rather than guess.
        return (
            Verdict::UnderInvestigation,
            "exact identity without a parseable version".to_string(),
        );
    };

    // Affected ranges take precedence: if the exact version is in one, it is
    // affected regardless of anything else.
    for range in affected
        .affected_ranges
        .iter()
        .filter_map(SerdeRange::to_range)
    {
        if range.contains(&version) {
            return (
                Verdict::Affected,
                format!(
                    "exact version {} is within an affected range",
                    version_or_unknown(version_str)
                ),
            );
        }
    }
    // Otherwise, if it is in a fixed range, it is not affected.
    for range in affected
        .fixed_ranges
        .iter()
        .filter_map(SerdeRange::to_range)
    {
        if range.contains(&version) {
            return (
                Verdict::NotAffected,
                format!(
                    "exact version {} is within a fixed range",
                    version_or_unknown(version_str)
                ),
            );
        }
    }
    // Named component, exact version, but not in any listed range: not affected
    // by *this* advisory (the ranges are exhaustive for what it covers).
    (
        Verdict::NotAffected,
        format!(
            "exact version {} is outside all affected ranges",
            version_or_unknown(version_str)
        ),
    )
}

/// LIKELY: typically a major-only range like `12.x`. We make a definitive claim
/// only when the entire major series is on one side of the boundary.
fn evaluate_likely(version_str: Option<&str>, affected: &AffectedComponent) -> (Verdict, String) {
    // A LIKELY finding's version is expected to look like `12.x`; take the
    // leading integer as the major series.
    let major = version_str
        .and_then(|s| s.split('.').next())
        .and_then(|m| m.parse::<u64>().ok());

    let Some(major) = major else {
        // No usable major: cannot resolve.
        return (
            Verdict::UnderInvestigation,
            "likely identity without a usable version".to_string(),
        );
    };

    // Parse the affected ranges once; both checks below reuse the result.
    let ranges: Vec<_> = affected
        .affected_ranges
        .iter()
        .filter_map(SerdeRange::to_range)
        .collect();

    // If the entire major series is inside an affected range, it is affected.
    if ranges.iter().any(|r| r.contains_entire_major(major)) {
        return (
            Verdict::Affected,
            format!("entire {major}.x series is within an affected range"),
        );
    }

    // If the entire major series is excluded from every affected range, and
    // there is at least one affected range to compare against, it is not
    // affected.
    if !ranges.is_empty() && ranges.iter().all(|r| r.excludes_entire_major(major)) {
        return (
            Verdict::NotAffected,
            format!("entire {major}.x series is outside all affected ranges"),
        );
    }

    // The series straddles a boundary (or there is nothing to compare): the
    // major-only version cannot resolve it.
    (
        Verdict::UnderInvestigation,
        format!("{major}.x range straddles the advisory boundary; exact version needed"),
    )
}

/// Render an optional version string for a justification, falling back to `"?"`.
fn version_or_unknown(v: Option<&str>) -> &str {
    v.unwrap_or("?")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::{Advisory, SerdeRange};
    use cudabom_core::{Component, Relationship};

    #[test]
    fn verdict_serde_matches_as_str() {
        // The JSON token and the `as_str` token must never diverge.
        for v in [
            Verdict::Affected,
            Verdict::NotAffected,
            Verdict::UnderInvestigation,
        ] {
            let json = serde_json::to_string(&v).unwrap();
            assert_eq!(json, format!("\"{}\"", v.as_str()));
        }
    }

    fn finding(name: &str, version: Option<&str>, conf: Confidence) -> Finding {
        Finding {
            id: format!("f::{name}"),
            component: Component {
                name: name.to_string(),
                version: version.map(ToString::to_string),
                candidate_versions: Vec::new(),
                relationship: Relationship::EmbeddedCopy,
            },
            confidence: conf,
            evidence: Vec::new(),
            conflicts: Vec::new(),
        }
    }

    /// An index: cudart affected in [12.0, 12.4).
    fn index() -> AdvisoryIndex {
        AdvisoryIndex {
            schema_version: 1,
            source_commit: None,
            advisories: vec![Advisory {
                id: "CVE-2025-0001".to_string(),
                title: None,
                severity: Some("high".to_string()),
                description: None,
                published: None,
                cvss_score: None,
                references: Vec::new(),
                affected: vec![AffectedComponent {
                    component: "cudart".to_string(),
                    affected_ranges: vec![SerdeRange {
                        introduced: Some("12.0".to_string()),
                        fixed: Some("12.4".to_string()),
                    }],
                    fixed_ranges: Vec::new(),
                }],
            }],
        }
    }

    #[test]
    fn exact_in_range_is_affected() {
        let m = match_finding(
            &finding("cudart", Some("12.3.1"), Confidence::Exact),
            &index(),
        );
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].verdict, Verdict::Affected);
    }

    #[test]
    fn exact_at_fix_boundary_is_not_affected() {
        let m = match_finding(
            &finding("cudart", Some("12.4"), Confidence::Exact),
            &index(),
        );
        assert_eq!(m[0].verdict, Verdict::NotAffected);
    }

    #[test]
    fn exact_outside_is_not_affected() {
        let m = match_finding(
            &finding("cudart", Some("11.8"), Confidence::Exact),
            &index(),
        );
        assert_eq!(m[0].verdict, Verdict::NotAffected);
    }

    #[test]
    fn likely_straddling_major_is_under_investigation() {
        // 12.x straddles [12.0, 12.4): cannot resolve without exact version.
        let m = match_finding(
            &finding("cudart", Some("12.x"), Confidence::Likely),
            &index(),
        );
        assert_eq!(m[0].verdict, Verdict::UnderInvestigation);
    }

    #[test]
    fn likely_major_fully_outside_is_not_affected() {
        // 13.x is entirely above the affected range -> not affected.
        let m = match_finding(
            &finding("cudart", Some("13.x"), Confidence::Likely),
            &index(),
        );
        assert_eq!(m[0].verdict, Verdict::NotAffected);
    }

    #[test]
    fn likely_major_fully_inside_open_range_is_affected() {
        // Advisory affecting >= 12.0 (no fix yet): entire 12.x is affected.
        let idx = AdvisoryIndex {
            schema_version: 1,
            source_commit: None,
            advisories: vec![Advisory {
                id: "CVE-2025-0002".to_string(),
                title: None,
                severity: None,
                description: None,
                published: None,
                cvss_score: None,
                references: Vec::new(),
                affected: vec![AffectedComponent {
                    component: "cudart".to_string(),
                    affected_ranges: vec![SerdeRange {
                        introduced: Some("12.0".to_string()),
                        fixed: None,
                    }],
                    fixed_ranges: Vec::new(),
                }],
            }],
        };
        let m = match_finding(&finding("cudart", Some("12.x"), Confidence::Likely), &idx);
        assert_eq!(m[0].verdict, Verdict::Affected);
    }

    #[test]
    fn unknown_confidence_is_under_investigation() {
        let m = match_finding(&finding("cudart", None, Confidence::Unknown), &index());
        assert_eq!(m[0].verdict, Verdict::UnderInvestigation);
    }

    #[test]
    fn unrelated_component_produces_no_match() {
        let m = match_finding(&finding("cudnn", Some("9.0"), Confidence::Exact), &index());
        assert!(
            m.is_empty(),
            "a version outside the affected range yields no match"
        );
    }

    /// A `cuda-toolkit` advisory index for the toolkit-correlation tests:
    /// affected in [0, 11.6.2) (i.e. "prior to 11.6 Update 2").
    fn toolkit_index() -> AdvisoryIndex {
        AdvisoryIndex {
            schema_version: 1,
            source_commit: None,
            advisories: vec![Advisory {
                id: "CVE-2022-21821".to_string(),
                title: None,
                severity: Some("high".to_string()),
                description: None,
                published: None,
                cvss_score: None,
                references: Vec::new(),
                affected: vec![AffectedComponent {
                    component: "cuda-toolkit".to_string(),
                    affected_ranges: vec![SerdeRange {
                        introduced: None,
                        fixed: Some("11.6.2".to_string()),
                    }],
                    fixed_ranges: Vec::new(),
                }],
            }],
        }
    }

    #[test]
    fn toolkit_correlation_flags_library_via_release() {
        // A cudart library that shipped in CUDA toolkit 11.4.2 is affected by a
        // toolkit CVE fixed at 11.6.2, reached via the release mapping.
        let f = finding("cudart", Some("11.4.108"), Confidence::Exact);
        let m = match_finding_via_toolkit(&f, &["11.4.2".to_string()], &toolkit_index());
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].advisory_id, "CVE-2022-21821");
        assert_eq!(m[0].component, "cudart"); // reported against the library
        assert_eq!(m[0].verdict, Verdict::Affected);
        assert_eq!(m[0].via_toolkit_release.as_deref(), Some("11.4.2"));
    }

    #[test]
    fn toolkit_correlation_collapses_duplicate_releases() {
        // A component version shipped in two toolkit releases must yield one
        // match per advisory (not one per release), with both releases credited.
        let f = finding("cudart", Some("11.4.108"), Confidence::Exact);
        let m = match_finding_via_toolkit(
            &f,
            &["11.4.2".to_string(), "11.4.3".to_string()],
            &toolkit_index(),
        );
        assert_eq!(
            m.len(),
            1,
            "one match for the advisory, not one per release"
        );
        assert_eq!(m[0].advisory_id, "CVE-2022-21821");
        assert!(
            m[0].justification.contains("11.4.2") && m[0].justification.contains("11.4.3"),
            "both contributing releases are credited: {}",
            m[0].justification
        );
    }

    #[test]
    fn toolkit_correlation_excludes_fixed_release() {
        // A library shipped in toolkit 12.4.1 is NOT affected by a CVE fixed at
        // 11.6.2 (12.4.1 is past the fix); no indirect match is emitted.
        let f = finding("cudart", Some("12.4.127"), Confidence::Exact);
        let m = match_finding_via_toolkit(&f, &["12.4.1".to_string()], &toolkit_index());
        assert!(
            m.is_empty(),
            "a version past the fix yields no indirect toolkit match"
        );
    }

    #[test]
    fn toolkit_correlation_ignores_non_toolkit_advisories() {
        // The cudart-only index has no cuda-toolkit component, so indirect
        // correlation yields nothing.
        let f = finding("cudart", Some("11.4.108"), Confidence::Exact);
        let m = match_finding_via_toolkit(&f, &["11.4.2".to_string()], &index());
        assert!(
            m.is_empty(),
            "an index without a cuda-toolkit component yields no indirect match"
        );
    }
}
