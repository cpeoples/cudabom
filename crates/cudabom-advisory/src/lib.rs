//! NVIDIA advisory correlation for cudabom.
//!
//! Responsibility: normalize NVIDIA's machine-readable CSAF security bulletins
//! into a local index (see the `index` module) and match identified components
//! against it to produce affected / not_affected / under_investigation verdicts
//! (see the `matcher` module).
//!
//! Network access is confined to the explicit `cudabom db update` command; a
//! normal scan reads the local, verified index only. Absence of a match is
//! never treated as proof of safety: [`match_findings`] returns only positive
//! verdicts, so the caller prints the coverage caveat itself.

mod csaf;
mod data;
mod fetch;
mod index;
mod matcher;
mod product_map;
mod unpack;
mod version;

pub use csaf::{ingest, CsafError, Ingest};
pub use cudabom_fetch::RetryPolicy;
pub use data::{
    bundle_asset_name, update_data, DataSource, Installed, DEFAULT_DATA_OWNER, DEFAULT_DATA_REPO,
};
pub use fetch::{
    download, fetch_file, fetch_file_checked, is_csaf_path, list_csaf_paths, unpack_csaf,
    verify_sha256, FetchError, FetchMode, FetchSource, FileOutcome, UnpackLimits, DEFAULT_OWNER,
    DEFAULT_REPO, DEFAULT_REV,
};
pub use index::{Advisory, AdvisoryIndex, AffectedComponent, IndexError, SerdeRange};
pub use matcher::{match_finding, match_finding_via_toolkit, Match, Verdict};
pub use product_map::{MapError, ProductMap, SubstringRule};
pub use version::{Bound, Version, VersionRange};

use cudabom_core::Finding;

/// Fetch, verify, unpack, and ingest CSAF from `source` into a normalized index.
///
/// This is the network path behind `cudabom db update`. NVIDIA publishes no CSAF
/// discovery manifest, so cudabom synthesizes one from the repository tree:
///
/// - [`FetchMode::Manifest`] (default): list the CSAF documents via the Git Trees
///   API, then fetch only those files (each verified against its published
///   `.sha256` sibling when present).
/// - [`FetchMode::Tarball`]: download the whole-repository tarball and unpack its
///   CSAF entries in memory.
///
/// Both strategies feed the same offline [`ingest`] used by `db build`, and the
/// source revision is recorded as the index's provenance.
///
/// # Errors
/// Returns [`FetchError`] on any network, integrity, or unpack failure, and a
/// [`CsafError`] (wrapped) if a document is not valid JSON.
pub fn update(source: &FetchSource, map: &ProductMap) -> Result<Ingest, UpdateError> {
    let mut integrity_skipped = Vec::new();
    let documents = match source.mode {
        FetchMode::Manifest => {
            let paths = list_csaf_paths(source).map_err(UpdateError::Fetch)?;
            let mut docs = Vec::with_capacity(paths.len());
            for path in &paths {
                match fetch_file_checked(source, path).map_err(UpdateError::Fetch)? {
                    FileOutcome::Fetched(bytes) => docs.push(bytes),
                    FileOutcome::IntegrityMismatch { expected, actual } => {
                        // Stale upstream sidecar: skip this one document and
                        // report it. The pinned commit SHA still anchors the
                        // overall tree's integrity.
                        integrity_skipped
                            .push(format!("{path}: expected {expected}, got {actual}"));
                    }
                }
            }
            docs
        }
        FetchMode::Tarball => {
            let archive = download(source).map_err(UpdateError::Fetch)?;
            unpack_csaf(&archive, &UnpackLimits::default()).map_err(UpdateError::Fetch)?
        }
    };
    let mut ingested =
        ingest(&documents, map, Some(source.rev.clone())).map_err(UpdateError::Csaf)?;
    integrity_skipped.sort();
    ingested.integrity_skipped = integrity_skipped;
    Ok(ingested)
}

/// Errors from the end-to-end [`update`].
#[derive(Debug)]
pub enum UpdateError {
    Fetch(FetchError),
    Csaf(CsafError),
}

impl std::fmt::Display for UpdateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Fetch(e) => write!(f, "{e}"),
            Self::Csaf(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for UpdateError {}

/// Match every finding against the index, returning all verdicts.
///
/// Findings with no matching advisory contribute nothing; the absence of a
/// verdict is not a safety claim. Callers should surface the coverage caveat
/// ("absence of a match is not proof of safety") alongside these results.
#[must_use]
pub fn match_findings(findings: &[Finding], index: &AdvisoryIndex) -> Vec<Match> {
    let mut all = Vec::new();
    for finding in findings {
        all.extend(matcher::match_finding(finding, index));
    }
    // Deterministic order: by advisory id, then component.
    all.sort_by(|a, b| {
        a.advisory_id
            .cmp(&b.advisory_id)
            .then(a.component.cmp(&b.component))
    });
    all
}

/// Match every finding against the index, *and* correlate each finding against
/// toolkit-level advisories via the CUDA release(s) that shipped its version.
///
/// `toolkit_releases(component, version)` returns the toolkit release label(s)
/// that shipped that exact component version (the first-party mapping derived
/// from the redist manifest's `release_label`). This is what lets a
/// `cuda-toolkit` CVE reach an individually-scanned library. Direct matches and
/// indirect toolkit matches are merged and de-duplicated so the same
/// (advisory, component, verdict, via) tuple never appears twice.
#[must_use]
pub fn match_findings_with_toolkit(
    findings: &[Finding],
    index: &AdvisoryIndex,
    toolkit_releases: impl Fn(&str, &str) -> Vec<String>,
) -> Vec<Match> {
    let mut all = Vec::new();
    for finding in findings {
        all.extend(matcher::match_finding(finding, index));
        // Indirect toolkit correlation requires a concrete version to resolve
        // the shipping release(s).
        if let Some(version) = finding.component.version.as_deref() {
            let releases = toolkit_releases(&finding.component.name, version);
            if !releases.is_empty() {
                all.extend(matcher::match_finding_via_toolkit(
                    finding, &releases, index,
                ));
            }
        }
    }
    // Deterministic order and de-duplication.
    all.sort_by(|a, b| {
        a.advisory_id
            .cmp(&b.advisory_id)
            .then(a.component.cmp(&b.component))
            .then(a.via_toolkit_release.cmp(&b.via_toolkit_release))
    });
    all.dedup();
    all
}

#[cfg(test)]
mod tests {
    use super::*;
    use cudabom_core::{Component, Confidence, Finding, Relationship};

    #[test]
    fn match_findings_is_deterministic_and_sorted() {
        let json = r#"{
            "schema_version": 1,
            "advisories": [
                { "id": "CVE-B", "affected": [ { "component": "cudart", "affected_ranges": [ { "introduced": "12.0", "fixed": "12.5" } ] } ] },
                { "id": "CVE-A", "affected": [ { "component": "cudart", "affected_ranges": [ { "introduced": "12.0", "fixed": "12.5" } ] } ] }
            ]
        }"#;
        let idx = AdvisoryIndex::from_json(json.as_bytes()).unwrap();
        let findings = vec![Finding {
            id: "f::cudart".to_string(),
            component: Component {
                name: "cudart".to_string(),
                version: Some("12.3".to_string()),
                candidate_versions: Vec::new(),
                relationship: Relationship::EmbeddedCopy,
            },
            confidence: Confidence::Exact,
            evidence: Vec::new(),
            conflicts: Vec::new(),
        }];
        let matches = match_findings(&findings, &idx);
        assert_eq!(matches.len(), 2);
        // Sorted by advisory id: CVE-A before CVE-B.
        assert_eq!(matches[0].advisory_id, "CVE-A");
        assert_eq!(matches[1].advisory_id, "CVE-B");
        assert!(matches.iter().all(|m| m.verdict == Verdict::Affected));
    }

    #[test]
    fn empty_index_yields_no_matches() {
        let findings = vec![Finding {
            id: "f::cudart".to_string(),
            component: Component {
                name: "cudart".to_string(),
                version: Some("12.3".to_string()),
                candidate_versions: Vec::new(),
                relationship: Relationship::EmbeddedCopy,
            },
            confidence: Confidence::Exact,
            evidence: Vec::new(),
            conflicts: Vec::new(),
        }];
        assert!(
            match_findings(&findings, &AdvisoryIndex::default()).is_empty(),
            "an empty advisory index yields no matches"
        );
    }
}
