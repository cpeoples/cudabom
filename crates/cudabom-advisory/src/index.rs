//! The normalized advisory index.
//!
//! CSAF documents are verbose and varied; a scan should not re-parse them every
//! run. `cudabom db update` parses CSAF once and writes this compact, normalized
//! index, which a scan loads read-only. The index is intentionally simple:
//! a list of advisories, each naming the affected/fixed/not-affected version
//! ranges per cudabom component.

use serde::{Deserialize, Serialize};

use crate::version::{Bound, Version, VersionRange};

/// The complete normalized advisory index.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AdvisoryIndex {
    /// Schema version of this index file.
    pub schema_version: u32,
    /// Provenance so a report can say "advisories as of <source>".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_commit: Option<String>,
    /// The advisories.
    pub advisories: Vec<Advisory>,
}

/// One security advisory affecting one or more cudabom components.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Advisory {
    /// Advisory identifier (e.g. a CVE id or NVIDIA bulletin id).
    pub id: String,
    /// Short title/summary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Severity as published (free text, e.g. `critical`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    /// A longer human-readable description of the vulnerability, taken from the
    /// CSAF `notes` (a `description`/`summary`/`general` note). First-party;
    /// absent when the bulletin carried none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// The date the advisory was first published, as CSAF states it in
    /// `document.tracking.initial_release_date` (e.g. `2024-04-03` or a full
    /// RFC 3339 timestamp). Recorded verbatim; absent when not provided.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub published: Option<String>,
    /// The CVSS base score (0.0-10.0) as published in the CSAF vulnerability
    /// `scores` (highest base score across the vulnerability's CVSS entries).
    /// A numeric complement to the free-text `severity`; absent when none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cvss_score: Option<f64>,
    /// Reference URLs for the advisory: the CSAF `vulnerabilities[].references[]`
    /// URLs (NVIDIA bulletin pages, etc.) plus the canonical NVD page for a CVE
    /// id. First-party and deterministic; deduplicated and sorted. An additive
    /// field: older indexes without it deserialize to an empty vector, and an
    /// empty vector is omitted on serialization, so the schema stays at 1.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<String>,
    /// Per-component version status.
    pub affected: Vec<AffectedComponent>,
}

/// The version status of one component within one advisory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AffectedComponent {
    /// cudabom canonical component name (e.g. `cudart`).
    pub component: String,
    /// Version ranges known to be affected.
    #[serde(default)]
    pub affected_ranges: Vec<SerdeRange>,
    /// Versions known to be fixed / not affected.
    #[serde(default)]
    pub fixed_ranges: Vec<SerdeRange>,
}

/// A serializable version range (string bounds) that converts to the internal
/// [`VersionRange`]. Bounds are given as strings so the index stays readable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SerdeRange {
    /// Inclusive lower bound (`>=`), if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub introduced: Option<String>,
    /// Exclusive upper bound (`<`), if any. Following the common advisory
    /// convention that a fix "at" a version means versions below it are
    /// affected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fixed: Option<String>,
}

impl SerdeRange {
    /// Convert to an internal [`VersionRange`], returning `None` if a bound is
    /// present but unparseable (so bad data fails loudly rather than matching
    /// everything).
    #[must_use]
    pub fn to_range(&self) -> Option<VersionRange> {
        let lower = match &self.introduced {
            None => Bound::Unbounded,
            Some(s) => Bound::Inclusive(Version::parse(s)?),
        };
        let upper = match &self.fixed {
            None => Bound::Unbounded,
            Some(s) => Bound::Exclusive(Version::parse(s)?),
        };
        Some(VersionRange { lower, upper })
    }
}

impl AdvisoryIndex {
    /// The current index schema version this build understands.
    pub const CURRENT_SCHEMA: u32 = 1;

    /// Load an index from JSON bytes.
    ///
    /// # Errors
    /// Returns an error if the JSON is malformed or the schema is newer than
    /// this build understands.
    pub fn from_json(bytes: &[u8]) -> Result<Self, IndexError> {
        let index: AdvisoryIndex =
            serde_json::from_slice(bytes).map_err(|e| IndexError::Parse(e.to_string()))?;
        if index.schema_version > Self::CURRENT_SCHEMA {
            return Err(IndexError::UnsupportedSchema {
                found: index.schema_version,
                supported: Self::CURRENT_SCHEMA,
            });
        }
        Ok(index)
    }

    /// True if the index has no advisories.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.advisories.is_empty()
    }

    /// Serialize the index to pretty JSON.
    ///
    /// # Errors
    /// Returns an error only if serialization fails.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

/// Errors from loading an advisory index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IndexError {
    Parse(String),
    UnsupportedSchema { found: u32, supported: u32 },
}

impl std::fmt::Display for IndexError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Parse(msg) => write!(f, "advisory index parse error: {msg}"),
            Self::UnsupportedSchema { found, supported } => write!(
                f,
                "advisory index schema {found} is newer than supported {supported}"
            ),
        }
    }
}

impl std::error::Error for IndexError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_index_is_empty() {
        assert!(AdvisoryIndex::default().is_empty());
    }

    #[test]
    fn range_conversion() {
        let r = SerdeRange {
            introduced: Some("12.0".to_string()),
            fixed: Some("12.4".to_string()),
        };
        let range = r.to_range().unwrap();
        assert!(range.contains(&Version::parse("12.3").unwrap()));
        assert!(!range.contains(&Version::parse("12.4").unwrap()));
    }

    #[test]
    fn bad_bound_fails_loudly() {
        let r = SerdeRange {
            introduced: Some("not-a-version".to_string()),
            fixed: None,
        };
        assert!(r.to_range().is_none());
    }

    #[test]
    fn round_trips_json() {
        let json = r#"{
            "schema_version": 1,
            "advisories": [
                {
                    "id": "CVE-2025-0001",
                    "severity": "high",
                    "description": "A flaw in cudart.",
                    "published": "2025-01-15",
                    "cvss_score": 8.8,
                    "references": [ "https://nvidia.example/bulletin/1" ],
                    "affected": [
                        { "component": "cudart", "affected_ranges": [ { "introduced": "12.0", "fixed": "12.4" } ] }
                    ]
                }
            ]
        }"#;
        let idx = AdvisoryIndex::from_json(json.as_bytes()).unwrap();
        assert_eq!(idx.advisories.len(), 1);
        let adv = &idx.advisories[0];
        assert_eq!(adv.id, "CVE-2025-0001");
        assert_eq!(adv.description.as_deref(), Some("A flaw in cudart."));
        assert_eq!(adv.published.as_deref(), Some("2025-01-15"));
        assert_eq!(adv.cvss_score, Some(8.8));
        assert_eq!(
            adv.references,
            vec!["https://nvidia.example/bulletin/1".to_string()]
        );
        assert_eq!(adv.affected[0].component, "cudart");

        // Re-serializing and re-parsing preserves the enrichment fields.
        let reserialized = idx.to_json().unwrap();
        let reparsed = AdvisoryIndex::from_json(reserialized.as_bytes()).unwrap();
        assert_eq!(reparsed.advisories[0].cvss_score, Some(8.8));
        assert_eq!(
            reparsed.advisories[0].references,
            vec!["https://nvidia.example/bulletin/1".to_string()]
        );
    }

    #[test]
    fn rejects_future_schema() {
        let json = r#"{ "schema_version": 99, "advisories": [] }"#;
        assert!(matches!(
            AdvisoryIndex::from_json(json.as_bytes()),
            Err(IndexError::UnsupportedSchema { .. })
        ));
    }
}
