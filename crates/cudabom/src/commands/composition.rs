//! Per-binary composition view: which CUDA components each scanned file *links*
//! (dynamic `NEEDED` dependencies) versus *contains* (embedded/vendored or
//! statically-linked copies).
//!
//! This is pure aggregation over the findings the identify engine already
//! produced: every [`Finding`]'s evidence records the file it was observed in
//! (`evidence[].location.path`), and its [`Relationship`] says whether the
//! component is linked or contained. Grouping those two facts yields a
//! dependency/composition tree without any new parsing or identity logic, so
//! the evidence model stays the single source of truth.

use std::collections::BTreeMap;

use cudabom_advisory::Match;
use cudabom_core::{Confidence, Finding, Relationship};
use serde::Serialize;

/// The composition of every scanned binary that had at least one CUDA finding.
#[derive(Debug, Default, Serialize)]
pub(crate) struct Composition {
    /// One entry per originating file, sorted by path.
    pub(crate) binaries: Vec<BinaryComposition>,
}

impl Composition {
    /// True when no binary had any CUDA linkage or contents.
    pub(crate) fn is_empty(&self) -> bool {
        self.binaries.is_empty()
    }
}

/// The CUDA composition of a single file.
#[derive(Debug, Serialize)]
pub(crate) struct BinaryComposition {
    /// Logical path of the file within the scanned artifact.
    pub(crate) path: String,
    /// sha256 of the file, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) sha256: Option<String>,
    /// CUDA components this file declares as dynamic (`NEEDED`) dependencies.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) links: Vec<CompNode>,
    /// CUDA components embedded/vendored or statically linked *into* this file.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) contains: Vec<CompNode>,
}

/// One CUDA component in a binary's composition, tracing back to its finding.
#[derive(Debug, Serialize)]
pub(crate) struct CompNode {
    /// Canonical component name (e.g. `cudart`).
    pub(crate) name: String,
    /// Exact version or supported range, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) version: Option<String>,
    /// Confidence of the underlying finding.
    pub(crate) confidence: Confidence,
    /// The finding id, so `cudabom explain <id>` reaches the full evidence.
    pub(crate) finding_id: String,
    /// Advisory verdicts for this component, when an index was supplied. Lets a
    /// reader see per-node whether the contained/linked component is affected.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) advisories: Vec<NodeVerdict>,
}

/// One advisory verdict attached to a composition node.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct NodeVerdict {
    /// The advisory id (CVE or bulletin id).
    pub(crate) advisory_id: String,
    /// Serializes to `affected`, `not_affected`, or `under_investigation`.
    pub(crate) verdict: cudabom_advisory::Verdict,
}

impl CompNode {
    fn from_finding(f: &Finding) -> Self {
        Self {
            name: f.component.name.clone(),
            version: f.component.version.clone(),
            confidence: f.confidence,
            finding_id: f.id.clone(),
            advisories: Vec::new(),
        }
    }
}

/// Assemble the composition view from the flat findings list, optionally
/// annotating each node with the advisory verdicts for its component.
///
/// Findings are grouped by the file their first evidence item points at.
/// [`Relationship::DynamicDependency`] becomes a `links` edge;
/// [`Relationship::EmbeddedCopy`] and [`Relationship::StaticallyLinked`] become
/// `contains` edges. [`Relationship::DeclaredOnly`] is not a byte-level
/// composition fact and is skipped here (it is surfaced in the findings list).
///
/// `matches` (when present) are the advisory verdicts from `match_findings`;
/// each node is annotated with the verdicts whose component equals the node's.
/// The join is by component name because a verdict is a property of the
/// (component, version) identity, which the node already carries.
pub(crate) fn build(findings: &[Finding], matches: Option<&[Match]>) -> Composition {
    // Preserve a stable path order while grouping.
    let mut order: Vec<String> = Vec::new();
    let mut by_path: BTreeMap<String, BinaryComposition> = BTreeMap::new();

    // Group verdicts by component name for annotation.
    let mut verdicts_by_component: BTreeMap<&str, Vec<NodeVerdict>> = BTreeMap::new();
    if let Some(matches) = matches {
        for m in matches {
            verdicts_by_component
                .entry(m.component.as_str())
                .or_default()
                .push(NodeVerdict {
                    advisory_id: m.advisory_id.clone(),
                    verdict: m.verdict,
                });
        }
    }
    let annotate = |mut node: CompNode| -> CompNode {
        if let Some(vs) = verdicts_by_component.get(node.name.as_str()) {
            node.advisories = vs.clone();
        }
        node
    };

    for f in findings {
        let Some(ev) = f.evidence.first() else {
            continue; // a finding with no evidence has no home file
        };
        let loc = &ev.location;
        let entry = by_path.entry(loc.path.clone()).or_insert_with(|| {
            order.push(loc.path.clone());
            BinaryComposition {
                path: loc.path.clone(),
                sha256: loc.sha256.clone(),
                links: Vec::new(),
                contains: Vec::new(),
            }
        });
        match f.component.relationship {
            Relationship::DynamicDependency => {
                entry.links.push(annotate(CompNode::from_finding(f)));
            }
            Relationship::EmbeddedCopy | Relationship::StaticallyLinked => {
                entry.contains.push(annotate(CompNode::from_finding(f)));
            }
            // Declared-only is not a composition fact; skip. New (non-exhaustive)
            // relationships are conservatively skipped until modeled here.
            _ => {}
        }
    }

    // Deterministic node order within each binary: by name, then finding id.
    let mut binaries: Vec<BinaryComposition> = by_path.into_values().collect();
    for b in &mut binaries {
        let sort = |v: &mut Vec<CompNode>| {
            v.sort_by(|a, c| a.name.cmp(&c.name).then(a.finding_id.cmp(&c.finding_id)));
        };
        sort(&mut b.links);
        sort(&mut b.contains);
    }
    // Drop binaries that ended up with neither links nor contains.
    binaries.retain(|b| !b.links.is_empty() || !b.contains.is_empty());
    binaries.sort_by(|a, c| a.path.cmp(&c.path));

    Composition { binaries }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cudabom_core::{Component, Evidence, EvidenceKind, Location};

    fn finding(id: &str, name: &str, rel: Relationship, path: &str) -> Finding {
        Finding {
            id: id.to_string(),
            component: Component {
                name: name.to_string(),
                version: Some("12.4.1".to_string()),
                candidate_versions: Vec::new(),
                relationship: rel,
            },
            confidence: Confidence::Likely,
            evidence: vec![Evidence {
                kind: EvidenceKind::Soname,
                location: Location {
                    path: path.to_string(),
                    sha256: Some("deadbeef".to_string()),
                    layer_digest: None,
                },
                detail: name.to_string(),
            }],
            conflicts: Vec::new(),
        }
    }

    #[test]
    fn groups_links_and_contains_per_file() {
        let findings = vec![
            finding("f1", "cudart", Relationship::EmbeddedCopy, "app/lib.so"),
            finding(
                "f2",
                "cublas",
                Relationship::DynamicDependency,
                "app/lib.so",
            ),
            finding("f3", "cufft", Relationship::StaticallyLinked, "app/lib.so"),
            finding(
                "f4",
                "cudart",
                Relationship::DynamicDependency,
                "app/other.so",
            ),
        ];
        let comp = build(&findings, None);
        assert_eq!(comp.binaries.len(), 2);

        let lib = &comp.binaries[0];
        assert_eq!(lib.path, "app/lib.so");
        assert_eq!(lib.sha256.as_deref(), Some("deadbeef"));
        // cublas is linked; cudart + cufft are contained.
        assert_eq!(
            lib.links.iter().map(|n| &n.name).collect::<Vec<_>>(),
            ["cublas"]
        );
        assert_eq!(
            lib.contains.iter().map(|n| &n.name).collect::<Vec<_>>(),
            ["cudart", "cufft"]
        );

        let other = &comp.binaries[1];
        assert_eq!(other.path, "app/other.so");
        assert_eq!(
            other.links.iter().map(|n| &n.name).collect::<Vec<_>>(),
            ["cudart"]
        );
        assert!(
            other.contains.is_empty(),
            "a non-container node contains nothing"
        );
    }

    #[test]
    fn declared_only_is_not_a_composition_edge() {
        let findings = vec![finding(
            "f1",
            "cudnn",
            Relationship::DeclaredOnly,
            "app/lib.so",
        )];
        let comp = build(&findings, None);
        assert!(comp.is_empty());
    }

    #[test]
    fn empty_findings_yield_empty_composition() {
        assert!(build(&[], None).is_empty());
    }

    #[test]
    fn annotates_nodes_with_advisory_verdicts() {
        use cudabom_advisory::{Match, Verdict};
        let findings = vec![finding(
            "f1",
            "cudart",
            Relationship::EmbeddedCopy,
            "app/lib.so",
        )];
        let matches = vec![Match {
            advisory_id: "CVE-2025-0001".to_string(),
            component: "cudart".to_string(),
            verdict: Verdict::Affected,
            justification: "in range".to_string(),
            severity: None,
            cvss_score: None,
            published: None,
            description: None,
            via_toolkit_release: None,
            references: Vec::new(),
        }];
        let comp = build(&findings, Some(&matches));
        let node = &comp.binaries[0].contains[0];
        assert_eq!(node.advisories.len(), 1);
        assert_eq!(node.advisories[0].advisory_id, "CVE-2025-0001");
        assert_eq!(node.advisories[0].verdict, Verdict::Affected);
    }
}
