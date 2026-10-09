//! CSAF 2.0 ingestion: parse NVIDIA CSAF bulletins into the normalized
//! [`AdvisoryIndex`].
//!
//! CSAF (Common Security Advisory Framework) 2.0 is an OASIS JSON standard. Its
//! product model is expressive; cudabom parses the subset NVIDIA bulletins use
//! in practice and that our matcher needs:
//!
//! - `product_tree.full_product_names[]` and `product_tree.branches[]` give the
//!   map from `product_id` to a human product name and, where present, a
//!   version (from a `category: "product_version"` branch).
//! - `vulnerabilities[]` give the CVE id and `product_status` lists
//!   (`known_affected`, `fixed`, `known_not_affected`, `under_investigation`)
//!   as arrays of `product_id`.
//!
//! Each affected/fixed product is resolved to a cudabom component via the
//! [`ProductMap`]. A product with no mapping is *not* guessed: it is returned in
//! the [`Ingest::unmapped`] set so `cudabom db status` can report it, and the
//! advisory still records the products it *could* map. Nothing is silently
//! dropped.

use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;

use crate::index::{Advisory, AdvisoryIndex, AffectedComponent, SerdeRange};
use crate::product_map::ProductMap;

/// The result of ingesting one or more CSAF documents.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Ingest {
    /// The normalized index built from the mapped products.
    pub index: AdvisoryIndex,
    /// Product names encountered that had no mapping, for `db status`. Sorted
    /// and de-duplicated.
    pub unmapped: Vec<String>,
    /// CSAF documents skipped because a present `.sha256` sidecar did not match
    /// the fetched content (stale upstream sidecar). Each entry is
    /// `"<path>: expected <hex>, got <hex>"`. Empty for offline ingestion.
    pub integrity_skipped: Vec<String>,
}

/// Errors from CSAF ingestion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CsafError {
    /// The document was not valid JSON.
    Parse(String),
}

impl std::fmt::Display for CsafError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Parse(m) => write!(f, "CSAF parse error: {m}"),
        }
    }
}

impl std::error::Error for CsafError {}

/// Ingest a set of CSAF documents (raw JSON bytes) into a normalized index,
/// resolving products through `map`. The `source_commit`, when given, is
/// recorded in the index for provenance.
///
/// # Errors
/// Returns [`CsafError::Parse`] if any document is not valid JSON.
pub fn ingest(
    documents: &[Vec<u8>],
    map: &ProductMap,
    source_commit: Option<String>,
) -> Result<Ingest, CsafError> {
    let mut advisories = Vec::new();
    let mut unmapped = BTreeSet::new();

    for bytes in documents {
        let doc: CsafDocument =
            serde_json::from_slice(bytes).map_err(|e| CsafError::Parse(e.to_string()))?;
        ingest_document(&doc, map, &mut advisories, &mut unmapped);
    }

    // Deterministic advisory order.
    advisories.sort_by(|a: &Advisory, b: &Advisory| a.id.cmp(&b.id));

    Ok(Ingest {
        index: AdvisoryIndex {
            schema_version: AdvisoryIndex::CURRENT_SCHEMA,
            source_commit,
            advisories,
        },
        unmapped: unmapped.into_iter().collect(),
        integrity_skipped: Vec::new(),
    })
}

fn ingest_document(
    doc: &CsafDocument,
    map: &ProductMap,
    advisories: &mut Vec<Advisory>,
    unmapped: &mut BTreeSet<String>,
) {
    // Build product_id -> (name, optional version) from the product tree.
    let products = doc
        .product_tree
        .as_ref()
        .map(collect_products)
        .unwrap_or_default();

    let severity = doc
        .document
        .as_ref()
        .and_then(|d| d.aggregate_severity.as_ref())
        .map(|s| s.text.clone());

    // First-party publication date from the document tracking block.
    let published = doc
        .document
        .as_ref()
        .and_then(|d| d.tracking.as_ref())
        .and_then(|t| t.initial_release_date.clone());

    for vuln in &doc.vulnerabilities {
        let Some(id) = vuln.effective_id() else {
            continue;
        };

        // Group affected/fixed product versions by component.
        let mut by_component: BTreeMap<String, ComponentRanges> = BTreeMap::new();

        let status = &vuln.product_status;
        for pid in &status.known_affected {
            add_product(
                pid,
                &products,
                map,
                unmapped,
                &mut by_component,
                RangeKind::Affected,
            );
        }
        for pid in status.fixed.iter().chain(&status.known_not_affected) {
            add_product(
                pid,
                &products,
                map,
                unmapped,
                &mut by_component,
                RangeKind::Fixed,
            );
        }

        if by_component.is_empty() {
            // No product this advisory affects could be mapped; skip emitting an
            // empty advisory (the unmapped products are already recorded).
            continue;
        }

        let mut affected: Vec<AffectedComponent> = by_component
            .into_iter()
            .map(|(component, ranges)| AffectedComponent {
                component,
                affected_ranges: ranges.affected,
                fixed_ranges: ranges.fixed,
            })
            .collect();
        affected.sort_by(|a, b| a.component.cmp(&b.component));

        advisories.push(Advisory {
            id,
            title: vuln.title.clone(),
            severity: severity.clone(),
            description: vuln.description(),
            published: published.clone(),
            cvss_score: vuln.cvss_base_score(),
            references: vuln.references(),
            affected,
        });
    }
}

/// Accumulated ranges for one component within one advisory.
#[derive(Default)]
struct ComponentRanges {
    affected: Vec<SerdeRange>,
    fixed: Vec<SerdeRange>,
}

#[derive(Clone, Copy)]
enum RangeKind {
    Affected,
    Fixed,
}

/// Resolve one product id, record it as mapped/unmapped, and add a range.
fn add_product(
    product_id: &str,
    products: &BTreeMap<String, ProductInfo>,
    map: &ProductMap,
    unmapped: &mut BTreeSet<String>,
    by_component: &mut BTreeMap<String, ComponentRanges>,
    kind: RangeKind,
) {
    let Some(info) = products.get(product_id) else {
        // A product_status entry referencing an unknown product id: record the
        // id itself so it is visible, not silently ignored.
        unmapped.insert(product_id.to_string());
        return;
    };
    let Some(component) = map.resolve(&info.name) else {
        unmapped.insert(info.name.clone());
        return;
    };

    // Convert the CSAF version text into a range. NVIDIA uses point versions
    // (e.g. `v10.16.1`) and phrases (e.g. `All versions prior to v10.16.1`).
    // The affected/fixed side determines the semantics.
    let range = version_to_range(info.version.as_deref(), kind);

    let entry = by_component.entry(component.to_string()).or_default();
    match kind {
        RangeKind::Affected => entry.affected.push(range),
        RangeKind::Fixed => entry.fixed.push(range),
    }
}

/// Convert a CSAF version descriptor into a [`SerdeRange`], interpreting the
/// common NVIDIA forms:
///
/// - `All versions prior to X` / `< X` -> affected range `[.., X)`.
/// - a bare point version `X` (e.g. `v10.16.1`, `12.4`):
///   - on the **affected** side, the exact point `[X, X]-ish` (recorded as
///     `introduced = X`), and
///   - on the **fixed** side, `fixed = X` so the matcher treats `>= X` as not
///     affected.
///
/// A `v`/`V` prefix is stripped so `Version::parse` accepts it. Text that names
/// no parseable version yields an empty (open) range, which the index loader's
/// [`crate::index::SerdeRange::to_range`] will reject loudly rather than
/// matching everything.
fn version_to_range(version: Option<&str>, kind: RangeKind) -> SerdeRange {
    let Some(raw) = version else {
        return SerdeRange {
            introduced: None,
            fixed: None,
        };
    };
    let text = raw.trim();
    let lower = text.to_ascii_lowercase();

    // "prior to X" / "before X" / "< X" => upper-bounded affected range.
    if let Some(v) = ["prior to", "before", "earlier than", "<"]
        .iter()
        .find_map(|kw| lower.split_once(kw).map(|(_, rest)| rest))
    {
        if let Some(clean) = clean_version(v) {
            return SerdeRange {
                introduced: None,
                fixed: Some(clean),
            };
        }
    }

    // A bare point version.
    if let Some(clean) = clean_version(text) {
        return match kind {
            RangeKind::Affected => SerdeRange {
                introduced: Some(clean),
                fixed: None,
            },
            RangeKind::Fixed => SerdeRange {
                introduced: None,
                fixed: Some(clean),
            },
        };
    }

    SerdeRange {
        introduced: None,
        fixed: None,
    }
}

/// Extract a clean, parseable dotted-numeric version from free text.
///
/// Handles the forms NVIDIA uses in CSAF version descriptors:
/// - a leading `v`/`V` (`v10.16.1` -> `10.16.1`),
/// - `CUDA Toolkit 11.6 Update 2` / `11.6 Update 2` -> `11.6.2` (an "Update N"
///   suffix becomes the next dotted component),
/// - surrounding words (`All versions prior to CUDA Toolkit 11.6` -> `11.6`).
///
/// Returns `None` when no dotted-numeric version is present.
fn clean_version(text: &str) -> Option<String> {
    let lower = text.to_ascii_lowercase();

    // Find the base dotted version. NVIDIA sometimes writes the update inline
    // as a compact `U<n>` suffix directly on the version token (e.g. `12.5U1`),
    // which we recover as a trailing patch component.
    let mut base: Option<String> = None;
    let mut inline_update: Option<u64> = None;
    for token in text.split_whitespace() {
        let token = token.trim_start_matches(['v', 'V']);
        // Skip any leading non-digit noise (e.g. "(" in "(12.4)").
        let Some(start) = token.find(|c: char| c.is_ascii_digit()) else {
            continue;
        };
        let token = &token[start..];
        // The leading dotted-numeric run (e.g. "12.5" in "12.5U1").
        let ver_len = token
            .find(|c: char| !c.is_ascii_digit() && c != '.')
            .unwrap_or(token.len());
        let ver_part = token[..ver_len].trim_end_matches('.');
        if !ver_part.contains('.') {
            continue;
        }
        base = Some(ver_part.to_string());
        // A compact `U<n>` update must directly follow the version run.
        if let Some(rest) = token[ver_len..].strip_prefix(['u', 'U']) {
            inline_update = rest
                .split(|c: char| !c.is_ascii_digit())
                .next()
                .filter(|s| !s.is_empty())
                .and_then(|s| s.parse::<u64>().ok());
        }
        break;
    }
    let base = base?;

    // A compact inline `U<n>` update takes precedence when present.
    if let Some(n) = inline_update {
        return Some(format!("{base}.{n}"));
    }

    // Otherwise an "Update N" word suffix refines the version to a patch
    // component. NVIDIA writes e.g. "11.6 Update 2", meaning 11.6.2.
    if let Some(rest) = lower.split("update").nth(1) {
        if let Some(n) = rest.split_whitespace().next().and_then(|tok| {
            tok.trim_matches(|c: char| !c.is_ascii_digit())
                .parse::<u64>()
                .ok()
        }) {
            return Some(format!("{base}.{n}"));
        }
    }

    Some(base)
}

/// Product id -> resolved name and optional version.
#[derive(Debug, Clone, Default)]
struct ProductInfo {
    name: String,
    version: Option<String>,
}

/// Walk a CSAF product tree, collecting product_id -> info.
///
/// NVIDIA CSAF places the `product_name` branch and the `product_version`
/// branches in *sibling* subtrees, linked only by a product-id naming
/// convention: a version's product id (e.g. `all_tensorrt_v10_16_1`) is
/// prefixed by its product-name id (`all_tensorrt`). Simple path inheritance
/// therefore cannot connect them, so this is a two-pass collection:
///
/// 1. gather product-name ids -> family name, and version ids -> (branch name,
///    version text), plus any path-inherited name/version, and
/// 2. for each version id, if its resolved name is weak (a vendor/grouping name
///    like "NVIDIA" or "All"), re-link it to the longest product-name id that is
///    a prefix of the version id.
fn collect_products(tree: &ProductTree) -> BTreeMap<String, ProductInfo> {
    let mut out = BTreeMap::new();

    for fpn in &tree.full_product_names {
        out.insert(
            fpn.product_id.clone(),
            ProductInfo {
                name: fpn.name.clone(),
                version: None,
            },
        );
    }

    // Product-name product ids -> family name, gathered from anywhere in the
    // tree, for the prefix-linking pass.
    let mut name_ids: BTreeMap<String, String> = BTreeMap::new();
    for branch in &tree.branches {
        collect_name_ids(branch, &mut name_ids);
    }

    for branch in &tree.branches {
        walk_branch(branch, None, None, &mut out);
    }

    // Re-link version products whose resolved name is a weak grouping label to
    // the product-name id that prefixes them.
    for (pid, info) in &mut out {
        if !is_weak_product_name(&info.name) {
            continue;
        }
        if let Some(best) = name_ids
            .iter()
            .filter(|(name_id, _)| pid.starts_with(name_id.as_str()) && pid.len() > name_id.len())
            .max_by_key(|(name_id, _)| name_id.len())
        {
            info.name.clone_from(best.1);
        }
    }

    out
}

/// Collect `product_name` branch product ids -> the branch (family) name.
fn collect_name_ids(branch: &Branch, out: &mut BTreeMap<String, String>) {
    if branch.category.as_deref() == Some("product_name") {
        if let Some(product) = &branch.product {
            out.insert(product.product_id.clone(), branch.name.clone());
        }
    }
    for child in &branch.branches {
        collect_name_ids(child, out);
    }
}

/// True if a product name is a generic grouping/vendor label rather than a real
/// product (so it should be re-linked via the product-id prefix).
fn is_weak_product_name(name: &str) -> bool {
    let n = name.trim();
    n.eq_ignore_ascii_case("nvidia")
        || n.eq_ignore_ascii_case("all")
        || n.eq_ignore_ascii_case("all platforms")
        || n.is_empty()
}

fn walk_branch(
    branch: &Branch,
    inherited_name: Option<&str>,
    inherited_version: Option<&str>,
    out: &mut BTreeMap<String, ProductInfo>,
) {
    // Track the family name and version seen along the path. A `product_name`
    // branch establishes the name; a `product_version` branch establishes the
    // version. Grouping branches (vendor, product_family, architecture, an
    // unlabeled "All", etc.) do not overwrite an established product name.
    //
    // Real NVIDIA CSAF uses two conventions for a `product_version` branch:
    //   (a) the branch `name` is the version (e.g. "12.4"), or
    //   (b) the branch `name` repeats the product and the inner `product.name`
    //       carries the version text (e.g. product.name = "v10.16.1").
    // We handle both: the version is taken from the inner product name when it
    // looks like a version, otherwise from the branch name; and for the family
    // name we prefer an established `product_name`, then a version branch's own
    // name, then the inherited name.
    let (name, version): (Option<&str>, Option<&str>) = match branch.category.as_deref() {
        Some("product_version") => {
            let version_from_product = branch
                .product
                .as_ref()
                .map(|p| p.name.as_str())
                .filter(|s| looks_like_version_text(s));
            let version = version_from_product.or(Some(branch.name.as_str()));
            // Keep an established product name; else use this branch's name only
            // if it is not itself the version we just took.
            let name = if inherited_name.is_some() {
                inherited_name
            } else if version_from_product.is_some() {
                Some(branch.name.as_str())
            } else {
                inherited_name
            };
            (name, version.or(inherited_version))
        }
        Some("product_name") => (Some(branch.name.as_str()), inherited_version),
        // vendor / family / grouping / unspecified: keep the inherited family
        // name; only adopt this branch's name if none has been seen yet.
        _ => (
            inherited_name.or(Some(branch.name.as_str())),
            inherited_version,
        ),
    };

    if let Some(product) = &branch.product {
        // The version leaf's own product.name is the version text, so it must
        // not be used as the component name; prefer the established/branch name.
        let resolved_name = name.unwrap_or(&product.name);
        out.insert(
            product.product_id.clone(),
            ProductInfo {
                name: resolved_name.to_string(),
                version: version.map(ToString::to_string),
            },
        );
    }

    for child in &branch.branches {
        walk_branch(child, name, version, out);
    }
}

/// Heuristic: does a string look like a version descriptor rather than a
/// product name? Matches things like `v10.16.1`, `12.4`, or
/// `All versions prior to v10.16.1`. Used to tell apart the two NVIDIA CSAF
/// `product_version` conventions.
fn looks_like_version_text(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    if lower.contains("version") || lower.contains("prior to") || lower.contains("all ") {
        return true;
    }
    // A token like "v10.16.1" or "10.16.1": starts with optional 'v' then a
    // digit, and contains a dot.
    let trimmed = s.trim().trim_start_matches(['v', 'V']);
    trimmed.chars().next().is_some_and(|c| c.is_ascii_digit()) && trimmed.contains('.')
}

// --- CSAF serde model (the subset we parse) ----------------------------------
//
// Unknown fields are ignored (no `deny_unknown_fields`): CSAF documents carry
// far more than we model, and we must tolerate it.

#[derive(Debug, Deserialize)]
struct CsafDocument {
    document: Option<DocumentMeta>,
    product_tree: Option<ProductTree>,
    #[serde(default)]
    vulnerabilities: Vec<Vulnerability>,
}

#[derive(Debug, Deserialize)]
struct DocumentMeta {
    aggregate_severity: Option<AggregateSeverity>,
    tracking: Option<Tracking>,
}

#[derive(Debug, Deserialize)]
struct Tracking {
    /// The date the advisory was first released. CSAF requires RFC 3339.
    #[serde(default)]
    initial_release_date: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AggregateSeverity {
    text: String,
}

#[derive(Debug, Default, Deserialize)]
struct ProductTree {
    #[serde(default)]
    full_product_names: Vec<FullProductName>,
    #[serde(default)]
    branches: Vec<Branch>,
}

#[derive(Debug, Deserialize)]
struct FullProductName {
    product_id: String,
    name: String,
}

#[derive(Debug, Deserialize)]
struct Branch {
    #[serde(default)]
    category: Option<String>,
    #[serde(default)]
    name: String,
    #[serde(default)]
    product: Option<ProductRef>,
    #[serde(default)]
    branches: Vec<Branch>,
}

#[derive(Debug, Deserialize)]
struct ProductRef {
    product_id: String,
    #[serde(default)]
    name: String,
}

#[derive(Debug, Deserialize)]
struct Vulnerability {
    #[serde(default)]
    cve: Option<String>,
    #[serde(default)]
    ids: Vec<VulnId>,
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    notes: Vec<Note>,
    #[serde(default)]
    scores: Vec<Score>,
    #[serde(default)]
    references: Vec<Reference>,
    #[serde(default)]
    product_status: ProductStatus,
}

impl Vulnerability {
    /// The advisory id: prefer the CVE, else the first tracking id.
    fn effective_id(&self) -> Option<String> {
        if let Some(cve) = &self.cve {
            return Some(cve.clone());
        }
        self.ids.first().map(|i| i.text.clone())
    }

    /// The best human-readable description from the notes: prefer a
    /// `description`, then `summary`, then `general`; fall back to the first
    /// note with text. Whitespace-trimmed; `None` if no note has text.
    fn description(&self) -> Option<String> {
        let pick = |category: &str| {
            self.notes
                .iter()
                .find(|n| n.category.as_deref() == Some(category) && !n.text.trim().is_empty())
        };
        pick("description")
            .or_else(|| pick("summary"))
            .or_else(|| pick("general"))
            .or_else(|| self.notes.iter().find(|n| !n.text.trim().is_empty()))
            .map(|n| n.text.trim().to_string())
    }

    /// The highest CVSS base score across the vulnerability's `scores` entries
    /// (CSAF stores CVSS v2/v3/v4 objects under `cvss_v*`). `None` when no
    /// numeric base score is present.
    fn cvss_base_score(&self) -> Option<f64> {
        self.scores
            .iter()
            .filter_map(Score::base_score)
            .reduce(f64::max)
    }

    /// Reference URLs for this vulnerability: the CSAF `references[].url`
    /// entries, plus the canonical NVD page for a CVE id (always derivable,
    /// never invented). Deduplicated and sorted for deterministic output.
    fn references(&self) -> Vec<String> {
        let mut urls: BTreeSet<String> = self
            .references
            .iter()
            .filter_map(|r| {
                let url = r.url.trim();
                (!url.is_empty()).then(|| url.to_string())
            })
            .collect();
        // A CVE id has a canonical, deterministic NVD detail page. Add it so a
        // report always has at least one authoritative link for a CVE, even
        // when the bulletin carried no explicit reference URLs.
        if let Some(cve) = &self.cve {
            let cve = cve.trim();
            if cve.starts_with("CVE-") {
                urls.insert(format!("https://nvd.nist.gov/vuln/detail/{cve}"));
            }
        }
        urls.into_iter().collect()
    }
}

#[derive(Debug, Deserialize)]
struct Note {
    #[serde(default)]
    category: Option<String>,
    #[serde(default)]
    text: String,
}

/// A CSAF `references[]` entry. Only the URL is used.
#[derive(Debug, Deserialize)]
struct Reference {
    #[serde(default)]
    url: String,
}

/// A CSAF `scores[]` entry. CVSS objects appear under version-specific keys
/// (`cvss_v2`, `cvss_v3`, `cvss_v4`), each carrying a `baseScore`. The shared
/// `cvss_` prefix mirrors the CSAF schema keys exactly, so it is kept.
#[allow(clippy::struct_field_names)]
#[derive(Debug, Deserialize)]
struct Score {
    #[serde(default)]
    cvss_v4: Option<Cvss>,
    #[serde(default)]
    cvss_v3: Option<Cvss>,
    #[serde(default)]
    cvss_v2: Option<Cvss>,
}

impl Score {
    /// The base score from the highest CVSS version present in this entry.
    fn base_score(&self) -> Option<f64> {
        self.cvss_v4
            .as_ref()
            .or(self.cvss_v3.as_ref())
            .or(self.cvss_v2.as_ref())
            .and_then(|c| c.base_score)
    }
}

#[derive(Debug, Deserialize)]
struct Cvss {
    #[serde(rename = "baseScore", default)]
    base_score: Option<f64>,
}

#[derive(Debug, Deserialize)]
struct VulnId {
    text: String,
}

#[derive(Debug, Default, Deserialize)]
struct ProductStatus {
    #[serde(default)]
    known_affected: Vec<String>,
    #[serde(default)]
    fixed: Vec<String>,
    #[serde(default)]
    known_not_affected: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map() -> ProductMap {
        let json = r#"{
            "schema_version": 1,
            "exact": {},
            "rules": [ { "contains": "cuda runtime", "component": "cudart" } ]
        }"#;
        ProductMap::from_json(json.as_bytes()).unwrap()
    }

    /// A CSAF document with a versioned product and one affected CVE.
    fn csaf_full_product_names() -> Vec<u8> {
        br#"{
            "document": { "aggregate_severity": { "text": "high" } },
            "product_tree": {
                "full_product_names": [
                    { "product_id": "P1", "name": "NVIDIA CUDA Runtime" }
                ]
            },
            "vulnerabilities": [
                {
                    "cve": "CVE-2025-1234",
                    "title": "Example",
                    "product_status": { "known_affected": ["P1"] }
                }
            ]
        }"#
        .to_vec()
    }

    #[test]
    fn ingests_full_product_names() {
        let out = ingest(&[csaf_full_product_names()], &map(), Some("abc".into())).unwrap();
        assert_eq!(out.index.advisories.len(), 1);
        let adv = &out.index.advisories[0];
        assert_eq!(adv.id, "CVE-2025-1234");
        assert_eq!(adv.severity.as_deref(), Some("high"));
        assert_eq!(adv.affected[0].component, "cudart");
        assert_eq!(out.index.source_commit.as_deref(), Some("abc"));
        assert!(
            out.unmapped.is_empty(),
            "every product mapped, so nothing is unmapped"
        );
    }

    #[test]
    fn extracts_published_description_and_cvss() {
        let csaf = br#"{
            "document": {
                "aggregate_severity": { "text": "critical" },
                "tracking": { "initial_release_date": "2024-04-03T00:00:00Z" }
            },
            "product_tree": {
                "full_product_names": [ { "product_id": "P1", "name": "NVIDIA CUDA Runtime" } ]
            },
            "vulnerabilities": [
                {
                    "cve": "CVE-2024-9999",
                    "notes": [
                        { "category": "summary", "text": "short summary" },
                        { "category": "description", "text": "  A heap overflow in cudart.  " }
                    ],
                    "scores": [
                        { "cvss_v3": { "baseScore": 7.5 } },
                        { "cvss_v3": { "baseScore": 9.1 } }
                    ],
                    "product_status": { "known_affected": ["P1"] }
                }
            ]
        }"#
        .to_vec();
        let out = ingest(&[csaf], &map(), None).unwrap();
        let adv = &out.index.advisories[0];
        assert_eq!(adv.published.as_deref(), Some("2024-04-03T00:00:00Z"));
        // The `description` note is preferred over `summary`, trimmed.
        assert_eq!(
            adv.description.as_deref(),
            Some("A heap overflow in cudart.")
        );
        // The highest base score across entries wins.
        assert_eq!(adv.cvss_score, Some(9.1));
    }

    #[test]
    fn extracts_references_and_adds_nvd_fallback() {
        // CSAF carries explicit reference URLs; the canonical NVD page for the
        // CVE id is added, and the result is deduplicated and sorted.
        let csaf = br#"{
            "product_tree": {
                "full_product_names": [ { "product_id": "P1", "name": "NVIDIA CUDA Runtime" } ]
            },
            "vulnerabilities": [
                {
                    "cve": "CVE-2024-9999",
                    "references": [
                        { "url": "https://nvidia.custhelp.com/app/answers/detail/a_id/5555" },
                        { "url": "https://nvidia.custhelp.com/app/answers/detail/a_id/5555" }
                    ],
                    "product_status": { "known_affected": ["P1"] }
                }
            ]
        }"#
        .to_vec();
        let out = ingest(&[csaf], &map(), None).unwrap();
        let adv = &out.index.advisories[0];
        assert_eq!(
            adv.references,
            vec![
                "https://nvd.nist.gov/vuln/detail/CVE-2024-9999".to_string(),
                "https://nvidia.custhelp.com/app/answers/detail/a_id/5555".to_string(),
            ],
            "explicit bulletin url plus the canonical NVD page, deduped and sorted"
        );
    }

    #[test]
    fn nvd_fallback_present_even_without_csaf_references() {
        let csaf = br#"{
            "product_tree": {
                "full_product_names": [ { "product_id": "P1", "name": "NVIDIA CUDA Runtime" } ]
            },
            "vulnerabilities": [
                { "cve": "CVE-2025-0001", "product_status": { "known_affected": ["P1"] } }
            ]
        }"#
        .to_vec();
        let out = ingest(&[csaf], &map(), None).unwrap();
        assert_eq!(
            out.index.advisories[0].references,
            vec!["https://nvd.nist.gov/vuln/detail/CVE-2025-0001".to_string()]
        );
    }

    #[test]
    fn enrichment_is_optional() {
        // A bulletin with no tracking/notes/scores yields None for each, not an
        // error, and still produces the advisory.
        let out = ingest(&[csaf_full_product_names()], &map(), None).unwrap();
        let adv = &out.index.advisories[0];
        assert!(adv.published.is_none());
        assert!(adv.description.is_none());
        assert!(adv.cvss_score.is_none());
    }

    #[test]
    fn ingests_version_branches() {
        let csaf = br#"{
            "product_tree": {
                "branches": [
                    {
                        "category": "product_name",
                        "name": "NVIDIA CUDA Runtime",
                        "branches": [
                            {
                                "category": "product_version",
                                "name": "12.3",
                                "product": { "product_id": "P9", "name": "cudart 12.3" }
                            }
                        ]
                    }
                ]
            },
            "vulnerabilities": [
                { "cve": "CVE-2025-2000", "product_status": { "known_affected": ["P9"] } }
            ]
        }"#
        .to_vec();
        let out = ingest(&[csaf], &map(), None).unwrap();
        let adv = &out.index.advisories[0];
        assert_eq!(adv.affected[0].component, "cudart");
        // The version from the product_version branch is recorded.
        assert_eq!(
            adv.affected[0].affected_ranges[0].introduced.as_deref(),
            Some("12.3")
        );
    }

    #[test]
    fn unmapped_products_are_reported_not_dropped() {
        let csaf = br#"{
            "product_tree": {
                "full_product_names": [ { "product_id": "P1", "name": "Totally Unknown Product" } ]
            },
            "vulnerabilities": [
                { "cve": "CVE-2025-3000", "product_status": { "known_affected": ["P1"] } }
            ]
        }"#
        .to_vec();
        let out = ingest(&[csaf], &map(), None).unwrap();
        // No mappable component -> no advisory emitted, but the product is
        // recorded as unmapped.
        assert!(
            out.index.advisories.is_empty(),
            "an unmappable product emits no advisory"
        );
        assert_eq!(out.unmapped, vec!["Totally Unknown Product".to_string()]);
    }

    #[test]
    fn uses_tracking_id_when_no_cve() {
        let csaf = br#"{
            "product_tree": { "full_product_names": [ { "product_id": "P1", "name": "NVIDIA CUDA Runtime" } ] },
            "vulnerabilities": [
                { "ids": [ { "text": "NVIDIA-2025-01" } ], "product_status": { "known_affected": ["P1"] } }
            ]
        }"#
        .to_vec();
        let out = ingest(&[csaf], &map(), None).unwrap();
        assert_eq!(out.index.advisories[0].id, "NVIDIA-2025-01");
    }

    #[test]
    fn unknown_product_id_reference_is_recorded() {
        let csaf = br#"{
            "product_tree": { "full_product_names": [] },
            "vulnerabilities": [
                { "cve": "CVE-2025-4000", "product_status": { "known_affected": ["MISSING"] } }
            ]
        }"#
        .to_vec();
        let out = ingest(&[csaf], &map(), None).unwrap();
        assert!(
            out.index.advisories.is_empty(),
            "a MISSING product mapping emits no advisory"
        );
        assert_eq!(out.unmapped, vec!["MISSING".to_string()]);
    }

    #[test]
    fn rejects_invalid_json() {
        assert!(matches!(
            ingest(&[b"not json".to_vec()], &map(), None),
            Err(CsafError::Parse(_))
        ));
    }

    #[test]
    fn multiple_documents_sorted_by_id() {
        let a = br#"{ "product_tree": { "full_product_names": [ { "product_id": "P1", "name": "NVIDIA CUDA Runtime" } ] }, "vulnerabilities": [ { "cve": "CVE-B", "product_status": { "known_affected": ["P1"] } } ] }"#.to_vec();
        let b = br#"{ "product_tree": { "full_product_names": [ { "product_id": "P1", "name": "NVIDIA CUDA Runtime" } ] }, "vulnerabilities": [ { "cve": "CVE-A", "product_status": { "known_affected": ["P1"] } } ] }"#.to_vec();
        let out = ingest(&[a, b], &map(), None).unwrap();
        assert_eq!(out.index.advisories[0].id, "CVE-A");
        assert_eq!(out.index.advisories[1].id, "CVE-B");
    }

    /// The real NVIDIA CSAF shape: the `product_name` branch and the
    /// `product_version` branches live in *sibling* subtrees, linked only by a
    /// product-id prefix, and the version text sits in the leaf `product.name`
    /// (e.g. `v10.16.1`). Verifies the two-pass prefix re-linking and version
    /// descriptor parsing.
    #[test]
    fn ingests_real_nvidia_sibling_product_tree() {
        let map = ProductMap::from_json(
            br#"{ "schema_version": 1, "exact": {}, "rules": [ { "contains": "tensorrt", "component": "tensorrt" } ] }"#,
        )
        .unwrap();
        let csaf = br#"{
            "document": { "aggregate_severity": { "text": "HIGH" } },
            "product_tree": { "branches": [
                { "category": "vendor", "name": "NVIDIA", "branches": [
                    { "category": "product_family", "name": "NVIDIA Product Family", "branches": [
                        { "category": "product_name", "name": "TensorRT",
                          "product": { "product_id": "all_tensorrt", "name": "TensorRT" } }
                    ] },
                    { "category": "architecture", "name": "All", "branches": [
                        { "category": "product_version", "name": "TensorRT",
                          "product": { "product_id": "all_tensorrt_prior_10_16_1", "name": "All versions prior to v10.16.1" } },
                        { "category": "product_version", "name": "TensorRT",
                          "product": { "product_id": "all_tensorrt_v10_16_1", "name": "v10.16.1" } }
                    ] }
                ] }
            ] },
            "vulnerabilities": [
                { "cve": "CVE-2026-24188", "product_status": {
                    "known_affected": ["all_tensorrt_prior_10_16_1"],
                    "fixed": ["all_tensorrt_v10_16_1"]
                } }
            ]
        }"#
        .to_vec();

        let out = ingest(&[csaf], &map, None).unwrap();
        assert_eq!(out.index.advisories.len(), 1, "one advisory expected");
        let adv = &out.index.advisories[0];
        assert_eq!(adv.id, "CVE-2026-24188");
        assert_eq!(adv.affected.len(), 1);
        let comp = &adv.affected[0];
        // The version leaves were re-linked to the sibling product_name.
        assert_eq!(comp.component, "tensorrt");
        // "All versions prior to v10.16.1" -> affected range upper-bounded at 10.16.1.
        assert_eq!(comp.affected_ranges[0].fixed.as_deref(), Some("10.16.1"));
        // The fix version `v10.16.1` -> fixed at 10.16.1 (v-prefix stripped).
        assert_eq!(comp.fixed_ranges[0].fixed.as_deref(), Some("10.16.1"));
        assert!(out.unmapped.is_empty(), "no unmapped products expected");
    }

    #[test]
    fn version_descriptor_parsing() {
        // "prior to" phrasing -> upper bound.
        let r = version_to_range(Some("All versions prior to v10.16.1"), RangeKind::Affected);
        assert_eq!(r.fixed.as_deref(), Some("10.16.1"));
        assert_eq!(r.introduced, None);
        // Bare point version on the affected side -> introduced.
        let r = version_to_range(Some("v12.4"), RangeKind::Affected);
        assert_eq!(r.introduced.as_deref(), Some("12.4"));
        // Bare point version on the fixed side -> fixed.
        let r = version_to_range(Some("12.4.1"), RangeKind::Fixed);
        assert_eq!(r.fixed.as_deref(), Some("12.4.1"));
        // Non-version text -> open range (rejected downstream, matches nothing).
        let r = version_to_range(Some("All"), RangeKind::Affected);
        assert_eq!(r.introduced, None);
        assert_eq!(r.fixed, None);
    }

    #[test]
    fn update_suffix_becomes_patch_component() {
        // NVIDIA CUDA Toolkit versions carry an "Update N" that maps to a patch.
        assert_eq!(clean_version("11.6 Update 2").as_deref(), Some("11.6.2"));
        assert_eq!(
            clean_version("CUDA Toolkit 11.6 Update 2").as_deref(),
            Some("11.6.2")
        );
        // "prior to ... Update 2" flows through version_to_range as an upper bound.
        let r = version_to_range(
            Some("All versions prior to CUDA Toolkit 11.6 Update 2"),
            RangeKind::Affected,
        );
        assert_eq!(r.fixed.as_deref(), Some("11.6.2"));
        // The fixed branch "11.6 Update 2" becomes the fixed bound 11.6.2.
        let r = version_to_range(Some("11.6 Update 2"), RangeKind::Fixed);
        assert_eq!(r.fixed.as_deref(), Some("11.6.2"));
    }

    #[test]
    fn clean_version_handles_leading_v_and_no_dot() {
        assert_eq!(clean_version("v12.4.131").as_deref(), Some("12.4.131"));
        // No dotted version present -> None.
        assert_eq!(clean_version("All versions"), None);
        assert_eq!(clean_version("12"), None);
    }

    #[test]
    fn clean_version_handles_compact_update_suffix() {
        // NVIDIA's compact `U<n>` inline form: 12.5U1 -> 12.5.1.
        assert_eq!(clean_version("12.5U1").as_deref(), Some("12.5.1"));
        assert_eq!(clean_version("12.6u1").as_deref(), Some("12.6.1"));
        let r = version_to_range(Some("12.5U1"), RangeKind::Affected);
        assert_eq!(r.introduced.as_deref(), Some("12.5.1"));
        // A plain three-part version with no update is untouched.
        assert_eq!(clean_version("12.4.127").as_deref(), Some("12.4.127"));
        // A `u`/`U` not followed by digits is not an update separator: the base
        // version is still recovered and no spurious patch component is added.
        assert_eq!(clean_version("12.5Update").as_deref(), Some("12.5"));
        assert_eq!(clean_version("12.4ubuntu").as_deref(), Some("12.4"));
    }

    #[test]
    fn weak_product_names_are_recognized() {
        assert!(is_weak_product_name("NVIDIA"));
        assert!(is_weak_product_name("all"));
        assert!(is_weak_product_name(""));
        assert!(!is_weak_product_name("TensorRT"));
        assert!(!is_weak_product_name("cuDNN"));
    }
}
