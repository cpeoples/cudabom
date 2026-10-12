//! `cargo xtask product-map`: generate `advisories/product-map.json` from the
//! reviewed component profiles.
//!
//! The CSAF product → component mapping is *derived*, not hand-maintained. Its
//! substring rules come from three sources, combined deterministically:
//!
//! 1. [`MANUAL_RULES`]: a small, reviewed seed of mappings that have **no**
//!    fingerprint component profile: toolkit/driver umbrellas (`cuda-toolkit`,
//!    `cuda-driver`) and sibling products not yet profiled in the identify
//!    crate (`cudnn`, `nccl`, `tensorrt`). These are facts about advisory
//!    vocabulary, kept here until/unless a matching profile exists.
//! 2. [`cudabom_identify::advisory_terms`]: the `(term, component)` pairs
//!    carried by the reviewed component profiles, so every profiled component
//!    contributes its advisory vocabulary automatically. Adding a component in
//!    `derive.rs` therefore updates fingerprint attribution *and* advisory
//!    matching from one edit.
//! 3. **Auto-derived (Model B) components in the shards**: components that were
//!    minted dynamically from an archive's `.so`/`.dll` (e.g. `nvtx`,
//!    `sanitizer_api`) have no reviewed profile and so contribute nothing via
//!    source 2, which would leave them *fingerprinted but un-advisable* (a
//!    scan identifies them, but no CVE/CSAF ever resolves to them). To close
//!    that gap, the generator reads the committed shard tree and emits a
//!    `{ contains: <name>, component: <name> }` rule for each shard component
//!    not already covered, using the component's own name as its advisory term
//!    (exactly what [`cudabom_identify::auto_identity`] returns). This keeps
//!    advisory coverage dynamic: a newly auto-derived component becomes
//!    advisable in the same refresh PR that first fingerprints it.
//!
//! The sources are merged with the manual seed first (so umbrella rules like
//! `cuda toolkit` stay ahead of narrower ones), then profile-derived rules,
//! then auto-derived shard rules, with duplicate `contains` substrings dropped
//! (first occurrence wins). The result is rendered as stable, pretty JSON
//! matching the committed file byte-for-byte.
//!
//! Modes:
//!   - `--check` (default): regenerate in memory and compare to the committed
//!     file; exit non-zero if they differ, printing a unified-style hint. Wired
//!     into CI and pre-commit so the map can never silently drift from the
//!     profiles.
//!   - `--write`: regenerate and write the file. Run locally after adding a
//!     component, and in the nightly refresh so the regenerated map rides along
//!     in the same review PR as new shards.

use std::fmt::Write as _;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};

use crate::verbosity::status;
use crate::{flag, has_flag};

/// Default output path for the generated product map.
const DEFAULT_OUT: &str = "advisories/product-map.json";

/// Root directory holding the committed fingerprint shards (per-product
/// subdirectories). Auto-derived components (Model B) exist only in the shards,
/// not in the reviewed [`cudabom_identify::advisory_terms`] table, so the
/// generator reads this tree to contribute their advisory vocabulary. Kept
/// relative to the repo root (xtask runs from `<root>/xtask` under cargo but
/// the CLI/CI run from `<root>`); resolved via [`shard_root`].
const DEFAULT_SHARD_ROOT: &str = "fingerprints";

/// The product-map schema version this generator emits. Single-sourced from the
/// loader's constant so the generator and reader can never disagree.
const SCHEMA_VERSION: u32 = cudabom_advisory::ProductMap::CURRENT_SCHEMA;

/// Reviewed substring rules that have no fingerprint component profile.
///
/// These are advisory-vocabulary facts for products cudabom reasons about but
/// that are either umbrellas spanning many libraries (`cuda-toolkit`,
/// `cuda-driver`) or products with no [`cudabom_identify`] component profile
/// (`tensorrt`, which is not published as a redist tree cudabom ingests). When
/// a profile is later added for one of these, its term moves into `derive.rs`
/// and is removed here (de-duplication keeps the first occurrence, so a
/// lingering duplicate is harmless, but the seed should stay minimal).
///
/// Order is significant: umbrella/most-specific rules first. `cuda runtime`
/// (cudart) is intentionally **not** here; it is contributed by the `cudart`
/// profile; but `cuda toolkit` must precede any bare `cuda` style match.
const MANUAL_RULES: &[(&str, &str)] = &[
    ("cuda toolkit", "cuda-toolkit"),
    ("tensorrt", "tensorrt"),
    ("cuda driver", "cuda-driver"),
];

/// `product-map [--check | --write] [--out <file>] [--shards <dir>]`
pub(crate) fn run(args: &[String]) -> Result<()> {
    let out = PathBuf::from(flag(args, "--out").unwrap_or_else(|| DEFAULT_OUT.to_string()));
    let shard_root = shard_root(flag(args, "--shards"));
    let write = has_flag(args, "--write");
    // --check is the safe default so a bare invocation never mutates the tree.
    let check = has_flag(args, "--check") || !write;

    let generated = render(&shard_root);

    if write {
        if let Some(parent) = out.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        std::fs::write(&out, &generated).with_context(|| format!("writing {}", out.display()))?;
        status!("xtask: wrote {}", out.display());
        return Ok(());
    }

    if check {
        let existing = std::fs::read_to_string(&out).with_context(|| {
            format!(
                "reading {} (run `cargo xtask product-map --write`)",
                out.display()
            )
        })?;
        if existing == generated {
            status!(
                "xtask: {} is up to date with the component profiles",
                out.display()
            );
            return Ok(());
        }
        bail!(
            "{} is out of sync with the component profiles.\n\
             Run `cargo xtask product-map --write` and commit the result.\n\
             (The map is generated from advisory_terms in \
             crates/cudabom-identify/src/derive.rs, the MANUAL_RULES seed, \
             and auto-derived components in the fingerprints/ shards.)",
            out.display()
        );
    }

    Ok(())
}

/// Build the ordered, de-duplicated rule list: manual seed first, then
/// profile-derived terms, then auto-derived shard-component terms, dropping any
/// `contains` substring already seen.
///
/// After collection, rules are reordered so that whenever one rule's `contains`
/// is a substring of another's, the longer (more specific) rule comes first.
/// Matching is first-wins substring, so without this a short rule (`nvjpeg`)
/// would shadow a more specific one (`nvjpeg2000`) and misattribute its
/// advisories. The reordering is a stable partial sort: rules not in a
/// substring relationship keep their original (profile/seed) order.
fn ordered_rules(shard_root: &std::path::Path) -> Vec<(String, String)> {
    let mut seen = std::collections::BTreeSet::new();
    let mut rules = Vec::new();
    let push = |rules: &mut Vec<(String, String)>,
                seen: &mut std::collections::BTreeSet<String>,
                contains: &str,
                component: &str| {
        let key = normalize(contains);
        if seen.insert(key) {
            rules.push((contains.to_string(), component.to_string()));
        }
    };
    for (contains, component) in MANUAL_RULES {
        push(&mut rules, &mut seen, contains, component);
    }
    for (contains, component) in cudabom_identify::advisory_terms() {
        push(&mut rules, &mut seen, contains, component);
    }
    // Auto-derived (Model B) components: contribute `{ name -> name }` for each
    // shard component with no reviewed profile. `push`'s dedup drops any whose
    // normalized name a manual/profile rule already covers, so a profiled
    // component is never double-listed and `nvpl-blas` (covered by the `nvpl
    // blas` profile term, different normalization) is not re-emitted here.
    for (contains, component) in auto_component_rules(shard_root) {
        push(&mut rules, &mut seen, &contains, &component);
    }
    sort_by_specificity(&mut rules);
    rules
}

/// Resolve the shard tree root: an explicit `--shards <dir>`, else the repo's
/// committed [`DEFAULT_SHARD_ROOT`]. The generator (CLI/CI) runs from the repo
/// root, so the default relative path is correct there; the unit tests pass an
/// explicit temp dir.
fn shard_root(flag: Option<String>) -> PathBuf {
    flag.map_or_else(|| PathBuf::from(DEFAULT_SHARD_ROOT), PathBuf::from)
}

/// Advisory rules for auto-derived (Model B) components found in the shards.
///
/// Loads the merged shard DB under `shard_root` and returns a
/// `(contains, component)` pair for every component whose name is NOT a
/// reviewed profile component (those already contribute via `advisory_terms`).
/// The pair is `(name, name)`: the component's own name is its advisory term,
/// matching [`cudabom_identify::auto_identity`]. Sorted by name
/// for deterministic output; a missing/empty shard tree yields no rules (so the
/// generator still works on a tree with no shards yet).
///
/// REVIEWER NOTE: the term is a *substring* rule (first-wins), so a very short
/// auto name (e.g. `cal` from `libcal`) is a broad match that could catch an
/// unrelated CSAF product string. This is intentionally left to the nightly
/// refresh PR's human review (the same PR that first introduces the component),
/// rather than silently dropped or widened, keeping the mapping an explicit,
/// reviewable fact. `sort_by_specificity` still orders any substring-related
/// terms longest-first so a short term never shadows a more specific one.
fn auto_component_rules(shard_root: &std::path::Path) -> Vec<(String, String)> {
    let profiled: std::collections::BTreeSet<String> = cudabom_identify::advisory_terms()
        .into_iter()
        .map(|(_, component)| component.to_string())
        .collect();

    let Ok((db, _report)) = cudabom_identify::FingerprintDb::from_dir(shard_root) else {
        return Vec::new(); // unreadable tree: contribute nothing
    };

    let mut names: Vec<String> = db
        .components
        .into_iter()
        .map(|c| c.name)
        .filter(|name| !profiled.contains(name))
        .collect();
    names.sort();
    names.dedup();
    names.into_iter().map(|name| (name.clone(), name)).collect()
}

/// Stable-reorder rules so a rule whose `contains` is a substring of another's
/// never precedes that longer rule. Matching is first-wins substring, so this
/// prevents a short rule (`nvjpeg`) from shadowing a more specific one
/// (`nvjpeg2000`).
///
/// Implemented as a deterministic topological-style pass rather than
/// `slice::sort_by`, because the substring relation is a partial order (not a
/// total one) and feeding a non-total comparator to a general sort is
/// incorrect. For each output slot we pick, from the remaining rules, the first
/// one that is not a strict substring of any other remaining rule: i.e. a
/// current "maximal" element, preserving original order among unrelated rules.
fn sort_by_specificity(rules: &mut Vec<(String, String)>) {
    let normalized: Vec<String> = rules.iter().map(|(c, _)| normalize(c)).collect();
    let n = rules.len();
    let mut taken = vec![false; n];
    let mut order: Vec<usize> = Vec::with_capacity(n);
    for _ in 0..n {
        // The next rule is the earliest remaining one that is not a strict
        // substring of any other remaining rule (so supersets are emitted
        // first). "Strict" = different text but contained.
        let mut pick = None;
        for i in 0..n {
            if taken[i] {
                continue;
            }
            let shadowed = (0..n).any(|j| {
                !taken[j]
                    && j != i
                    && normalized[j] != normalized[i]
                    && normalized[j].contains(&normalized[i])
            });
            if !shadowed {
                pick = Some(i);
                break;
            }
        }
        // `pick` is always Some: a longest remaining rule can never be a strict
        // substring of another remaining rule.
        let idx = pick.unwrap_or_else(|| taken.iter().position(|t| !t).unwrap());
        taken[idx] = true;
        order.push(idx);
    }
    let reordered: Vec<(String, String)> = order.into_iter().map(|i| rules[i].clone()).collect();
    *rules = reordered;
}

/// Render the product map as stable, pretty JSON matching the committed file.
///
/// Hand-rolled rather than via `serde_json::to_string_pretty` so the exact
/// formatting (2-space indent, one rule per line, trailing newline) is pinned
/// and reviewable, independent of serde's pretty-printer defaults.
fn render(shard_root: &std::path::Path) -> String {
    let rules = ordered_rules(shard_root);
    let mut s = String::new();
    s.push_str("{\n");
    let _ = writeln!(s, "  \"schema_version\": {SCHEMA_VERSION},");
    s.push_str("  \"exact\": {},\n");
    s.push_str("  \"rules\": [\n");
    for (i, (contains, component)) in rules.iter().enumerate() {
        let comma = if i + 1 < rules.len() { "," } else { "" };
        let _ = writeln!(
            s,
            "    {{ \"contains\": {}, \"component\": {} }}{comma}",
            json_string(contains),
            json_string(component),
        );
    }
    s.push_str("  ]\n");
    s.push_str("}\n");
    s
}

/// Encode a string as a JSON string literal (handles the characters that can
/// appear in advisory terms: quotes and backslashes). Advisory terms are ASCII
/// product substrings, so this minimal escaping is sufficient and keeps output
/// identical to the committed file.
fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            _ => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Normalize a substring for duplicate detection: lowercase, collapse
/// whitespace. Mirrors `cudabom_advisory::product_map::normalize` so dedup
/// matches the runtime matcher's own normalization.
fn normalize(s: &str) -> String {
    s.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The repo-root `fingerprints/` shard tree, resolved relative to this
    /// crate (`xtask` lives at `<root>/xtask`). The real committed shards are
    /// the generator's third input, so tests that assert the committed map or
    /// profile-term presence must use the same tree the CLI/CI use.
    fn repo_shard_root() -> PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join(DEFAULT_SHARD_ROOT)
    }

    #[test]
    fn manual_rules_come_before_profile_rules() {
        let rules = ordered_rules(&repo_shard_root());
        let toolkit = rules.iter().position(|(c, _)| c == "cuda toolkit");
        let cudart = rules.iter().position(|(c, _)| c == "cuda runtime");
        assert!(toolkit.is_some(), "manual umbrella rule present");
        assert!(cudart.is_some(), "profile-derived cudart term present");
        assert!(
            toolkit < cudart,
            "manual seed must precede profile-derived rules"
        );
    }

    #[test]
    fn more_specific_substring_rules_come_first() {
        // `nvjpeg2000` must precede `nvjpeg` so an "nvJPEG2000" advisory is not
        // shadowed by the shorter `nvjpeg` rule (first-wins substring matching).
        let rules = ordered_rules(&repo_shard_root());
        let pos = |needle: &str| rules.iter().position(|(c, _)| c == needle);
        let nvjpeg = pos("nvjpeg").expect("nvjpeg rule present");
        let nvjpeg2000 = pos("nvjpeg2000").expect("nvjpeg2000 rule present");
        let nvjpeg2k = pos("nvjpeg2k").expect("nvjpeg2k rule present");
        assert!(nvjpeg2000 < nvjpeg, "nvjpeg2000 must precede nvjpeg");
        assert!(nvjpeg2k < nvjpeg, "nvjpeg2k must precede nvjpeg");
    }

    #[test]
    fn specificity_pass_orders_substrings_before_shorter_rules() {
        // Direct unit of the reordering: `ab` is a substring of `abc`, so the
        // superset `abc` must come first; the unrelated `xy` keeps its place.
        let mut rules = vec![
            ("ab".to_string(), "c1".to_string()),
            ("xy".to_string(), "c2".to_string()),
            ("abc".to_string(), "c3".to_string()),
        ];
        sort_by_specificity(&mut rules);
        let order: Vec<&str> = rules.iter().map(|(c, _)| c.as_str()).collect();
        let ab = order.iter().position(|&c| c == "ab").unwrap();
        let abc = order.iter().position(|&c| c == "abc").unwrap();
        assert!(abc < ab, "superset abc before substring ab");
    }

    #[test]
    fn rules_are_deduplicated_by_normalized_contains() {
        let rules = ordered_rules(&repo_shard_root());
        let mut seen = std::collections::BTreeSet::new();
        for (contains, _) in &rules {
            assert!(
                seen.insert(normalize(contains)),
                "duplicate contains rule: {contains}"
            );
        }
    }

    #[test]
    fn every_profiled_component_term_is_present() {
        let rules = ordered_rules(&repo_shard_root());
        for (term, _component) in cudabom_identify::advisory_terms() {
            assert!(
                rules.iter().any(|(c, _)| normalize(c) == normalize(term)),
                "profile term missing from generated rules: {term}"
            );
        }
    }

    #[test]
    fn rendered_json_parses_and_round_trips_stably() {
        let a = render(&repo_shard_root());
        // Must be valid JSON.
        let value: serde_json::Value = serde_json::from_str(&a).unwrap();
        assert_eq!(value["schema_version"], SCHEMA_VERSION);
        assert!(value["rules"].as_array().unwrap().len() >= MANUAL_RULES.len());
        // Deterministic: rendering twice yields identical bytes.
        assert_eq!(a, render(&repo_shard_root()));
        // Ends with a single trailing newline.
        assert!(a.ends_with("}\n"));
    }

    #[test]
    fn json_string_escapes_quotes_and_backslashes() {
        assert_eq!(json_string(r#"a"b"#), r#""a\"b""#);
        assert_eq!(json_string(r"a\b"), r#""a\\b""#);
        assert_eq!(json_string("cublas"), r#""cublas""#);
    }

    /// An auto-derived (Model B) shard component (one with no reviewed profile)
    /// contributes a `{ name -> name }` advisory rule, so it is advisable even
    /// though it is not in the component-profile table. Driven by a synthetic
    /// shard tree so the assertion holds regardless of what the committed
    /// shards currently contain.
    #[test]
    fn auto_derived_shard_component_becomes_an_advisory_rule() {
        let dir = std::env::temp_dir().join(format!(
            "cudabom-pmap-auto-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        std::fs::create_dir_all(&dir).unwrap();
        // A minimal valid shard carrying one auto-derived component (`nvtx`,
        // not in the profile table) and one profiled one (`cudart`).
        let shard = format!(
            r#"{{
                "schema_version": {},
                "components": [
                    {{ "name": "nvtx", "soname_stems": ["libnvtx3interop.so"] }},
                    {{ "name": "cudart", "soname_stems": ["libcudart.so"] }}
                ]
            }}"#,
            cudabom_identify::FingerprintDb::CURRENT_SCHEMA
        );
        std::fs::write(dir.join("redistrib_test.json"), shard).unwrap();

        let auto = auto_component_rules(&dir);
        // The auto component contributes exactly `(nvtx, nvtx)`.
        assert!(
            auto.iter().any(|(c, comp)| c == "nvtx" && comp == "nvtx"),
            "auto-derived nvtx must contribute a {{ nvtx -> nvtx }} rule: {auto:?}"
        );
        // The PROFILED cudart must NOT be re-emitted here (it comes from
        // advisory_terms); only unprofiled components are auto rules.
        assert!(
            !auto.iter().any(|(_, comp)| comp == "cudart"),
            "a profiled component (cudart) must not be an auto rule: {auto:?}"
        );

        // End to end: the full rule list resolves an `nvtx` product.
        let rules = ordered_rules(&dir);
        assert!(
            rules.iter().any(|(c, comp)| c == "nvtx" && comp == "nvtx"),
            "nvtx must appear in the final ordered rules"
        );

        // Closed loop through the REAL advisory matcher: render the map with
        // this shard tree, load it as a `cudabom_advisory::ProductMap`, and
        // confirm a CSAF-style product naming "NVTX" resolves to the auto
        // component. This is the actual CVE/CSAF path a scan would take.
        let json = render(&dir);
        let map = cudabom_advisory::ProductMap::from_json(json.as_bytes())
            .expect("generated product map is valid");
        assert_eq!(
            map.resolve("NVIDIA NVTX 1.2"),
            Some("nvtx"),
            "an auto-derived component must be resolvable from a CSAF product name"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A missing/empty shard tree is not an error: the generator still produces
    /// the manual + profile rules and no auto rules.
    #[test]
    fn absent_shard_tree_yields_no_auto_rules() {
        let dir = std::env::temp_dir().join("cudabom-pmap-does-not-exist-xyz");
        let _ = std::fs::remove_dir_all(&dir); // ensure absent
        assert_eq!(auto_component_rules(&dir).len(), 0);
    }

    /// The committed `advisories/product-map.json` must equal the generator's
    /// output. This is the same invariant `--check` enforces in CI/pre-commit,
    /// pinned as a unit test so a hand-edit to the committed file (or a profile
    /// change without regeneration) fails `cargo test` locally too.
    #[test]
    fn committed_product_map_matches_generated() {
        // Resolve relative to the repo root (xtask lives at <root>/xtask).
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join(DEFAULT_OUT);
        let committed = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
        assert_eq!(
            committed,
            render(&repo_shard_root()),
            "advisories/product-map.json is out of sync; run `cargo xtask product-map --write`"
        );
    }
}
