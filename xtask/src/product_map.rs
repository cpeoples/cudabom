//! `cargo xtask product-map`: generate `advisories/product-map.json` from the
//! reviewed component profiles.
//!
//! The CSAF product → component mapping is *derived*, not hand-maintained. Its
//! substring rules come from two sources, combined deterministically:
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
//!
//! The two sources are merged with the manual seed first (so umbrella rules like
//! `cuda toolkit` stay ahead of narrower ones), then profile-derived rules, with
//! duplicate `contains` substrings dropped (first occurrence wins). The result
//! is rendered as stable, pretty JSON matching the committed file byte-for-byte.
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

/// `product-map [--check | --write] [--out <file>]`
pub(crate) fn run(args: &[String]) -> Result<()> {
    let out = PathBuf::from(flag(args, "--out").unwrap_or_else(|| DEFAULT_OUT.to_string()));
    let write = has_flag(args, "--write");
    // --check is the safe default so a bare invocation never mutates the tree.
    let check = has_flag(args, "--check") || !write;

    let generated = render();

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
             crates/cudabom-identify/src/derive.rs plus the MANUAL_RULES seed.)",
            out.display()
        );
    }

    Ok(())
}

/// Build the ordered, de-duplicated rule list: manual seed first, then
/// profile-derived terms, dropping any `contains` substring already seen.
///
/// After collection, rules are reordered so that whenever one rule's `contains`
/// is a substring of another's, the longer (more specific) rule comes first.
/// Matching is first-wins substring, so without this a short rule (`nvjpeg`)
/// would shadow a more specific one (`nvjpeg2000`) and misattribute its
/// advisories. The reordering is a stable partial sort: rules not in a
/// substring relationship keep their original (profile/seed) order.
fn ordered_rules() -> Vec<(String, String)> {
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
    sort_by_specificity(&mut rules);
    rules
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
fn render() -> String {
    let rules = ordered_rules();
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

    #[test]
    fn manual_rules_come_before_profile_rules() {
        let rules = ordered_rules();
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
        let rules = ordered_rules();
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
        let rules = ordered_rules();
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
        let rules = ordered_rules();
        for (term, _component) in cudabom_identify::advisory_terms() {
            assert!(
                rules.iter().any(|(c, _)| normalize(c) == normalize(term)),
                "profile term missing from generated rules: {term}"
            );
        }
    }

    #[test]
    fn rendered_json_parses_and_round_trips_stably() {
        let a = render();
        // Must be valid JSON.
        let value: serde_json::Value = serde_json::from_str(&a).unwrap();
        assert_eq!(value["schema_version"], SCHEMA_VERSION);
        assert!(value["rules"].as_array().unwrap().len() >= MANUAL_RULES.len());
        // Deterministic: rendering twice yields identical bytes.
        assert_eq!(a, render());
        // Ends with a single trailing newline.
        assert!(a.ends_with("}\n"));
    }

    #[test]
    fn json_string_escapes_quotes_and_backslashes() {
        assert_eq!(json_string(r#"a"b"#), r#""a\"b""#);
        assert_eq!(json_string(r"a\b"), r#""a\\b""#);
        assert_eq!(json_string("cublas"), r#""cublas""#);
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
            render(),
            "advisories/product-map.json is out of sync; run `cargo xtask product-map --write`"
        );
    }
}
