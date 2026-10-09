//! Reconcile a *declared* CycloneDX SBOM/VEX (e.g. from NVIDIA NGC) against the
//! CUDA components cudabom actually *discovered* in an artifact.
//!
//! This is the "declared vs discovered" validation: a third party publishes an
//! SBOM (and VEX) for an image; cudabom independently proves what CUDA software
//! is inside. Reconciling the two yields three buckets:
//!
//! - **matched**: a CUDA component both declared and discovered (with any VEX
//!   analysis statements the declaration carried for it);
//! - **declared_only**: declared as present but *not* discovered by cudabom;
//! - **discovered_only**: discovered by cudabom but *absent* from the
//!   declaration: the high-value case, where a declaration under-reports what
//!   is actually shipped.
//!
//! Comparison is by canonical CUDA component identity (via
//! [`cudabom_identify::canonicalize_declared_name`]), not by spelling, so
//! `cuda-cudart` / `libcudart.so.12` / `pkg:generic/cuda-cudart@...` all line up
//! with cudabom's `cudart`. Only components that resolve to a known CUDA
//! component participate; unrelated declared entries (openssl, numpy, ...) are
//! counted but not treated as CUDA findings.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use cudabom_core::{Finding, Limits};
use cudabom_identify::canonicalize_declared_name;
use cudabom_sbom::DeclaredBom;
use serde::Serialize;

use crate::cli::{OutputFormat, ReconcileArgs};
use crate::commands::pipeline;
use crate::exit::ExitStatus;

/// `cudabom reconcile`: scan targets, load a declared SBOM/VEX, and report the
/// agreement and gaps between what was declared and what cudabom discovered.
pub(crate) fn run(args: &ReconcileArgs) -> ExitStatus {
    if args.sbom.is_none() && args.vex.is_none() && args.ngc_image.is_none() {
        eprintln!("cudabom: reconcile requires --sbom, --vex, or --ngc-image");
        return ExitStatus::Input;
    }

    let mut declared = DeclaredBom::default();

    // Networked path: fetch the declared SBOM/VEX from NGC (opt-in, key-gated).
    if let Some(spec) = &args.ngc_image {
        let image = match crate::commands::ngc::NgcImage::parse(spec) {
            Ok(img) => img,
            Err(err) => {
                eprintln!("cudabom: invalid --ngc-image: {err}");
                return ExitStatus::Input;
            }
        };
        let key = args
            .ngc_api_key
            .clone()
            .or_else(|| std::env::var("NGC_API_KEY").ok());
        let Some(key) = key else {
            eprintln!("cudabom: --ngc-image requires an API key via --ngc-api-key or NGC_API_KEY");
            return ExitStatus::Input;
        };
        eprintln!("cudabom: fetching declared SBOM/VEX from NGC for {spec}");
        match crate::commands::ngc::fetch_declared(&image, &key) {
            Ok(fetched) => {
                match DeclaredBom::from_json(&fetched.sbom) {
                    Ok(doc) => declared.merge(doc),
                    Err(err) => {
                        eprintln!("cudabom: NGC SBOM parse error: {err}");
                        return ExitStatus::Input;
                    }
                }
                if let Some(vex) = fetched.vex {
                    match DeclaredBom::from_json(&vex) {
                        Ok(doc) => declared.merge(doc),
                        Err(err) => {
                            eprintln!("cudabom: NGC VEX parse error: {err}");
                            return ExitStatus::Input;
                        }
                    }
                }
            }
            Err(err) => {
                eprintln!("cudabom: {err}");
                return ExitStatus::Input;
            }
        }
    }

    // Offline path: load and merge any local declared document(s).
    for path in [args.sbom.as_deref(), args.vex.as_deref()]
        .into_iter()
        .flatten()
    {
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(err) => {
                eprintln!("cudabom: cannot read {path}: {err}");
                return ExitStatus::Input;
            }
        };
        match DeclaredBom::from_json(&bytes) {
            Ok(doc) => declared.merge(doc),
            Err(err) => {
                eprintln!("cudabom: {err} ({path})");
                return ExitStatus::Input;
            }
        }
    }

    let limits = Limits::default();
    let db = match crate::commands::or_input_error(pipeline::load_db(args.db.as_deref())) {
        Ok(db) => db,
        Err(status) => return status,
    };

    // Advisories are not needed for reconciliation; discoveries alone are
    // compared against the declaration.
    let outcome = match pipeline::run(&args.targets, &db, None, &limits) {
        Ok(outcome) => outcome,
        Err(status) => return status,
    };

    let result = reconcile(&declared, &outcome.findings, &outcome.catalog);

    let text = match args.format {
        OutputFormat::Json => match serde_json::to_string_pretty(&result) {
            Ok(json) => json,
            Err(err) => {
                eprintln!("cudabom: {err}");
                return ExitStatus::Internal;
            }
        },
        // Any non-JSON format renders the human-readable table; reconciliation
        // is a comparison report, not an SBOM/SARIF artifact.
        _ => render_table(&result),
    };

    if let Err(status) = super::emit(args.output.as_deref(), &text) {
        return status;
    }

    ExitStatus::Success
}

/// Render the reconciliation as a readable table.
fn render_table(r: &Reconciliation) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "reconciliation: {} matched, {} declared-only, {} discovered-only ({} non-CUDA declared)",
        r.matched.len(),
        r.declared_only.len(),
        r.discovered_only.len(),
        r.non_cuda_declared,
    );
    if r.is_in_agreement() {
        let _ = writeln!(
            out,
            "  declaration and discovery agree on the CUDA inventory"
        );
    }

    if !r.discovered_only.is_empty() {
        let _ = writeln!(
            out,
            "\ndiscovered but NOT declared (declaration under-reports):"
        );
        for c in &r.discovered_only {
            let v = c.discovered_version.as_deref().unwrap_or("-");
            let _ = writeln!(out, "  + {} {} [{}]", c.component, v, c.finding_id);
            if let Some(desc) = &c.description {
                let _ = writeln!(out, "      {desc}");
            }
        }
    }
    if !r.declared_only.is_empty() {
        let _ = writeln!(out, "\ndeclared but NOT discovered:");
        for c in &r.declared_only {
            let v = c.declared_version.as_deref().unwrap_or("-");
            let _ = writeln!(out, "  - {} {}", c.component, v);
        }
    }
    if !r.matched.is_empty() {
        let _ = writeln!(out, "\nmatched:");
        for c in &r.matched {
            let dv = c.discovered_version.as_deref().unwrap_or("-");
            let mismatch = if c.version_mismatch {
                format!(
                    " (version mismatch: declared {})",
                    c.declared_version.as_deref().unwrap_or("-")
                )
            } else {
                String::new()
            };
            let _ = writeln!(out, "  = {} {}{}", c.component, dv, mismatch);
            if let Some(desc) = &c.description {
                let _ = writeln!(out, "      {desc}");
            }
            for vex in &c.declared_vex {
                let state = vex.state.as_deref().unwrap_or("unspecified");
                let _ = writeln!(out, "      vex: {state} {}", vex.id);
            }
        }
    }
    out
}

/// The full reconciliation result between a declaration and cudabom findings.
#[derive(Debug, Default, Serialize)]
pub(crate) struct Reconciliation {
    /// CUDA components present in both the declaration and cudabom's findings.
    pub(crate) matched: Vec<MatchedComponent>,
    /// CUDA components declared as present but not discovered by cudabom.
    pub(crate) declared_only: Vec<DeclaredComponentView>,
    /// CUDA components discovered by cudabom but absent from the declaration.
    pub(crate) discovered_only: Vec<DiscoveredComponentView>,
    /// Count of declared components that are not CUDA components cudabom knows
    /// (recorded for transparency; they are outside cudabom's scope).
    pub(crate) non_cuda_declared: usize,
}

impl Reconciliation {
    /// True when the declaration and cudabom fully agree on the CUDA inventory
    /// (nothing declared-only, nothing discovered-only).
    pub(crate) fn is_in_agreement(&self) -> bool {
        self.declared_only.is_empty() && self.discovered_only.is_empty()
    }
}

/// A CUDA component found in both the declaration and cudabom's findings.
#[derive(Debug, Serialize)]
pub(crate) struct MatchedComponent {
    /// Canonical CUDA component name.
    pub(crate) component: String,
    /// NVIDIA-provided description, when known (first-party from the DB).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) description: Option<String>,
    /// The version cudabom discovered, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) discovered_version: Option<String>,
    /// The version the declaration stated, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) declared_version: Option<String>,
    /// True when both sides state a version and they disagree.
    pub(crate) version_mismatch: bool,
    /// VEX analysis statements the declaration carried that reference this
    /// component (by canonical identity).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) declared_vex: Vec<VexStatement>,
}

/// A declared-but-not-discovered CUDA component.
#[derive(Debug, Serialize)]
pub(crate) struct DeclaredComponentView {
    pub(crate) component: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) declared_version: Option<String>,
}

/// A discovered-but-not-declared CUDA component.
#[derive(Debug, Serialize)]
pub(crate) struct DiscoveredComponentView {
    pub(crate) component: String,
    /// NVIDIA-provided description, when known (first-party from the DB).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) discovered_version: Option<String>,
    /// The finding id, so `cudabom explain <id>` reaches the evidence.
    pub(crate) finding_id: String,
}

/// A declared VEX statement, reduced to what reconciliation surfaces.
#[derive(Debug, Serialize)]
pub(crate) struct VexStatement {
    /// The vulnerability id (CVE, GHSA, ...).
    pub(crate) id: String,
    /// The declared VEX state (`not_affected`, `in_triage`, ...), when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) state: Option<String>,
    /// The declared justification, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) justification: Option<String>,
}

/// Reconcile a declared CycloneDX document against cudabom's discovered findings.
///
/// `catalog` supplies NVIDIA-provided descriptions (first-party from the DB) to
/// annotate matched and discovered-only components.
pub(crate) fn reconcile(
    declared: &DeclaredBom,
    findings: &[Finding],
    catalog: &BTreeMap<String, crate::commands::pipeline::ComponentInfo>,
) -> Reconciliation {
    // Index declared CUDA components by canonical name (first version wins for
    // display; keep a set of bom-refs to attach VEX by reference too).
    let mut declared_versions: BTreeMap<String, Option<String>> = BTreeMap::new();
    let mut ref_to_canonical: BTreeMap<String, String> = BTreeMap::new();
    let mut non_cuda = 0usize;
    for c in &declared.components {
        match canonicalize_declared_name(&c.name)
            .or_else(|| c.purl.as_deref().and_then(canonicalize_declared_name))
        {
            Some(canonical) => {
                declared_versions
                    .entry(canonical.clone())
                    .or_insert_with(|| c.version.clone());
                if let Some(bref) = &c.bom_ref {
                    ref_to_canonical.insert(bref.clone(), canonical.clone());
                }
                // The bare declared name can also be a VEX `affects` ref.
                ref_to_canonical.insert(c.name.clone(), canonical);
            }
            None => non_cuda += 1,
        }
    }

    // Attach declared VEX statements to canonical components. A statement's
    // `affects[].ref` may be a bom-ref or a bare name; try both, and also
    // canonicalize the ref directly for declarations that name CUDA components
    // inline in `affects`.
    let mut vex_by_component: BTreeMap<String, Vec<VexStatement>> = BTreeMap::new();
    for v in &declared.vulnerabilities {
        for aff in &v.affects {
            let Some(bref) = &aff.bom_ref else { continue };
            let canonical = ref_to_canonical
                .get(bref)
                .cloned()
                .or_else(|| canonicalize_declared_name(bref));
            if let Some(canonical) = canonical {
                vex_by_component
                    .entry(canonical)
                    .or_default()
                    .push(VexStatement {
                        id: v.id.clone(),
                        state: v.analysis.as_ref().and_then(|a| a.state.clone()),
                        justification: v.analysis.as_ref().and_then(|a| a.justification.clone()),
                    });
            }
        }
    }

    // Index discovered CUDA components by canonical name (findings already use
    // canonical names). Keep the strongest (first sorted) finding per component.
    let mut discovered: BTreeMap<String, (&Finding, Option<String>)> = BTreeMap::new();
    for f in findings {
        discovered
            .entry(f.component.name.clone())
            .or_insert_with(|| (f, f.component.version.clone()));
    }

    let declared_names: BTreeSet<&String> = declared_versions.keys().collect();
    let discovered_names: BTreeSet<&String> = discovered.keys().collect();

    let mut result = Reconciliation {
        non_cuda_declared: non_cuda,
        ..Default::default()
    };

    // Matched: in both.
    for name in declared_names.intersection(&discovered_names) {
        let name = (*name).clone();
        let declared_version = declared_versions.get(&name).cloned().flatten();
        let (_finding, discovered_version) = &discovered[&name];
        let version_mismatch = match (&declared_version, discovered_version) {
            (Some(d), Some(v)) => d != v,
            _ => false,
        };
        let mut declared_vex = vex_by_component.remove(&name).unwrap_or_default();
        declared_vex.sort_by(|a, b| a.id.cmp(&b.id));
        let description = catalog.get(&name).and_then(|i| i.description.clone());
        result.matched.push(MatchedComponent {
            component: name,
            description,
            discovered_version: discovered_version.clone(),
            declared_version,
            version_mismatch,
            declared_vex,
        });
    }

    // Declared only: in the declaration, not discovered.
    for name in declared_names.difference(&discovered_names) {
        let name = (*name).clone();
        let declared_version = declared_versions.get(&name).cloned().flatten();
        result.declared_only.push(DeclaredComponentView {
            component: name,
            declared_version,
        });
    }

    // Discovered only: cudabom found it, the declaration omitted it.
    for name in discovered_names.difference(&declared_names) {
        let name = (*name).clone();
        let (finding, discovered_version) = &discovered[&name];
        let description = catalog.get(&name).and_then(|i| i.description.clone());
        result.discovered_only.push(DiscoveredComponentView {
            component: name,
            description,
            discovered_version: discovered_version.clone(),
            finding_id: finding.id.clone(),
        });
    }

    result.matched.sort_by(|a, b| a.component.cmp(&b.component));
    result
        .declared_only
        .sort_by(|a, b| a.component.cmp(&b.component));
    result
        .discovered_only
        .sort_by(|a, b| a.component.cmp(&b.component));
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use cudabom_core::{Component, Confidence, Relationship};

    fn finding(name: &str, version: Option<&str>) -> Finding {
        Finding {
            id: format!("f::{name}"),
            component: Component {
                name: name.to_string(),
                version: version.map(ToString::to_string),
                candidate_versions: Vec::new(),
                relationship: Relationship::EmbeddedCopy,
            },
            confidence: Confidence::Exact,
            evidence: Vec::new(),
            conflicts: Vec::new(),
        }
    }

    /// A catalog giving npp a description, to prove it flows to discovered-only.
    fn catalog() -> BTreeMap<String, crate::commands::pipeline::ComponentInfo> {
        let mut m = BTreeMap::new();
        m.insert(
            "npp".to_string(),
            crate::commands::pipeline::ComponentInfo {
                description: Some("CUDA NPP".to_string()),
                license: Some("CUDA Toolkit".to_string()),
                release_dates: BTreeMap::new(),
            },
        );
        m
    }

    /// Declaration: cudart (matches, with a VEX statement) and cublas
    /// (declared-only). cudabom also discovers npp (discovered-only).
    fn declared() -> DeclaredBom {
        DeclaredBom::from_json(
            br#"{
                "bomFormat": "CycloneDX",
                "components": [
                    { "type": "library", "bom-ref": "c1", "name": "cuda-cudart", "version": "12.4.127" },
                    { "type": "library", "name": "libcublas", "version": "12.4.5.8" },
                    { "type": "library", "name": "openssl", "version": "3.0" }
                ],
                "vulnerabilities": [
                    { "id": "CVE-2025-0001",
                      "analysis": { "state": "not_affected", "justification": "code_not_reachable" },
                      "affects": [ { "ref": "c1" } ] }
                ]
            }"#,
        )
        .unwrap()
    }

    #[test]
    fn matched_declared_only_and_discovered_only_are_bucketed() {
        let findings = vec![
            finding("cudart", Some("12.4.127")),
            finding("npp", Some("12.2.5.30")),
        ];
        let r = reconcile(&declared(), &findings, &catalog());
        assert_eq!(r.matched.len(), 1);
        assert_eq!(r.matched[0].component, "cudart");
        assert!(!r.matched[0].version_mismatch);
        // The VEX statement rode along, attached by bom-ref.
        assert_eq!(r.matched[0].declared_vex.len(), 1);
        assert_eq!(r.matched[0].declared_vex[0].id, "CVE-2025-0001");
        assert_eq!(
            r.matched[0].declared_vex[0].state.as_deref(),
            Some("not_affected")
        );

        // cublas was declared but cudabom did not find it.
        assert_eq!(r.declared_only.len(), 1);
        assert_eq!(r.declared_only[0].component, "cublas");

        // npp was discovered but not declared: the high-value gap.
        assert_eq!(r.discovered_only.len(), 1);
        assert_eq!(r.discovered_only[0].component, "npp");
        assert_eq!(r.discovered_only[0].finding_id, "f::npp");
        // The NVIDIA description flowed through from the catalog.
        assert_eq!(
            r.discovered_only[0].description.as_deref(),
            Some("CUDA NPP")
        );

        // openssl is not a CUDA component; counted, not bucketed.
        assert_eq!(r.non_cuda_declared, 1);
        assert!(!r.is_in_agreement());
    }

    #[test]
    fn version_mismatch_is_flagged() {
        let findings = vec![finding("cudart", Some("12.4.99"))];
        let r = reconcile(&declared(), &findings, &BTreeMap::new());
        let cudart = r.matched.iter().find(|m| m.component == "cudart").unwrap();
        assert!(cudart.version_mismatch);
        assert_eq!(cudart.declared_version.as_deref(), Some("12.4.127"));
        assert_eq!(cudart.discovered_version.as_deref(), Some("12.4.99"));
    }

    #[test]
    fn full_agreement_when_inventories_match() {
        let decl = DeclaredBom::from_json(
            br#"{ "components": [ { "type": "library", "name": "cuda-cudart", "version": "12.4.127" } ] }"#,
        )
        .unwrap();
        let findings = vec![finding("cudart", Some("12.4.127"))];
        let r = reconcile(&decl, &findings, &BTreeMap::new());
        assert!(r.is_in_agreement());
        assert_eq!(r.matched.len(), 1);
    }
}
