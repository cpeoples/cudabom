//! `cudabom vex <target>...`.
//!
//! Runs the shared scan pipeline, correlates findings against an advisory index
//! (when supplied), and emits a CycloneDX 1.6 VEX document: an SBOM of the
//! identified components plus a `vulnerabilities` array carrying the advisory
//! verdicts as VEX `analysis.state` statements.

use cudabom_core::Limits;
use cudabom_sbom::{SbomOptions, VexState, VexVerdict};

use crate::cli::VexArgs;
use crate::commands::pipeline;
use crate::exit::ExitStatus;

pub(crate) fn run(args: &VexArgs) -> ExitStatus {
    let limits = Limits::default();

    let (db, advisory_index) =
        match pipeline::load_db_and_advisories(args.db.as_deref(), args.advisories.as_deref()) {
            Ok(pair) => pair,
            Err(status) => return status,
        };

    let outcome = match pipeline::run(&args.targets, &db, advisory_index, &limits) {
        Ok(outcome) => outcome,
        Err(status) => return status,
    };

    let verdicts: Vec<VexVerdict> = outcome
        .advisory_matches
        .as_deref()
        .unwrap_or_default()
        .iter()
        .map(to_vex_verdict)
        .collect();

    let options = SbomOptions {
        subject_name: args.targets.first().cloned(),
        subject_sha256: None,
        // Timestamp omitted for reproducible output.
        timestamp: None,
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
    };

    let text = match cudabom_sbom::to_vex_json(&outcome.findings, &verdicts, &options) {
        Ok(text) => text,
        Err(err) => {
            eprintln!("cudabom: {err}");
            return ExitStatus::Internal;
        }
    };

    if let Err(status) = super::emit(args.output.as_deref(), &text) {
        return status;
    }

    // VEX generation is a reporting action: success regardless of verdicts.
    ExitStatus::Success
}

/// Map an advisory match into the SBOM crate's neutral VEX verdict type.
fn to_vex_verdict(m: &cudabom_advisory::Match) -> VexVerdict {
    let state = match m.verdict {
        cudabom_advisory::Verdict::Affected => VexState::Affected,
        cudabom_advisory::Verdict::NotAffected => VexState::NotAffected,
        cudabom_advisory::Verdict::UnderInvestigation => VexState::UnderInvestigation,
    };
    VexVerdict {
        advisory_id: m.advisory_id.clone(),
        component: m.component.clone(),
        state,
        justification: m.justification.clone(),
    }
}
