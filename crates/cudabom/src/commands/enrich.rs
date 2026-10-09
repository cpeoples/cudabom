//! `cudabom enrich --sbom <file> <target>...`.
//!
//! Scans the targets for CUDA components and merges them into an existing
//! CycloneDX SBOM, preserving the input document (including fields cudabom does
//! not model) and skipping components the SBOM already contains.

use cudabom_core::Limits;

use crate::cli::EnrichArgs;
use crate::commands::pipeline;
use crate::exit::ExitStatus;

pub(crate) fn run(args: &EnrichArgs) -> ExitStatus {
    let limits = Limits::default();

    let input = match std::fs::read(&args.sbom) {
        Ok(bytes) => bytes,
        Err(err) => {
            eprintln!("cudabom: cannot read SBOM {}: {err}", args.sbom);
            return ExitStatus::Input;
        }
    };

    let db = match crate::commands::or_input_error(pipeline::load_db(args.db.as_deref())) {
        Ok(db) => db,
        Err(status) => return status,
    };

    // Enrichment does not use advisories; it only adds discovered components.
    let outcome = match pipeline::run(&args.targets, &db, None, &limits) {
        Ok(outcome) => outcome,
        Err(status) => return status,
    };

    let enriched = match cudabom_sbom::enrich(&input, &outcome.findings, env!("CARGO_PKG_VERSION"))
    {
        Ok(enriched) => enriched,
        Err(err) => {
            eprintln!("cudabom: {err}");
            return ExitStatus::Input;
        }
    };

    eprintln!(
        "cudabom: enriched SBOM (+{} component(s), {} already present)",
        enriched.added, enriched.skipped
    );

    if let Err(status) = super::emit(args.output.as_deref(), &enriched.json) {
        return status;
    }

    ExitStatus::Success
}
