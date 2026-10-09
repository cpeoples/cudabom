//! `cudabom explain [--id <finding-id>] <target>...`.
//!
//! Scans the targets and prints the full evidence chain behind a single
//! finding, so a reviewer can see exactly why a component was identified and at
//! what confidence. Without `--id`, every finding is listed with its id so one
//! can be chosen.

use cudabom_core::{Confidence, Finding, Limits};

use crate::cli::{ExplainArgs, ExplainFormat};
use crate::commands::pipeline;
use crate::exit::ExitStatus;

pub(crate) fn run(args: &ExplainArgs) -> ExitStatus {
    let limits = Limits::default();

    let db = match crate::commands::or_input_error(pipeline::load_db(args.db.as_deref())) {
        Ok(db) => db,
        Err(status) => return status,
    };

    // Explanation is about identification; it does not correlate advisories.
    let outcome = match pipeline::run(&args.targets, &db, None, &limits) {
        Ok(outcome) => outcome,
        Err(status) => return status,
    };

    match &args.id {
        None => {
            list_findings(&outcome.findings);
            ExitStatus::Success
        }
        Some(id) => explain_one(&outcome.findings, id, args.format),
    }
}

/// Explain a single finding by id, or report that the id is unknown.
fn explain_one(findings: &[Finding], id: &str, format: ExplainFormat) -> ExitStatus {
    let Some(finding) = findings.iter().find(|f| f.id == id) else {
        eprintln!("cudabom: no finding with id `{id}`.");
        if !findings.is_empty() {
            eprintln!("cudabom: available finding ids:");
            for f in findings {
                eprintln!("  {}", f.id);
            }
        }
        // A bad id is a usage problem from the caller's perspective.
        return ExitStatus::Usage;
    };

    match format {
        ExplainFormat::Text => {
            print!("{}", explain_text(finding));
            ExitStatus::Success
        }
        ExplainFormat::Json => match serde_json::to_string_pretty(finding) {
            Ok(json) => {
                println!("{json}");
                ExitStatus::Success
            }
            Err(err) => {
                eprintln!("cudabom: {err}");
                ExitStatus::Internal
            }
        },
    }
}

/// List every finding with its id and a one-line summary.
fn list_findings(findings: &[Finding]) {
    if findings.is_empty() {
        println!("no findings.");
        return;
    }
    println!("findings ({}):", findings.len());
    for f in findings {
        let version = f.component.version.as_deref().unwrap_or("-");
        println!(
            "  {}  {} {} [{}]",
            f.id,
            f.component.name,
            version,
            f.confidence.as_str(),
        );
    }
    println!("\nrun `cudabom explain --id <finding-id> <target>` for the full evidence chain.");
}

/// Render the full evidence chain for one finding as readable text.
fn explain_text(finding: &Finding) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();

    let version = finding.component.version.as_deref().unwrap_or("(unknown)");
    let _ = writeln!(out, "finding: {}", finding.id);
    let _ = writeln!(out, "  component:    {}", finding.component.name);
    let _ = writeln!(out, "  version:      {version}");
    let _ = writeln!(out, "  confidence:   {}", finding.confidence.as_str());
    let _ = writeln!(
        out,
        "  relationship: {}",
        finding.component.relationship.as_str()
    );

    let _ = writeln!(out, "  evidence ({}):", finding.evidence.len());
    for (i, ev) in finding.evidence.iter().enumerate() {
        let _ = writeln!(out, "    {}. {}", i + 1, ev.kind.as_str());
        let _ = writeln!(out, "       detail:   {}", ev.detail);
        let _ = writeln!(out, "       location: {}", ev.location.path);
        if let Some(sha) = &ev.location.sha256 {
            let _ = writeln!(out, "       sha256:   {sha}");
        }
        if let Some(layer) = &ev.location.layer_digest {
            let _ = writeln!(out, "       layer:    {layer}");
        }
    }

    if finding.conflicts.is_empty() {
        let _ = writeln!(out, "  conflicts:    none");
    } else {
        let _ = writeln!(out, "  conflicts ({}):", finding.conflicts.len());
        for c in &finding.conflicts {
            let _ = writeln!(out, "    - {c}");
        }
    }

    // A short note on what the confidence level means, for the reader.
    let _ = writeln!(out, "\n  {}", confidence_note(finding.confidence));

    out
}

fn confidence_note(c: Confidence) -> &'static str {
    match c {
        Confidence::Exact => {
            "exact: a known-hash/build-id match, or two agreeing strong evidence items."
        }
        Confidence::Likely => {
            "likely: identity well supported; version may be a range rather than exact."
        }
        Confidence::Unknown => {
            "unknown: CUDA-related signals exist but identity could not be established."
        }
    }
}
