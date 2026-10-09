//! `cudabom gate <target>...`.
//!
//! Runs the shared scan pipeline, then evaluates a policy against the result to
//! decide whether the build should fail. Without `--policy`, the built-in
//! secure default is used: fail on any `affected` advisory verdict.
//!
//! Exit codes: `Success` (0) when the gate passes, `Findings` (1) when the
//! policy is violated, `Input` (3) for unreadable inputs.

use cudabom_core::Limits;
use cudabom_policy::{evaluate, AdvisoryVerdict, Decision, Policy, ScanInput, Verdict};
use serde::Serialize;

use crate::cli::{GateArgs, GateFormat};
use crate::commands::pipeline;
use crate::exit::ExitStatus;

pub(crate) fn run(args: &GateArgs) -> ExitStatus {
    let limits = Limits::default();

    let (db, advisory_index) =
        match pipeline::load_db_and_advisories(args.db.as_deref(), args.advisories.as_deref()) {
            Ok(pair) => pair,
            Err(status) => return status,
        };
    let policy = match load_policy(args.policy.as_deref()) {
        Ok(policy) => policy,
        Err(err) => {
            eprintln!("cudabom: {err}");
            return ExitStatus::Input;
        }
    };

    let outcome = match pipeline::run(&args.targets, &db, advisory_index, &limits) {
        Ok(outcome) => outcome,
        Err(status) => return status,
    };

    // Map advisory matches into the policy crate's neutral verdict type.
    let verdicts: Option<Vec<AdvisoryVerdict>> = outcome
        .advisory_matches
        .as_ref()
        .map(|matches| matches.iter().map(to_policy_verdict).collect());

    let input = ScanInput {
        findings: &outcome.findings,
        advisories: verdicts.as_deref(),
    };
    let decision = evaluate(&policy, &input);

    if let Err(err) = render(&decision, args) {
        eprintln!("cudabom: {err}");
        return ExitStatus::Internal;
    }

    if decision.passed() {
        ExitStatus::Success
    } else {
        ExitStatus::Findings
    }
}

/// Load a policy from `path`, or the secure default when no path is given.
fn load_policy(path: Option<&str>) -> anyhow::Result<Policy> {
    match path {
        None => Ok(Policy::secure_default()),
        Some(p) => {
            let bytes =
                std::fs::read(p).map_err(|e| anyhow::anyhow!("cannot read policy {p}: {e}"))?;
            Policy::from_json(&bytes).map_err(|e| anyhow::anyhow!("{e}"))
        }
    }
}

/// Map an advisory match into the policy crate's neutral verdict type.
fn to_policy_verdict(m: &cudabom_advisory::Match) -> AdvisoryVerdict {
    let verdict = match m.verdict {
        cudabom_advisory::Verdict::Affected => Verdict::Affected,
        cudabom_advisory::Verdict::NotAffected => Verdict::NotAffected,
        cudabom_advisory::Verdict::UnderInvestigation => Verdict::UnderInvestigation,
    };
    AdvisoryVerdict {
        advisory_id: m.advisory_id.clone(),
        component: m.component.clone(),
        verdict,
        justification: m.justification.clone(),
    }
}

/// Render the gate decision, to stdout.
fn render(decision: &Decision, args: &GateArgs) -> anyhow::Result<()> {
    match args.format {
        GateFormat::Table => print!("{}", render_table(decision)),
        GateFormat::Json => println!("{}", serde_json::to_string_pretty(&as_json(decision))?),
    }
    Ok(())
}

fn render_table(decision: &Decision) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    if decision.passed() {
        let _ = writeln!(out, "gate: PASS");
    } else {
        let _ = writeln!(
            out,
            "gate: FAIL ({} violation(s))",
            decision.violations.len()
        );
        for v in &decision.violations {
            let _ = writeln!(out, "  [{}] {}", v.kind.as_str(), v.detail);
        }
    }
    if !decision.exemptions.is_empty() {
        let _ = writeln!(out, "exemptions applied:");
        for e in &decision.exemptions {
            let _ = writeln!(out, "  {} (reason: {})", e.detail, e.reason);
        }
    }
    out
}

/// A stable JSON view of the decision.
#[derive(Serialize)]
struct DecisionJson<'a> {
    passed: bool,
    violations: Vec<ViolationJson<'a>>,
    exemptions: Vec<ExemptionJson<'a>>,
}

#[derive(Serialize)]
struct ViolationJson<'a> {
    kind: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    component: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    advisory: Option<&'a str>,
    detail: &'a str,
}

#[derive(Serialize)]
struct ExemptionJson<'a> {
    reason: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    advisory: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    component: Option<&'a str>,
    detail: &'a str,
}

fn as_json(decision: &Decision) -> DecisionJson<'_> {
    DecisionJson {
        passed: decision.passed(),
        violations: decision
            .violations
            .iter()
            .map(|v| ViolationJson {
                kind: v.kind.as_str(),
                component: v.component.as_deref(),
                advisory: v.advisory.as_deref(),
                detail: &v.detail,
            })
            .collect(),
        exemptions: decision
            .exemptions
            .iter()
            .map(|e| ExemptionJson {
                reason: &e.reason,
                advisory: e.advisory.as_deref(),
                component: e.component.as_deref(),
                detail: &e.detail,
            })
            .collect(),
    }
}
