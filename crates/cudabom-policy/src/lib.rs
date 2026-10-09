//! Policy evaluation for cudabom.
//!
//! Evaluates a user-supplied policy file (see [`Policy`]) against a scan result
//! for the `cudabom gate` command, deciding whether findings should fail a
//! build. The design is secure-by-default: [`Policy::secure_default`] fails the
//! gate on any `affected` advisory verdict, and every relaxation (allowlist
//! entry, raised threshold) is explicit and must carry a reason.
//!
//! To keep the policy layer independent of the advisory database, advisory
//! results are passed in via the neutral [`AdvisoryVerdict`] type rather than
//! depending on `cudabom-advisory`; the CLI performs the mapping.

mod evaluate;
mod input;
mod schema;

pub use evaluate::{evaluate, AppliedExemption, Decision, Violation, ViolationKind};
pub use input::{AdvisoryVerdict, ScanInput, Verdict};
pub use schema::{Allow, FailOn, Policy, PolicyConfidence, PolicyError, PolicyVerdict};

#[cfg(test)]
mod tests {
    use super::*;
    use cudabom_core::{Component, Confidence, Finding, Relationship};

    #[test]
    fn end_to_end_default_policy_blocks_affected() {
        let policy = Policy::secure_default();
        let findings = vec![Finding {
            id: "f::cudart".to_string(),
            component: Component {
                name: "cudart".to_string(),
                version: Some("12.3".to_string()),
                candidate_versions: Vec::new(),
                relationship: Relationship::EmbeddedCopy,
            },
            confidence: Confidence::Exact,
            evidence: Vec::new(),
            conflicts: Vec::new(),
        }];
        let verdicts = vec![AdvisoryVerdict {
            advisory_id: "CVE-2025-0001".to_string(),
            component: "cudart".to_string(),
            verdict: Verdict::Affected,
            justification: "within affected range".to_string(),
        }];
        let input = ScanInput {
            findings: &findings,
            advisories: Some(&verdicts),
        };
        let decision = evaluate(&policy, &input);
        assert!(!decision.passed());
        assert_eq!(decision.violations.len(), 1);
    }
}
