//! Policy evaluation: policy + scan input -> gate decision.
//!
//! The evaluator collects every condition that would fail the gate, then
//! subtracts anything covered by an explicit allow entry. The result records
//! both the violations that stand and the exemptions that were applied, so
//! `cudabom gate` can explain exactly why it passed or failed.

use crate::input::{ScanInput, Verdict};
use crate::schema::{Allow, Policy};

/// The outcome of evaluating a policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    /// Violations that were not exempted. The gate fails iff this is non-empty.
    pub violations: Vec<Violation>,
    /// Exemptions that were applied (a would-be violation matched an allow
    /// entry), for auditability.
    pub exemptions: Vec<AppliedExemption>,
}

impl Decision {
    /// True if the gate passes (no standing violations).
    #[must_use]
    pub fn passed(&self) -> bool {
        self.violations.is_empty()
    }
}

/// A single policy violation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    /// A stable machine token for the violation kind.
    pub kind: ViolationKind,
    /// The component involved, when applicable.
    pub component: Option<String>,
    /// The advisory involved, when applicable.
    pub advisory: Option<String>,
    /// A description for output.
    pub detail: String,
}

/// The categories of policy violation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViolationKind {
    /// An advisory verdict listed in `fail_on.advisory_verdicts` occurred.
    AdvisoryVerdict,
    /// A finding met or exceeded `fail_on.min_confidence`.
    Confidence,
}

impl ViolationKind {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AdvisoryVerdict => "advisory_verdict",
            Self::Confidence => "confidence",
        }
    }
}

/// An allow entry that suppressed a would-be violation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedExemption {
    /// The exemption's justification (carried through for the audit trail).
    pub reason: String,
    /// The advisory it exempted, if any.
    pub advisory: Option<String>,
    /// The component it exempted, if any.
    pub component: Option<String>,
    /// A description of what was exempted.
    pub detail: String,
}

/// Evaluate `policy` against `input`, producing a [`Decision`].
#[must_use]
pub fn evaluate(policy: &Policy, input: &ScanInput<'_>) -> Decision {
    let mut violations = Vec::new();
    let mut exemptions = Vec::new();

    // 1. Advisory-verdict failures.
    if let Some(verdicts) = input.advisories {
        for v in verdicts {
            let fails = policy
                .fail_on
                .advisory_verdicts
                .iter()
                .any(|pv| pv.matches(v.verdict))
                || (policy.fail_on.under_investigation && v.verdict == Verdict::UnderInvestigation);
            if !fails {
                continue;
            }
            let candidate = Violation {
                kind: ViolationKind::AdvisoryVerdict,
                component: Some(v.component.clone()),
                advisory: Some(v.advisory_id.clone()),
                detail: format!(
                    "{} is {} for {}: {}",
                    v.component,
                    v.verdict.as_str(),
                    v.advisory_id,
                    v.justification
                ),
            };
            match find_exemption(&policy.allow, Some(&v.advisory_id), &v.component) {
                Some(allow) => exemptions.push(applied(allow, candidate.detail)),
                None => violations.push(candidate),
            }
        }
    }

    // 2. Confidence-threshold failures.
    if let Some(threshold) = policy.fail_on.min_confidence {
        let threshold = threshold.to_core();
        for f in input.findings {
            if f.confidence < threshold {
                continue;
            }
            let candidate = Violation {
                kind: ViolationKind::Confidence,
                component: Some(f.component.name.clone()),
                advisory: None,
                detail: format!(
                    "{} identified at {} confidence (>= policy threshold {})",
                    f.component.name,
                    f.confidence.as_str(),
                    threshold.as_str()
                ),
            };
            match find_exemption(&policy.allow, None, &f.component.name) {
                Some(allow) => exemptions.push(applied(allow, candidate.detail)),
                None => violations.push(candidate),
            }
        }
    }

    Decision {
        violations,
        exemptions,
    }
}

/// Find an allow entry that covers a would-be violation.
///
/// An entry matches when every field it specifies matches: an `advisory` field
/// must equal the violation's advisory (so a component-only violation is never
/// suppressed by an advisory-scoped exemption), and a `component` field must
/// equal the violation's component. An entry with only a `component` set
/// exempts any violation for that component.
fn find_exemption<'a>(
    allow: &'a [Allow],
    advisory: Option<&str>,
    component: &str,
) -> Option<&'a Allow> {
    allow.iter().find(|a| {
        let advisory_ok = match &a.advisory {
            None => true,
            Some(want) => advisory == Some(want.as_str()),
        };
        let component_ok = match &a.component {
            None => true,
            Some(want) => want == component,
        };
        advisory_ok && component_ok
    })
}

fn applied(allow: &Allow, detail: String) -> AppliedExemption {
    AppliedExemption {
        reason: allow.reason.clone(),
        advisory: allow.advisory.clone(),
        component: allow.component.clone(),
        detail,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::input::AdvisoryVerdict;
    use crate::schema::{FailOn, PolicyConfidence, PolicyVerdict};
    use cudabom_core::{Component, Confidence, Finding, Relationship};

    fn finding(name: &str, conf: Confidence) -> Finding {
        Finding {
            id: format!("f::{name}"),
            component: Component {
                name: name.to_string(),
                version: None,
                candidate_versions: Vec::new(),
                relationship: Relationship::EmbeddedCopy,
            },
            confidence: conf,
            evidence: Vec::new(),
            conflicts: Vec::new(),
        }
    }

    fn verdict(advisory: &str, component: &str, v: Verdict) -> AdvisoryVerdict {
        AdvisoryVerdict {
            advisory_id: advisory.to_string(),
            component: component.to_string(),
            verdict: v,
            justification: "test".to_string(),
        }
    }

    #[test]
    fn default_policy_fails_on_affected() {
        let policy = Policy::secure_default();
        let verdicts = vec![verdict("CVE-1", "cudart", Verdict::Affected)];
        let input = ScanInput {
            findings: &[],
            advisories: Some(&verdicts),
        };
        let d = evaluate(&policy, &input);
        assert!(!d.passed());
        assert_eq!(d.violations.len(), 1);
        assert_eq!(d.violations[0].kind, ViolationKind::AdvisoryVerdict);
    }

    #[test]
    fn default_policy_passes_on_not_affected() {
        let policy = Policy::secure_default();
        let verdicts = vec![verdict("CVE-1", "cudart", Verdict::NotAffected)];
        let input = ScanInput {
            findings: &[],
            advisories: Some(&verdicts),
        };
        assert!(evaluate(&policy, &input).passed());
    }

    #[test]
    fn under_investigation_blocks_only_when_configured() {
        let verdicts = vec![verdict("CVE-1", "cudart", Verdict::UnderInvestigation)];
        let input = ScanInput {
            findings: &[],
            advisories: Some(&verdicts),
        };
        // Default: does not block.
        assert!(evaluate(&Policy::secure_default(), &input).passed());
        // Configured to block.
        let strict = Policy {
            schema_version: 1,
            fail_on: FailOn {
                advisory_verdicts: vec![PolicyVerdict::Affected],
                min_confidence: None,
                under_investigation: true,
            },
            allow: Vec::new(),
        };
        assert!(!evaluate(&strict, &input).passed());
    }

    #[test]
    fn advisory_allow_exempts_and_is_recorded() {
        let policy = Policy {
            schema_version: 1,
            fail_on: FailOn::default(),
            allow: vec![Allow {
                advisory: Some("CVE-1".to_string()),
                component: None,
                reason: "mitigated".to_string(),
            }],
        };
        let verdicts = vec![verdict("CVE-1", "cudart", Verdict::Affected)];
        let input = ScanInput {
            findings: &[],
            advisories: Some(&verdicts),
        };
        let d = evaluate(&policy, &input);
        assert!(d.passed());
        assert_eq!(d.exemptions.len(), 1);
        assert_eq!(d.exemptions[0].reason, "mitigated");
    }

    #[test]
    fn component_allow_does_not_leak_across_advisories() {
        // Allow is scoped to advisory CVE-1; a different advisory still fails.
        let policy = Policy {
            schema_version: 1,
            fail_on: FailOn::default(),
            allow: vec![Allow {
                advisory: Some("CVE-1".to_string()),
                component: None,
                reason: "mitigated".to_string(),
            }],
        };
        let verdicts = vec![
            verdict("CVE-1", "cudart", Verdict::Affected),
            verdict("CVE-2", "cudart", Verdict::Affected),
        ];
        let input = ScanInput {
            findings: &[],
            advisories: Some(&verdicts),
        };
        let d = evaluate(&policy, &input);
        assert_eq!(d.violations.len(), 1);
        assert_eq!(d.violations[0].advisory.as_deref(), Some("CVE-2"));
        assert_eq!(d.exemptions.len(), 1);
    }

    #[test]
    fn confidence_threshold_fails_and_component_allow_exempts() {
        let policy = Policy {
            schema_version: 1,
            fail_on: FailOn {
                advisory_verdicts: vec![PolicyVerdict::Affected],
                min_confidence: Some(PolicyConfidence::Likely),
                under_investigation: false,
            },
            allow: vec![Allow {
                advisory: None,
                component: Some("cufft".to_string()),
                reason: "first-party, tracked".to_string(),
            }],
        };
        let findings = vec![
            finding("cudart", Confidence::Exact),   // fails
            finding("cufft", Confidence::Exact),    // exempted by component
            finding("cublas", Confidence::Unknown), // below threshold, ignored
        ];
        let input = ScanInput {
            findings: &findings,
            advisories: None,
        };
        let d = evaluate(&policy, &input);
        assert_eq!(d.violations.len(), 1);
        assert_eq!(d.violations[0].component.as_deref(), Some("cudart"));
        assert_eq!(d.violations[0].kind, ViolationKind::Confidence);
        assert_eq!(d.exemptions.len(), 1);
    }

    #[test]
    fn no_advisories_and_no_confidence_threshold_passes() {
        let policy = Policy::secure_default();
        let findings = vec![finding("cudart", Confidence::Exact)];
        let input = ScanInput {
            findings: &findings,
            advisories: None,
        };
        // Default policy only fails on advisory verdicts; with no advisory data
        // and identification alone, the gate passes.
        assert!(evaluate(&policy, &input).passed());
    }
}
