//! Neutral policy input types.
//!
//! Like the reporting layer, the policy evaluator renders a decision from
//! [`cudabom_core::Finding`]s plus optional advisory verdicts, without depending
//! on `cudabom-advisory`. Advisory results are passed in as this neutral
//! [`AdvisoryVerdict`] shape; the CLI maps advisory matches into these.

use cudabom_core::Finding;

/// A VEX-style advisory verdict for a finding, in neutral form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdvisoryVerdict {
    /// Advisory identifier (e.g. a CVE id).
    pub advisory_id: String,
    /// The component the verdict concerns.
    pub component: String,
    /// The verdict.
    pub verdict: Verdict,
    /// A short justification for explainability.
    pub justification: String,
}

/// The three VEX outcomes cudabom emits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Affected,
    NotAffected,
    UnderInvestigation,
}

impl Verdict {
    /// The stable lowercase token used in output and policy files.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Affected => "affected",
            Self::NotAffected => "not_affected",
            Self::UnderInvestigation => "under_investigation",
        }
    }
}

/// Everything the evaluator needs: the findings and any advisory verdicts.
#[derive(Debug, Clone)]
pub struct ScanInput<'a> {
    /// The identified components.
    pub findings: &'a [Finding],
    /// Advisory verdicts, when advisory correlation ran. `None` means no
    /// advisory index was supplied.
    pub advisories: Option<&'a [AdvisoryVerdict]>,
}
