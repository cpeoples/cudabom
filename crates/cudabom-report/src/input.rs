//! Neutral report input types.
//!
//! The report crate renders [`cudabom_core::Finding`]s plus optional advisory
//! verdicts. To keep the reporting layer independent of the advisory database
//! (see `docs/architecture.md`), advisory results are passed in as this neutral
//! [`AdvisoryVerdict`] shape rather than importing `cudabom-advisory`. The CLI
//! maps advisory matches into these before rendering.

use cudabom_core::Finding;

/// A VEX-style advisory verdict for a finding, in neutral form.
#[derive(Debug, Clone, PartialEq)]
pub struct AdvisoryVerdict {
    /// Advisory identifier (e.g. a CVE id).
    pub advisory_id: String,
    /// The component the verdict concerns.
    pub component: String,
    /// One of `affected`, `not_affected`, `under_investigation`.
    pub verdict: Verdict,
    /// A short justification for explainability.
    pub justification: String,
    /// Published severity (free text, e.g. `HIGH`). `None` when absent.
    pub severity: Option<String>,
    /// CVSS base score (0.0-10.0). `None` when absent.
    pub cvss_score: Option<f64>,
    /// Publication date (CSAF `initial_release_date`). `None` when absent.
    pub published: Option<String>,
    /// When set, the match was reached indirectly via this CUDA toolkit release
    /// (the advisory is keyed to the toolkit, not the library itself). `None`
    /// for a direct component match.
    pub via_toolkit_release: Option<String>,
    /// A longer human-readable description of the vulnerability. `None` when the
    /// advisory carried none.
    pub description: Option<String>,
    /// Reference URLs for the advisory (NVIDIA bulletin pages, the canonical
    /// NVD page for a CVE id). Used as link targets in reports; empty when the
    /// advisory carried none.
    pub references: Vec<String>,
}

/// The three VEX outcomes cudabom emits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Affected,
    NotAffected,
    UnderInvestigation,
}

impl Verdict {
    /// The stable lowercase token used in output.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Affected => "affected",
            Self::NotAffected => "not_affected",
            Self::UnderInvestigation => "under_investigation",
        }
    }
}

/// Everything a renderer needs: the findings and any advisory verdicts, plus
/// provenance for report headers.
#[derive(Debug, Clone)]
pub struct Report<'a> {
    /// The scan targets, for the report header.
    pub targets: &'a [String],
    /// The identified components, already sorted by the caller.
    pub findings: &'a [Finding],
    /// Advisory verdicts, when advisory correlation ran. `None` means no
    /// advisory index was supplied; empty means it ran and matched nothing.
    pub advisories: Option<&'a [AdvisoryVerdict]>,
    /// cudabom version string for the tool identity in output.
    pub tool_version: &'a str,
}

/// The standing advisory caveat, printed with any advisory output.
pub const ADVISORY_CAVEAT: &str =
    "advisory coverage may be incomplete; absence of a match is not proof of safety";
