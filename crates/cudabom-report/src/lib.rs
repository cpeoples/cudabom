//! Output rendering for cudabom.
//!
//! Renders [`cudabom_core::Finding`]s (and optional advisory verdicts) into the
//! reporting formats: SARIF 2.1.0 for code scanning and Markdown for PR/MR
//! comments. CycloneDX output lives in `cudabom-sbom`; the native JSON and
//! terminal table are produced by the CLI directly from its richer report.
//!
//! All output is deterministic (stable ordering) so diffs and snapshot tests
//! are meaningful. To keep the reporting layer independent of the advisory
//! database (see `docs/architecture.md`), advisory results are passed in via the
//! neutral [`AdvisoryVerdict`] type rather than depending on `cudabom-advisory`.

mod input;
mod markdown;
mod sarif;
mod text;

pub use input::{AdvisoryVerdict, Report, Verdict, ADVISORY_CAVEAT};
pub use text::{clean_note, severity_rank, strip_html};

/// Render the report as a SARIF 2.1.0 log.
///
/// # Errors
/// Returns an error only if JSON serialization fails.
pub fn to_sarif(report: &Report<'_>) -> Result<String, serde_json::Error> {
    sarif::render(report)
}

/// Render the report as a Markdown summary suitable for a PR/MR comment.
#[must_use]
pub fn to_markdown(report: &Report<'_>) -> String {
    markdown::render(report)
}
