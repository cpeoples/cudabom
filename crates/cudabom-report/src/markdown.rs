//! Markdown rendering for PR/MR comments.
//!
//! Produces a compact, deterministic Markdown summary: a heading with counts, a
//! findings table (component, version, confidence, relationship, evidence
//! count), and, when advisory correlation ran, an advisory table with the
//! standing coverage caveat. Cells are escaped so pipe characters in values do
//! not break the table.

use std::fmt::Write as _;

use crate::input::{Report, Verdict, ADVISORY_CAVEAT};

/// Placeholder for a Markdown table cell with no value (empty version, missing
/// severity, no references, and so on). A single hyphen reads cleanly in a
/// rendered table and keeps every empty cell consistent.
const EMPTY_CELL: &str = "-";

/// Render the report as Markdown.
#[must_use]
pub(crate) fn render(report: &Report<'_>) -> String {
    let mut out = String::new();

    // Heading and one-line summary.
    let _ = writeln!(out, "## cudabom scan");
    out.push('\n');
    let target_desc = if report.targets.is_empty() {
        "the provided input".to_string()
    } else {
        report
            .targets
            .iter()
            .map(|t| format!("`{}`", escape_inline(t)))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let _ = writeln!(
        out,
        "Scanned {target_desc}: **{} finding(s)**.",
        report.findings.len()
    );
    out.push('\n');

    render_findings_table(&mut out, report);

    if let Some(verdicts) = report.advisories {
        out.push('\n');
        render_advisory_table(&mut out, verdicts);
    }

    out
}

fn render_findings_table(out: &mut String, report: &Report<'_>) {
    if report.findings.is_empty() {
        let _ = writeln!(out, "_No CUDA components were identified._");
        return;
    }

    let _ = writeln!(out, "### Findings");
    out.push('\n');
    let _ = writeln!(
        out,
        "| Component | Version | Confidence | Relationship | Evidence |"
    );
    let _ = writeln!(out, "| --- | --- | --- | --- | --- |");
    for f in report.findings {
        let version = f.component.version.as_deref().unwrap_or(EMPTY_CELL);
        let _ = writeln!(
            out,
            "| {} | {} | {} | {} | {} |",
            escape_cell(&f.component.name),
            escape_cell(version),
            f.confidence.as_str(),
            f.component.relationship.as_str(),
            escape_cell(&evidence_summary(f)),
        );
    }
}

/// A readable summary of a finding's evidence for a table cell: the kind plus
/// the observed value (e.g. an abbreviated SHA-256 for a known-file-hash match),
/// so a reader sees *why* it matched, not just that N pieces of evidence exist.
fn evidence_summary(f: &cudabom_core::Finding) -> String {
    if f.evidence.is_empty() {
        return EMPTY_CELL.to_string();
    }
    f.evidence
        .iter()
        .map(|e| {
            let kind = e.kind.as_str().to_string();
            let detail = e.detail.trim();
            if detail.is_empty() {
                kind
            } else {
                format!("{kind} ({})", abbreviate_detail(detail))
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// Abbreviate a long evidence detail (such as a 64-hex-char SHA-256) to its
/// first 12 characters with an ellipsis, so the table stays readable while the
/// value remains recognizable. Short values pass through unchanged.
fn abbreviate_detail(detail: &str) -> String {
    let is_hash = detail.len() >= 32 && detail.chars().all(|c| c.is_ascii_hexdigit());
    if is_hash {
        format!("sha256:{}…", &detail[..12])
    } else if detail.chars().count() > 40 {
        let truncated: String = detail.chars().take(40).collect();
        format!("{truncated}…")
    } else {
        detail.to_string()
    }
}

fn render_advisory_table(out: &mut String, verdicts: &[crate::input::AdvisoryVerdict]) {
    let _ = writeln!(out, "### Advisories");
    out.push('\n');
    if verdicts.is_empty() {
        let _ = writeln!(out, "_No advisory matched the findings._");
        out.push('\n');
        let _ = writeln!(out, "> {ADVISORY_CAVEAT}.");
        return;
    }

    // Group verdicts by the component they concern, so a reader sees which
    // component each block of CVEs is about rather than one flat list.
    let mut components: Vec<&str> = verdicts.iter().map(|v| v.component.as_str()).collect();
    components.sort_unstable();
    components.dedup();

    for component in components {
        let mut rows: Vec<&crate::input::AdvisoryVerdict> = verdicts
            .iter()
            .filter(|v| v.component == component)
            .collect();
        // Affected first, then by severity (worst first), then CVSS, then id.
        rows.sort_by(|a, b| {
            verdict_order(a.verdict)
                .cmp(&verdict_order(b.verdict))
                .then_with(|| {
                    crate::severity_rank(b.severity.as_deref())
                        .cmp(&crate::severity_rank(a.severity.as_deref()))
                })
                .then_with(|| {
                    b.cvss_score
                        .partial_cmp(&a.cvss_score)
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
                .then_with(|| a.advisory_id.cmp(&b.advisory_id))
        });

        let affected = rows
            .iter()
            .filter(|v| v.verdict == Verdict::Affected)
            .count();
        let not_affected = rows
            .iter()
            .filter(|v| v.verdict == Verdict::NotAffected)
            .count();
        let investigating = rows
            .iter()
            .filter(|v| v.verdict == Verdict::UnderInvestigation)
            .count();
        let _ = writeln!(
            out,
            "**`{}`**: {} affected, {} not affected, {} under investigation.",
            escape_inline(component),
            affected,
            not_affected,
            investigating
        );
        out.push('\n');

        // Split into direct hits (the advisory names this component) and
        // toolkit-wide hits reached via the CUDA release that shipped it (often
        // other tools, cuobjdump/nvdisasm/Nsight, that may not affect this
        // file). Render each as its own clearly-labeled table.
        let direct: Vec<&crate::input::AdvisoryVerdict> = rows
            .iter()
            .copied()
            .filter(|v| v.via_toolkit_release.is_none())
            .collect();
        let toolkit: Vec<&crate::input::AdvisoryVerdict> = rows
            .iter()
            .copied()
            .filter(|v| v.via_toolkit_release.is_some())
            .collect();

        if !direct.is_empty() {
            if !toolkit.is_empty() {
                let _ = writeln!(out, "_Direct ({} advisory/advisories):_", direct.len());
                out.push('\n');
            }
            render_verdict_rows(out, &direct);
        }

        if !toolkit.is_empty() {
            let release = toolkit
                .iter()
                .find_map(|v| v.via_toolkit_release.as_deref())
                .unwrap_or("the same release");
            let _ = writeln!(
                out,
                "_Toolkit-wide ({}): shipped in CUDA {}; keyed to the CUDA toolkit (e.g. `cuobjdump`/`nvdisasm`/Nsight), not necessarily this file._",
                toolkit.len(),
                escape_inline(release)
            );
            out.push('\n');
            render_verdict_rows(out, &toolkit);
        }
    }

    let _ = writeln!(out, "> {ADVISORY_CAVEAT}.");
}

/// Render a set of advisory verdicts (already sorted) as one Markdown table.
fn render_verdict_rows(out: &mut String, rows: &[&crate::input::AdvisoryVerdict]) {
    let _ = writeln!(
        out,
        "| Advisory | Verdict | Severity | CVSS | Published | Summary | Links |"
    );
    let _ = writeln!(out, "| --- | --- | --- | ---: | --- | --- | --- |");
    for v in rows {
        let _ = writeln!(
            out,
            "| {} | {} | {} | {} | {} | {} | {} |",
            escape_cell(&v.advisory_id),
            verdict_badge(v.verdict),
            escape_cell(v.severity.as_deref().unwrap_or(EMPTY_CELL)),
            v.cvss_score
                .map_or_else(|| EMPTY_CELL.to_string(), |s| format!("{s:.1}")),
            escape_cell(v.published.as_deref().map_or(EMPTY_CELL, trim_date)),
            escape_cell(&summary_cell(v.description.as_deref())),
            reference_links(&v.references),
        );
    }
    out.push('\n');
}

/// Sort key putting affected verdicts before everything else.
fn verdict_order(v: Verdict) -> u8 {
    match v {
        Verdict::Affected => 0,
        Verdict::UnderInvestigation => 1,
        Verdict::NotAffected => 2,
    }
}

/// The leading date portion (`YYYY-MM-DD`) of a possibly-RFC3339 timestamp.
fn trim_date(published: &str) -> &str {
    match published.char_indices().nth(10) {
        Some((idx, _)) => &published[..idx],
        None => published,
    }
}

/// A description for a table cell: HTML tags removed and collapsed to a single
/// line (no raw newlines) so it never breaks the row. The full text is
/// preserved (not truncated).
fn summary_cell(description: Option<&str>) -> String {
    match description {
        None => EMPTY_CELL.to_string(),
        Some(d) => {
            let collapsed = crate::clean_note(d);
            if collapsed.is_empty() {
                EMPTY_CELL.to_string()
            } else {
                collapsed
            }
        }
    }
}

fn verdict_badge(v: Verdict) -> &'static str {
    match v {
        Verdict::Affected => "**affected**",
        Verdict::NotAffected => "not affected",
        Verdict::UnderInvestigation => "under investigation",
    }
}

/// Render reference URLs as Markdown links inside a table cell. The link label
/// is a short, readable name derived from the URL host (e.g. `nvd.nist.gov`),
/// so the cell stays compact. Multiple links are space-separated. Returns the
/// empty-cell placeholder when there are no references.
fn reference_links(references: &[String]) -> String {
    if references.is_empty() {
        return EMPTY_CELL.to_string();
    }
    references
        .iter()
        .map(|url| {
            let label = link_label(url);
            // A URL should not contain a pipe, but escape defensively so a
            // malformed one cannot break the table row.
            format!("[{}]({})", escape_cell(&label), escape_cell(url))
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// A short link label from a URL: its host without a leading `www.`, falling
/// back to the whole URL when no host can be extracted.
fn link_label(url: &str) -> String {
    let after_scheme = url.split("://").nth(1).unwrap_or(url);
    let host = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_scheme);
    host.strip_prefix("www.").unwrap_or(host).to_string()
}

/// Escape a value for use inside a Markdown table cell: pipes would end the
/// cell, and newlines would break the row.
fn escape_cell(s: &str) -> String {
    s.replace('|', "\\|").replace(['\r', '\n'], " ")
}

/// Escape a value for inline code/text (newlines only; backticks are handled by
/// the caller's fencing).
fn escape_inline(s: &str) -> String {
    s.replace(['\r', '\n'], " ").replace('`', "'")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::input::AdvisoryVerdict;
    use cudabom_core::{Component, Confidence, Finding, Relationship};

    fn finding(name: &str, version: Option<&str>, conf: Confidence) -> Finding {
        Finding {
            id: format!("f::{name}"),
            component: Component {
                name: name.to_string(),
                version: version.map(ToString::to_string),
                candidate_versions: Vec::new(),
                relationship: Relationship::EmbeddedCopy,
            },
            confidence: conf,
            evidence: Vec::new(),
            conflicts: Vec::new(),
        }
    }

    #[test]
    fn renders_findings_table() {
        let findings = vec![finding("cudart", Some("12.4.1"), Confidence::Exact)];
        let report = Report {
            targets: &["wheel.whl".to_string()],
            findings: &findings,
            advisories: None,
            tool_version: "0.1.0",
        };
        let md = render(&report);
        assert!(md.contains("## cudabom scan"));
        assert!(md.contains("**1 finding(s)**"));
        assert!(md.contains("| Component | Version | Confidence |"));
        assert!(md.contains("| cudart | 12.4.1 | exact | embedded-copy |"));
        // No advisory section when advisories is None.
        assert!(!md.contains("### Advisories"));
    }

    #[test]
    fn renders_advisory_table_with_caveat() {
        let findings = vec![finding("cudart", Some("12.3"), Confidence::Exact)];
        let verdicts = vec![AdvisoryVerdict {
            advisory_id: "CVE-2025-0001".to_string(),
            component: "cudart".to_string(),
            verdict: Verdict::Affected,
            justification: "within affected range".to_string(),
            severity: Some("HIGH".to_string()),
            cvss_score: Some(7.5),
            published: Some("2025-01-15T00:00:00Z".to_string()),
            via_toolkit_release: None,
            description: Some("A flaw in cudart.".to_string()),
            references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2025-0001".to_string()],
        }];
        let report = Report {
            targets: &["wheel.whl".to_string()],
            findings: &findings,
            advisories: Some(&verdicts),
            tool_version: "0.1.0",
        };
        let md = render(&report);
        assert!(md.contains("### Advisories"));
        assert!(md.contains("**`cudart`**: 1 affected"));
        assert!(md.contains("| CVE-2025-0001 | **affected** | HIGH | 7.5 | 2025-01-15 |"));
        assert!(
            md.contains("A flaw in cudart."),
            "the CVE description is surfaced as the summary:\n{md}"
        );
        assert!(
            md.contains("[nvd.nist.gov](https://nvd.nist.gov/vuln/detail/CVE-2025-0001)"),
            "reference renders as a Markdown link labeled by host:\n{md}"
        );
        assert!(md.contains("absence of a match is not proof of safety"));
    }

    #[test]
    fn empty_findings_states_none() {
        let report = Report {
            targets: &[],
            findings: &[],
            advisories: Some(&[]),
            tool_version: "0.1.0",
        };
        let md = render(&report);
        assert!(md.contains("_No CUDA components were identified._"));
        assert!(md.contains("_No advisory matched the findings._"));
    }

    #[test]
    fn escapes_pipe_in_cell() {
        let findings = vec![finding("cud|art", None, Confidence::Unknown)];
        let report = Report {
            targets: &[],
            findings: &findings,
            advisories: None,
            tool_version: "0.1.0",
        };
        let md = render(&report);
        assert!(md.contains("cud\\|art"));
    }

    #[test]
    fn trim_date_handles_multibyte_boundary() {
        // A multibyte char straddling byte index 10 must not panic.
        assert_eq!(trim_date("2024-01-02T03:04:05Z"), "2024-01-02");
        assert_eq!(trim_date("2024-01-0é2more"), "2024-01-0é");
        assert_eq!(trim_date("short"), "short");
    }

    #[test]
    fn abbreviate_detail_handles_multibyte_boundary() {
        // 41 multibyte chars: truncation must land on a char boundary.
        let long = "é".repeat(41);
        let out = abbreviate_detail(&long);
        assert_eq!(out, format!("{}…", "é".repeat(40)));
        // Hex hashes keep the ASCII fast path.
        let hash = "a".repeat(64);
        assert_eq!(abbreviate_detail(&hash), "sha256:aaaaaaaaaaaa…");
    }
}
