//! `cudabom scan <target>...`.
//!
//! Runs the shared scan pipeline (safe extraction -> per-file facts -> component
//! identification -> optional advisory correlation) and renders the result in
//! the requested format.
//!
//! Output is deterministic: files are reported in the order extraction yields
//! them, per-file fact collections are sorted upstream, and findings are sorted
//! by id before rendering.

use cudabom_advisory::Verdict;
use cudabom_core::{Finding, Limits};
use cudabom_fatbin::{CapabilityManifest, GpuCode};
use serde::Serialize;

use crate::cli::{OutputFormat, ScanArgs};
use crate::commands::composition::Composition;
use crate::commands::pipeline::{self, FileReport};
use crate::exit::ExitStatus;

/// The full scan result for one invocation.
#[derive(Debug, Serialize)]
struct ScanReport {
    /// cudabom native schema version.
    schema_version: String,
    /// The targets scanned.
    targets: Vec<String>,
    /// Every file surfaced, with facts.
    files: Vec<FileReport>,
    /// CUDA-component findings, sorted by id.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    findings: Vec<Finding>,
    /// NVIDIA-provided descriptive metadata (description + license) for each
    /// found component, keyed by canonical name. Omitted when empty.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    catalog: std::collections::BTreeMap<String, crate::commands::pipeline::ComponentInfo>,
    /// GPU capability manifest (SM targets across all GPU code). Omitted when
    /// the artifact contains no GPU device code.
    #[serde(skip_serializing_if = "CapabilityManifest::is_empty")]
    capability: CapabilityManifest,
    /// Per-binary CUDA composition (links vs contains). Omitted when no binary
    /// linked or contained a CUDA component.
    #[serde(skip_serializing_if = "Composition::is_empty")]
    composition: Composition,
    /// Advisory correlation results, present only when `--advisories` is given.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    advisories: Option<AdvisoryReport>,
}

/// The advisory-correlation section of the report.
#[derive(Debug, Serialize)]
struct AdvisoryReport {
    /// Upstream provenance of the index, when recorded.
    #[serde(skip_serializing_if = "Option::is_none")]
    source_commit: Option<String>,
    /// A count of verdicts by kind, so a result reads deliberately rather than
    /// looking empty when nothing is affected.
    summary: AdvisorySummary,
    /// One entry per (finding, advisory) verdict.
    matches: Vec<AdvisoryMatch>,
    /// Always emitted: absence of a match is not proof of safety.
    caveat: String,
}

/// A tally of advisory verdicts across all findings.
#[derive(Debug, Default, Serialize)]
struct AdvisorySummary {
    /// Verdicts of `affected`.
    affected: usize,
    /// Verdicts of `not_affected` (positively shown fixed / out of range).
    not_affected: usize,
    /// Verdicts of `under_investigation` (matched, version could not resolve).
    under_investigation: usize,
}

impl AdvisorySummary {
    fn of(matches: &[AdvisoryMatch]) -> Self {
        Self::tally(matches.iter().map(|m| m.verdict))
    }

    /// Count verdicts into the three-way summary. Shared by every surface that
    /// summarizes a set of verdicts, so the tally lives in one place.
    fn tally(verdicts: impl Iterator<Item = Verdict>) -> Self {
        let mut s = Self::default();
        for v in verdicts {
            match v {
                Verdict::Affected => s.affected += 1,
                Verdict::NotAffected => s.not_affected += 1,
                Verdict::UnderInvestigation => s.under_investigation += 1,
            }
        }
        s
    }

    fn total(&self) -> usize {
        self.affected + self.not_affected + self.under_investigation
    }
}

/// A single advisory verdict for a finding.
#[derive(Debug, Serialize)]
struct AdvisoryMatch {
    advisory_id: String,
    component: String,
    /// The VEX verdict for this (finding, advisory) pair. Serializes to one of
    /// `affected`, `not_affected`, `under_investigation`.
    verdict: cudabom_advisory::Verdict,
    justification: String,
    /// Published severity (free text), when the advisory carried it.
    #[serde(skip_serializing_if = "Option::is_none")]
    severity: Option<String>,
    /// CVSS base score (0.0-10.0), when published.
    #[serde(skip_serializing_if = "Option::is_none")]
    cvss_score: Option<f64>,
    /// Publication date (CSAF initial_release_date), when published.
    #[serde(skip_serializing_if = "Option::is_none")]
    published: Option<String>,
    /// When set, the match was reached *indirectly*: the scanned library
    /// shipped in this CUDA toolkit release and the advisory is keyed to the
    /// toolkit (e.g. a `cuobjdump`/`nvdisasm`/Nsight bug), not the library
    /// itself. `None` for a direct component match.
    #[serde(skip_serializing_if = "Option::is_none")]
    via_toolkit_release: Option<String>,
    /// A longer human-readable description of the vulnerability (CSAF notes),
    /// for report context. Omitted when the advisory carried none.
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    /// Reference URLs (NVIDIA bulletin pages, canonical NVD page). Omitted when
    /// the advisory carried none.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    references: Vec<String>,
}

/// The standing caveat printed with any advisory results.
const ADVISORY_CAVEAT: &str =
    "advisory coverage may be incomplete; absence of a match is not proof of safety";

impl AdvisoryMatch {
    fn from_match(m: cudabom_advisory::Match) -> Self {
        Self {
            advisory_id: m.advisory_id,
            component: m.component,
            verdict: m.verdict,
            justification: m.justification,
            severity: m.severity,
            cvss_score: m.cvss_score,
            published: m.published,
            via_toolkit_release: m.via_toolkit_release,
            description: m.description,
            references: m.references,
        }
    }

    /// True when the match was reached indirectly via a CUDA toolkit release
    /// (the advisory concerns the toolkit, not this library specifically).
    fn is_toolkit_wide(&self) -> bool {
        self.via_toolkit_release.is_some()
    }
}

/// Split matches into the direct tier (advisory concerns this library) and the
/// toolkit-wide tier (reached via a CUDA toolkit release). The headline is
/// driven by the direct tier so toolkit-wide advisories never inflate it.
fn partition_tiers<'a>(
    matches: &[&'a AdvisoryMatch],
) -> (Vec<&'a AdvisoryMatch>, Vec<&'a AdvisoryMatch>) {
    matches.iter().copied().partition(|m| !m.is_toolkit_wide())
}

pub(crate) fn run(args: &ScanArgs) -> ExitStatus {
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

    let has_finding = pipeline::has_positive_finding(&outcome.findings);

    let advisories = outcome.advisory_matches.map(|matches| {
        let matches: Vec<AdvisoryMatch> =
            matches.into_iter().map(AdvisoryMatch::from_match).collect();
        AdvisoryReport {
            source_commit: outcome.advisory_source_commit,
            summary: AdvisorySummary::of(&matches),
            matches,
            caveat: ADVISORY_CAVEAT.to_string(),
        }
    });

    let has_affected = advisories
        .as_ref()
        .is_some_and(|adv| adv.summary.affected > 0);

    let report = ScanReport {
        schema_version: cudabom_core::SCHEMA_VERSION.to_string(),
        targets: args.targets.clone(),
        files: outcome.files,
        findings: outcome.findings,
        catalog: outcome.catalog,
        capability: outcome.capability,
        composition: outcome.composition,
        advisories,
    };

    match render(&report, args) {
        Ok(text) => {
            if let Err(status) = super::emit(args.output.as_deref(), &text) {
                return status;
            }
            exit_for(args.fail_on, has_finding, has_affected)
        }
        Err(err) => {
            eprintln!("cudabom: {err}");
            ExitStatus::Internal
        }
    }
}

/// Map the `--fail-on` threshold and result to an exit status. `scan` is a
/// reporting command: it succeeds (exit 0) unless the caller opted into a
/// failure threshold. Real policy enforcement is `gate`'s job.
fn exit_for(fail_on: crate::cli::FailOn, has_finding: bool, has_affected: bool) -> ExitStatus {
    use crate::cli::FailOn;
    let fail = match fail_on {
        FailOn::None => false,
        FailOn::Found => has_finding,
        FailOn::Affected => has_affected,
    };
    if fail {
        ExitStatus::Findings
    } else {
        ExitStatus::Success
    }
}

/// Render the report in the requested format, returning the rendered text.
/// The caller writes it to stdout or a file via `super::emit`.
fn render(report: &ScanReport, args: &ScanArgs) -> anyhow::Result<String> {
    // Advisory verdicts, mapped into the report crate's neutral form. Kept in
    // this scope so the borrow in `Report` outlives the render call.
    let verdicts: Option<Vec<cudabom_report::AdvisoryVerdict>> = report
        .advisories
        .as_ref()
        .map(|adv| adv.matches.iter().map(to_report_verdict).collect());

    let text = match args.format {
        OutputFormat::Json => serde_json::to_string_pretty(report)?,
        OutputFormat::Table => render_table(report, args.all_files),
        OutputFormat::Cyclonedx => render_cyclonedx(report)?,
        OutputFormat::Sarif => {
            cudabom_report::to_sarif(&report_input(report, verdicts.as_deref()))?
        }
        OutputFormat::Markdown => {
            cudabom_report::to_markdown(&report_input(report, verdicts.as_deref()))
        }
    };

    Ok(text)
}

/// Build the report crate's neutral input from the scan report.
fn report_input<'a>(
    report: &'a ScanReport,
    verdicts: Option<&'a [cudabom_report::AdvisoryVerdict]>,
) -> cudabom_report::Report<'a> {
    cudabom_report::Report {
        targets: &report.targets,
        findings: &report.findings,
        advisories: verdicts,
        tool_version: env!("CARGO_PKG_VERSION"),
    }
}

/// Map a CLI advisory match into the report crate's neutral verdict type.
fn to_report_verdict(m: &AdvisoryMatch) -> cudabom_report::AdvisoryVerdict {
    let verdict = match m.verdict {
        Verdict::Affected => cudabom_report::Verdict::Affected,
        Verdict::NotAffected => cudabom_report::Verdict::NotAffected,
        Verdict::UnderInvestigation => cudabom_report::Verdict::UnderInvestigation,
    };
    cudabom_report::AdvisoryVerdict {
        advisory_id: m.advisory_id.clone(),
        component: m.component.clone(),
        verdict,
        justification: m.justification.clone(),
        severity: m.severity.clone(),
        cvss_score: m.cvss_score,
        published: m.published.clone(),
        via_toolkit_release: m.via_toolkit_release.clone(),
        description: m.description.clone(),
        references: m.references.clone(),
    }
}

/// Render the findings as a CycloneDX 1.6 SBOM.
fn render_cyclonedx(report: &ScanReport) -> anyhow::Result<String> {
    let options = cudabom_sbom::SbomOptions {
        // Use the first target as the SBOM subject name.
        subject_name: report.targets.first().cloned(),
        subject_sha256: None,
        // Timestamp omitted for reproducible output.
        timestamp: None,
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
    };
    Ok(cudabom_sbom::to_json(&report.findings, &options)?)
}

/// A compact summary: one line per interesting file, with ELF highlights. By
/// default, files that carry no signal (unrecognized leaves such as source
/// headers and package metadata) are collapsed into a single summary line;
/// `all_files` restores the full per-file listing.
fn render_table(report: &ScanReport, all_files: bool) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let _ = writeln!(
        out,
        "cudabom scan  schema {}  files {}  findings {}",
        report.schema_version,
        report.files.len(),
        report.findings.len()
    );
    let mut suppressed = 0usize;
    for file in &report.files {
        // An "interesting" file carries a signal worth a line: a recognized
        // container/binary kind, parsed ELF or GPU facts, a parse error, or an
        // embedded fatbin. Unrecognized leaves (headers, text, metadata) are
        // noise on a real artifact and are collapsed unless `--all-files`.
        let interesting = file.kind != cudabom_extract::FileKind::Unknown
            || file.elf.is_some()
            || file.gpu_code.is_some()
            || file.parse_error.is_some()
            || !file.embedded_fatbins.is_empty();
        if !all_files && !interesting {
            suppressed += 1;
            continue;
        }
        let kind = file.kind.as_str();
        if let Some(elf) = &file.elf {
            let soname = elf.soname.as_deref().unwrap_or("-");
            let _ = writeln!(
                out,
                "  {} [{}] {:?} {} soname={} needed={} exports={}",
                file.path,
                kind,
                elf.elf_type,
                elf.architecture,
                soname,
                elf.needed.len(),
                elf.exported_symbols.len()
            );
        } else if let Some(gpu) = &file.gpu_code {
            let _ = writeln!(out, "  {} [{}] {}", file.path, kind, describe_gpu(gpu));
        } else if let Some(err) = &file.parse_error {
            let _ = writeln!(out, "  {} [{}] parse-error: {}", file.path, kind, err);
        } else {
            let _ = writeln!(out, "  {} [{}]", file.path, kind);
        }

        // Note any fatbins embedded in this file (indented under it).
        for fat in &file.embedded_fatbins {
            let _ = writeln!(
                out,
                "      +fatbin@{} version={} entries={}{}",
                fat.offset,
                fat.facts.version,
                fat.facts.entries.len(),
                if fat.facts.truncated {
                    " (truncated)"
                } else {
                    ""
                }
            );
        }
    }

    // Collapse the uninteresting files into one line so a real artifact's
    // report leads with signal rather than a wall of header/metadata paths.
    if suppressed > 0 {
        let _ = writeln!(
            out,
            "  ... and {suppressed} other file(s) with no CUDA signal (headers, metadata); use --all-files to list them"
        );
    }

    // Findings section: the identified CUDA components with confidence.
    if !report.findings.is_empty() {
        let _ = writeln!(out);
        let _ = writeln!(out, "findings:");
        for f in &report.findings {
            let version = format_version(&f.component);
            let _ = writeln!(
                out,
                "  [{}] {} {} ({})",
                f.confidence.as_str(),
                f.component.name,
                version,
                f.component.relationship.as_str(),
            );
            // Evidence, one line each, with the observed value (e.g. the
            // SHA-256 that matched) so the reader sees *why* it was identified.
            for e in &f.evidence {
                let _ = writeln!(out, "        evidence: {}", describe_evidence(e));
            }
            // NVIDIA-provided description/license/date, when the DB carried it.
            if let Some(info) = report.catalog.get(&f.component.name) {
                render_component_info(&mut out, info);
            }
        }
    }

    // GPU capability manifest section, when GPU code was present.
    render_capability(&mut out, &report.capability);

    // Per-binary composition section (links vs contains), when present.
    render_composition(&mut out, &report.composition);

    // Advisory correlation section, when present.
    if let Some(adv) = &report.advisories {
        render_advisories(&mut out, adv, report.findings.is_empty());
    }

    out
}

/// Render the advisory-correlation section: provenance, a severity-aware verdict
/// summary, and the matches grouped by the component (and the file) they
/// concern, as an aligned table. Affected advisories lead, highest severity
/// first. `-v` adds the full per-advisory justification and every reference URL.
/// `no_findings` distinguishes "nothing to correlate" from "correlated, none
/// affected".
fn render_advisories(out: &mut String, adv: &AdvisoryReport, no_findings: bool) {
    use std::fmt::Write as _;
    let verbose = crate::verbosity::enabled(crate::verbosity::Level::Verbose);
    let _ = writeln!(out);
    let _ = writeln!(out, "advisories:");
    if let Some(commit) = &adv.source_commit {
        let _ = writeln!(out, "  (index source: {commit})");
    }

    let s = &adv.summary;
    if s.total() > 0 {
        // Lead with a severity breakdown of the affected verdicts so "how bad
        // is it" is answerable from one line, not by reading every CVE.
        let affected: Vec<&AdvisoryMatch> = adv
            .matches
            .iter()
            .filter(|m| m.verdict == Verdict::Affected)
            .collect();
        // Direct hits (the advisory names this component itself) are the real
        // signal; toolkit-wide matches are reached indirectly via the CUDA
        // release that shipped this library and often concern *other* tools
        // (cuobjdump, nvdisasm, Nsight), so they are reported as a separate,
        // lower-priority tier and must not inflate the headline.
        let (direct_affected, toolkit_affected) = partition_tiers(&affected);
        let breakdown = severity_breakdown(&affected);
        let _ = writeln!(
            out,
            "  summary: {} affected{}, {} not affected, {} under investigation",
            s.affected, breakdown, s.not_affected, s.under_investigation
        );
        if !toolkit_affected.is_empty() {
            let _ = writeln!(
                out,
                "    of which {} direct, {} toolkit-wide (shipped in the same CUDA release; may not affect this file)",
                direct_affected.len(),
                toolkit_affected.len()
            );
        }
        // Headline: a direct hit when one exists; otherwise state plainly that
        // there are none and name the worst toolkit-wide CVE only as context.
        if let Some(worst) = most_severe(&direct_affected) {
            let _ = writeln!(out, "  most severe: {}", headline_line(worst));
        } else if let Some(worst) = most_severe(&toolkit_affected) {
            let _ = writeln!(
                out,
                "  most severe: no direct advisories; {} toolkit-wide (worst: {})",
                toolkit_affected.len(),
                headline_line(worst)
            );
        }
    }

    if adv.matches.is_empty() {
        if no_findings {
            let _ = writeln!(out, "  no findings to correlate");
        } else {
            let _ = writeln!(
                out,
                "  no advisory affects the identified component version(s)"
            );
        }
        let _ = writeln!(out, "  note: {}", adv.caveat);
        return;
    }

    if s.affected == 0 {
        // Matches exist but none are affected (e.g. a modern library past every
        // toolkit fix): say so explicitly before listing them.
        let _ = writeln!(
            out,
            "  no affected advisories for the identified component version(s)"
        );
    }

    // Group the matches by the component they concern, so each block of CVEs is
    // clearly attributed ("which component / file is affected and why").
    let mut components: Vec<&str> = adv.matches.iter().map(|m| m.component.as_str()).collect();
    components.sort_unstable();
    components.dedup();

    for component in components {
        let group: Vec<&AdvisoryMatch> = adv
            .matches
            .iter()
            .filter(|m| m.component == component)
            .collect();
        render_component_advisories(out, component, &group, verbose);
    }

    let _ = writeln!(out, "  note: {}", adv.caveat);
}

/// Render the advisories for one component, split into two tiers: **direct**
/// matches (the advisory names this component) first, then **toolkit-wide**
/// matches reached indirectly via the CUDA release that shipped the library
/// (these frequently concern other toolkit tools, e.g. cuobjdump, nvdisasm,
/// Nsight, and may not affect this file). Within each tier, affected leads
/// and worst-severity-first. In verbose mode each row is followed by its
/// justification, full description, and references.
fn render_component_advisories(
    out: &mut String,
    component: &str,
    matches: &[&AdvisoryMatch],
    verbose: bool,
) {
    use std::fmt::Write as _;
    let summary = AdvisorySummary::tally(matches.iter().map(|m| m.verdict));
    let (affected, not_affected, investigating) = (
        summary.affected,
        summary.not_affected,
        summary.under_investigation,
    );
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "  {component}: {affected} affected, {not_affected} not affected, {investigating} under investigation"
    );

    let (direct, toolkit) = partition_tiers(matches);

    if !direct.is_empty() {
        // Only label the tier when both tiers are present; otherwise the single
        // list speaks for itself.
        if !toolkit.is_empty() {
            let _ = writeln!(out, "    direct ({}):", direct.len());
        }
        render_match_rows(out, &direct, verbose);
    }

    if !toolkit.is_empty() {
        let release = toolkit
            .iter()
            .find_map(|m| m.via_toolkit_release.as_deref())
            .unwrap_or("the same release");
        let _ = writeln!(
            out,
            "    toolkit-wide ({}): shipped in CUDA {release}; keyed to the toolkit (e.g. cuobjdump/nvdisasm/Nsight), not necessarily this file",
            toolkit.len()
        );
        render_match_rows(out, &toolkit, verbose);
    }
}

/// Render a set of advisory matches as an aligned table, affected first and
/// worst-severity first, under per-severity sub-headers (indented four spaces,
/// rows six). The sub-headers sit one level under the component/tier heading.
fn render_match_rows(out: &mut String, matches: &[&AdvisoryMatch], verbose: bool) {
    use std::fmt::Write as _;
    // Fixed layout: severity sub-headers at 4 spaces, rows at 6, verbose detail
    // at 8, matching the component heading at 2.
    const HEADER_INDENT: usize = 4;
    const ROW_INDENT: usize = 6;
    const DETAIL_INDENT: usize = 8;
    let pad = " ".repeat(HEADER_INDENT);
    // Order: affected first, then worst severity, then CVSS, then id.
    let mut ordered: Vec<&AdvisoryMatch> = matches.to_vec();
    ordered.sort_by(|a, b| {
        verdict_order(a.verdict)
            .cmp(&verdict_order(b.verdict))
            .then_with(|| {
                severity_rank_label(b.severity.as_deref())
                    .0
                    .cmp(&severity_rank_label(a.severity.as_deref()).0)
            })
            .then_with(|| {
                b.cvss_score
                    .partial_cmp(&a.cvss_score)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .then_with(|| a.advisory_id.cmp(&b.advisory_id))
    });

    // Column widths. The CVE id column is the widest variable field; the rest
    // are fixed small widths, so a simple padding scheme aligns cleanly.
    let id_w = ordered
        .iter()
        .map(|m| m.advisory_id.len())
        .max()
        .unwrap_or(3)
        .max(3);

    let mut current_rank: Option<u8> = None;
    for m in &ordered {
        // A severity sub-header before each new severity group (affected only;
        // non-affected rows carry their verdict inline instead).
        if m.verdict == Verdict::Affected {
            let (rank, label) = severity_rank_label(m.severity.as_deref());
            if current_rank != Some(rank) {
                let count = ordered
                    .iter()
                    .filter(|x| x.verdict == Verdict::Affected)
                    .filter(|x| severity_rank_label(x.severity.as_deref()).0 == rank)
                    .count();
                let _ = writeln!(out, "{pad}{} ({count}):", label.to_uppercase());
                current_rank = Some(rank);
            }
        } else if current_rank != Some(u8::MAX) {
            // Transition into the non-affected block once, after affected.
            let others = ordered
                .iter()
                .filter(|x| x.verdict != Verdict::Affected)
                .count();
            if others > 0 {
                let _ = writeln!(out, "{pad}OTHER ({others}):");
            }
            current_rank = Some(u8::MAX);
        }
        render_advisory_row(out, m, id_w, ROW_INDENT);
        if verbose {
            render_advisory_detail(out, m, DETAIL_INDENT);
        }
        // A blank line between entries so each CVE reads as its own block
        // rather than a dense stack.
        out.push('\n');
    }
}

/// Sort key putting affected verdicts first, then under-investigation, then
/// not-affected.
fn verdict_order(verdict: Verdict) -> u8 {
    match verdict {
        Verdict::Affected => 0,
        Verdict::UnderInvestigation => 1,
        Verdict::NotAffected => 2,
    }
}

/// Width of an ISO date prefix (`YYYY-MM-DD`), used for the advisory date column.
const DATE_WIDTH: usize = 10;

/// Trim a timestamp to its `YYYY-MM-DD` date prefix on a char boundary.
fn trim_to_date(ts: &str) -> String {
    ts.chars().take(DATE_WIDTH).collect()
}

/// One aligned advisory row:
/// `  CVE-2025-33228   CVSS 7.3  2026-01-20  <summary…>` followed by its link.
/// For non-affected rows the verdict replaces the CVSS column. `indent` is the
/// number of leading spaces for the row; the link sits two spaces deeper.
fn render_advisory_row(out: &mut String, m: &AdvisoryMatch, id_w: usize, indent: usize) {
    use std::fmt::Write as _;
    let pad = " ".repeat(indent);
    let link_pad = " ".repeat(indent + 2);
    let status = if m.verdict == Verdict::Affected {
        m.cvss_score
            .map_or_else(|| "CVSS   -".to_string(), |v| format!("CVSS {v:>4}"))
    } else {
        // not_affected / under_investigation: show the verdict, not a score.
        format!("[{}]", m.verdict.as_str())
    };
    let date = m
        .published
        .as_deref()
        .map_or_else(|| "-".repeat(DATE_WIDTH), trim_to_date);
    let summary = one_line_summary(m.description.as_deref());
    let link = canonical_link(&m.references).unwrap_or("");
    let _ = writeln!(
        out,
        "{pad}{id:<id_w$}  {status:<9}  {date:<10}  {summary}",
        id = m.advisory_id,
    );
    // The link on its own indented line keeps the row aligned and clickable.
    if !link.is_empty() {
        let _ = writeln!(out, "{link_pad}{link}");
    }
}

/// Maximum characters of CVE summary shown inline in the default (non-verbose)
/// table row. The full text is always available in `-v`, the Markdown report,
/// and JSON.
const SUMMARY_MAX: usize = 100;

/// A compact one-line form of a CVE description for the default table row:
/// whitespace-collapsed, HTML stripped, and truncated to [`SUMMARY_MAX`] with
/// an ellipsis so a row never wraps into a paragraph. Full text lives in `-v`.
fn one_line_summary(description: Option<&str>) -> String {
    let Some(d) = description else {
        return String::new();
    };
    let collapsed = cudabom_report::clean_note(d);
    if collapsed.chars().count() <= SUMMARY_MAX {
        return collapsed;
    }
    // Truncate on a char boundary, preferring the last word break so we do not
    // cut a word in half, then append an ellipsis.
    let truncated: String = collapsed.chars().take(SUMMARY_MAX).collect();
    let trimmed = match truncated.rsplit_once(' ') {
        Some((head, _)) if head.len() >= SUMMARY_MAX / 2 => head,
        _ => truncated.trim_end(),
    };
    format!("{trimmed}…")
}

/// Verbose per-advisory detail printed beneath a row: justification, the full
/// description, and every reference URL. `indent` is the leading-space width.
fn render_advisory_detail(out: &mut String, m: &AdvisoryMatch, indent: usize) {
    use std::fmt::Write as _;
    let pad = " ".repeat(indent);
    if !m.justification.is_empty() {
        let _ = writeln!(out, "{pad}reason: {}", m.justification);
    }
    if let Some(desc) = &m.description {
        let desc = cudabom_report::clean_note(desc);
        if !desc.is_empty() {
            let _ = writeln!(out, "{pad}description: {desc}");
        }
    }
    if m.references.len() > 1 {
        let _ = writeln!(out, "{pad}references: {}", m.references.join("  "));
    }
}

/// A parenthetical severity breakdown of affected matches, e.g.
/// ` (4 high, 29 low)`. Empty when there are no affected matches.
fn severity_breakdown(affected: &[&AdvisoryMatch]) -> String {
    use std::collections::BTreeMap;
    if affected.is_empty() {
        return String::new();
    }
    // Count by normalized severity, ordered most-severe-first for display.
    let mut counts: BTreeMap<u8, (String, usize)> = BTreeMap::new();
    for m in affected {
        let (rank, label) = severity_rank_label(m.severity.as_deref());
        let entry = counts.entry(rank).or_insert((label, 0));
        entry.1 += 1;
    }
    let parts: Vec<String> = counts
        .values()
        .rev()
        .map(|(label, n)| format!("{n} {label}"))
        .collect();
    format!(" ({})", parts.join(", "))
}

/// The most severe affected match: highest severity rank, then highest CVSS,
/// then lowest advisory id so ties are deterministic.
fn most_severe<'a>(affected: &[&'a AdvisoryMatch]) -> Option<&'a AdvisoryMatch> {
    affected.iter().copied().min_by(|a, b| {
        let ra = severity_rank_label(a.severity.as_deref()).0;
        let rb = severity_rank_label(b.severity.as_deref()).0;
        // Most severe first: higher rank and higher CVSS should sort earlier,
        // so compare b-vs-a for those, then ascending id as the stable tiebreak.
        rb.cmp(&ra)
            .then_with(|| {
                b.cvss_score
                    .partial_cmp(&a.cvss_score)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .then_with(|| a.advisory_id.cmp(&b.advisory_id))
    })
}

/// A compact one-line headline for a single advisory, e.g.
/// `CVE-2025-33228 cudart (HIGH CVSS 7.3)`.
fn headline_line(m: &AdvisoryMatch) -> String {
    let score = m
        .cvss_score
        .map(|v| format!(" CVSS {v}"))
        .unwrap_or_default();
    let sev = m.severity.as_deref().unwrap_or("?").to_uppercase();
    format!("{} {} ({}{})", m.advisory_id, m.component, sev, score)
}

/// Map a free-text severity to a sort rank (higher = worse) and a normalized
/// lowercase label. Unknown severities rank lowest so they never masquerade as
/// the headline. The rank uses the shared `cudabom_report::severity_rank` so
/// the terminal table and Markdown report order severities identically.
fn severity_rank_label(severity: Option<&str>) -> (u8, String) {
    let rank = cudabom_report::severity_rank(severity);
    let label = match severity.map(str::to_ascii_lowercase) {
        Some(s) if !s.is_empty() => s,
        _ => "unrated".to_string(),
    };
    (rank, label)
}

/// The preferred single link for the compact view: the canonical NVD page when
/// present, else the first reference.
fn canonical_link(references: &[String]) -> Option<&str> {
    references
        .iter()
        .find(|u| u.contains("nvd.nist.gov"))
        .or_else(|| references.first())
        .map(String::as_str)
}

/// Render one component's NVIDIA-provided descriptive metadata beneath its
/// finding: description, license, and first-party release date(s).
fn render_component_info(out: &mut String, info: &crate::commands::pipeline::ComponentInfo) {
    use std::fmt::Write as _;
    let desc = info.description.as_deref().unwrap_or("-");
    let license = info.license.as_deref().unwrap_or("-");
    let _ = writeln!(out, "        {desc}  (license: {license})");
    if !info.release_dates.is_empty() {
        let dated = info
            .release_dates
            .iter()
            .map(|(label, date)| format!("{label} ({date})"))
            .collect::<Vec<_>>()
            .join(", ");
        let _ = writeln!(out, "        shipped in: {dated}");
    }
}

/// Render the per-binary composition: which CUDA components each file links
/// (dynamic dependencies) versus contains (embedded/vendored/static).
fn render_composition(out: &mut String, comp: &Composition) {
    use std::fmt::Write as _;
    if comp.is_empty() {
        return;
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "composition:");
    for bin in &comp.binaries {
        let _ = writeln!(out, "  {}", bin.path);
        for node in &bin.contains {
            let version = node.version.as_deref().unwrap_or("-");
            let _ = writeln!(
                out,
                "    contains {} {} ({:?}) [{}]{}",
                node.name,
                version,
                node.confidence,
                node.finding_id,
                fmt_node_verdicts(&node.advisories),
            );
        }
        for node in &bin.links {
            let version = node.version.as_deref().unwrap_or("-");
            let _ = writeln!(
                out,
                "    links    {} {} ({:?}) [{}]{}",
                node.name,
                version,
                node.confidence,
                node.finding_id,
                fmt_node_verdicts(&node.advisories),
            );
        }
    }
}

/// Format a node's advisory verdicts as a compact count summary, e.g.
/// `  advisories: 33 affected, 0 not affected`. The full per-CVE detail lives
/// in the `advisories:` section; repeating every id here would just duplicate
/// that wall of text against each file.
fn fmt_node_verdicts(verdicts: &[crate::commands::composition::NodeVerdict]) -> String {
    if verdicts.is_empty() {
        return String::new();
    }
    let summary = AdvisorySummary::tally(verdicts.iter().map(|v| v.verdict));
    let (affected, not_affected, investigating) = (
        summary.affected,
        summary.not_affected,
        summary.under_investigation,
    );
    let mut parts = vec![format!("{affected} affected")];
    if not_affected > 0 {
        parts.push(format!("{not_affected} not affected"));
    }
    if investigating > 0 {
        parts.push(format!("{investigating} under investigation"));
    }
    format!("  advisories: {}", parts.join(", "))
}

/// Render the GPU capability manifest, when the artifact has device code.
fn render_capability(out: &mut String, cap: &CapabilityManifest) {
    use std::fmt::Write as _;
    if cap.is_empty() {
        return;
    }
    let fmt_sm = |v: &[u32]| -> String {
        if v.is_empty() {
            "-".to_string()
        } else {
            v.iter()
                .map(|s| format!("sm_{s}"))
                .collect::<Vec<_>>()
                .join(",")
        }
    };
    let _ = writeln!(out);
    let _ = writeln!(out, "gpu-capability:");
    let _ = writeln!(out, "  gpu-code-units: {}", cap.gpu_code_units);
    let _ = writeln!(out, "  cubin-targets: [{}]", fmt_sm(&cap.cubin_sm_targets));
    let _ = writeln!(out, "  ptx-targets:   [{}]", fmt_sm(&cap.ptx_sm_targets));
}

/// Format a component's version for human output. When a strong signal maps to
/// several releases (byte-identical binary under multiple labels), the single
/// representative is shown with a `(+N more)` hint so the reader knows the exact
/// micro version is one of a set; `cudabom explain`/JSON carry the full list.
fn format_version(component: &cudabom_core::Component) -> String {
    let base = component.version.as_deref().unwrap_or("-").to_string();
    let extra = component.candidate_versions.len().saturating_sub(1);
    if extra > 0 {
        format!("{base} (+{extra} more)")
    } else {
        base
    }
}

/// Describe one piece of evidence for the table: its kind, the file it was
/// observed in, and the observed value (a known-file-hash shows the SHA-256,
/// abbreviated; a soname/symbol shows the string). This answers "why did it
/// identify this?" at a glance, instead of a bare count.
fn describe_evidence(e: &cudabom_core::Evidence) -> String {
    let kind = e.kind.as_str();
    let detail = e.detail.trim();
    let value = if detail.is_empty() {
        String::new()
    } else if detail.len() >= 32 && detail.chars().all(|c| c.is_ascii_hexdigit()) {
        format!(" sha256:{}…", &detail[..12])
    } else {
        format!(" {detail}")
    };
    let path = &e.location.path;
    if path.is_empty() {
        format!("{kind}{value}")
    } else {
        format!("{kind}{value}  in {path}")
    }
}

fn describe_gpu(gpu: &GpuCode) -> String {
    match gpu {
        GpuCode::Fatbin(f) => format!(
            "fatbin version={} entries={}{}",
            f.version,
            f.entries.len(),
            if f.truncated { " (truncated)" } else { "" }
        ),
        GpuCode::Ptx(p) => {
            let ver = p.isa_version.as_deref().unwrap_or("?");
            let targets: Vec<String> = p.targets.iter().map(|t| format!("sm_{t}")).collect();
            format!("ptx isa={ver} targets=[{}]", targets.join(","))
        }
    }
}
