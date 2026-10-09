//! The shared scan pipeline: extraction -> facts -> identification -> advisory
//! correlation.
//!
//! Both `scan` (which reports) and `gate` (which enforces a policy) need the
//! same underlying work: walk each target safely, parse ELF/GPU-code facts,
//! identify components against the fingerprint database, and optionally
//! correlate against an advisory index. That work lives here so the two
//! commands cannot drift apart.

use cudabom_advisory::{match_findings_with_toolkit, AdvisoryIndex, Match};
use cudabom_core::{Error, Finding, Limits};
use cudabom_elf::ElfFacts;
use cudabom_extract::{scan_target, FileKind, ScannedFile};
use cudabom_fatbin::{CapabilityManifest, FatbinFacts, GpuCode};
use cudabom_identify::{FileFacts, FingerprintDb};
use serde::Serialize;

use crate::exit::ExitStatus;

/// Bound on embedded fatbins reported per file, to keep output bounded.
const MAX_EMBEDDED_FATBINS: usize = 256;
/// Bound on embedded ELFs reported per file, to keep output bounded. An
/// archive-like blob rarely hides more than a handful of real libraries; the
/// cap stops a buffer full of magic-like bytes from causing unbounded parse
/// attempts.
const MAX_EMBEDDED_ELFS: usize = 32;

/// One file surfaced by the scan, with its extracted facts.
#[derive(Debug, Serialize)]
pub(crate) struct FileReport {
    /// Logical path within the scanned target.
    pub(crate) path: String,
    /// sha256 of the file's bytes, if computed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) sha256: Option<String>,
    /// Detected content kind.
    pub(crate) kind: FileKind,
    /// ELF facts, when the file is an ELF that parsed successfully.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) elf: Option<ElfFacts>,
    /// PE facts, when the file is a Windows PE image that parsed successfully.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) pe: Option<cudabom_pe::PeFacts>,
    /// Fatbin containers embedded in this file, each with its byte offset.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) embedded_fatbins: Vec<EmbeddedFatbin>,
    /// ELF objects found embedded at a non-zero offset inside an otherwise
    /// unrecognized file (e.g. a CUDA `.so` hidden behind a junk prefix). Each
    /// records the byte offset and the parsed ELF facts.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) embedded_elfs: Vec<EmbeddedElf>,
    /// GPU code facts when the file *is* a standalone fatbin or PTX module.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) gpu_code: Option<GpuCode>,
    /// A note when an ELF failed to parse (recorded, not fatal to the scan).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) parse_error: Option<String>,
}

/// A fatbin container found embedded inside another file, with its offset.
#[derive(Debug, Serialize)]
pub(crate) struct EmbeddedFatbin {
    /// Byte offset of the container within the containing file.
    pub(crate) offset: usize,
    /// The container's facts.
    pub(crate) facts: FatbinFacts,
}

/// An ELF object found embedded at a non-zero offset inside an otherwise
/// unrecognized file, with its offset and parsed facts.
#[derive(Debug, Serialize)]
pub(crate) struct EmbeddedElf {
    /// Byte offset of the ELF header within the containing file.
    pub(crate) offset: usize,
    /// The embedded ELF's facts.
    pub(crate) facts: ElfFacts,
}

/// The result of running the pipeline over a set of targets.
pub(crate) struct PipelineOutcome {
    /// Every file surfaced, with facts.
    pub(crate) files: Vec<FileReport>,
    /// CUDA-component findings, sorted by id.
    pub(crate) findings: Vec<Finding>,
    /// Advisory matches, present only when an index was supplied. Sorted by
    /// advisory id then component.
    pub(crate) advisory_matches: Option<Vec<Match>>,
    /// Upstream provenance of the advisory index, when recorded.
    pub(crate) advisory_source_commit: Option<String>,
    /// The aggregated GPU capability manifest (SM targets across all GPU code).
    pub(crate) capability: CapabilityManifest,
    /// The per-binary CUDA composition (links vs contains), derived from
    /// findings.
    pub(crate) composition: crate::commands::composition::Composition,
    /// Descriptive metadata (NVIDIA-provided name + license) for each component
    /// that appears in the findings, keyed by canonical component name. Sourced
    /// first-party from the fingerprint DB (redist manifest); empty entries are
    /// omitted so absence stays honest.
    pub(crate) catalog: std::collections::BTreeMap<String, ComponentInfo>,
}

/// NVIDIA-provided descriptive metadata for one CUDA component.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub(crate) struct ComponentInfo {
    /// Human-readable description (e.g. `CUDA Runtime (cudart)`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) description: Option<String>,
    /// License name (e.g. `CUDA Toolkit`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) license: Option<String>,
    /// First-party release date(s) of the CUDA release(s) that shipped this
    /// component version, keyed by release label (e.g. `12.4.1` ->
    /// `2024-04-03`). Sourced from the redist manifest's `release_date`; empty
    /// when no dated release is known.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub(crate) release_dates: std::collections::BTreeMap<String, String>,
}

/// Run the pipeline over `targets`, using the given fingerprint database and
/// optional advisory index.
///
/// # Errors
/// Returns an [`ExitStatus`] (`Input` or `Internal`) when a target cannot be
/// scanned; the caller prints context and propagates the code.
pub(crate) fn run(
    targets: &[String],
    db: &FingerprintDb,
    advisory_index: Option<AdvisoryIndex>,
    limits: &Limits,
) -> Result<PipelineOutcome, ExitStatus> {
    let mut files = Vec::new();
    let mut findings = Vec::new();

    for (index, target) in targets.iter().enumerate() {
        crate::verbosity::detail!(
            "cudabom: [{}/{}] scanning {target}",
            index + 1,
            targets.len()
        );
        let path = std::path::Path::new(target);
        let result = scan_target(path, limits, |file: ScannedFile| {
            crate::verbosity::debug!("cudabom:   file {}", file.path());
            let (report, facts) = build_file_report(file);
            for file_facts in &facts {
                findings.extend(cudabom_identify::identify_file(file_facts, db));
            }
            files.push(report);
            Ok(())
        });

        if let Err(err) = result {
            eprintln!("cudabom: error scanning {target}: {err}");
            return Err(match err {
                // A malformed or oversized artifact, or an unreadable target,
                // is an input problem from the user's perspective.
                Error::Input(_) | Error::LimitExceeded(_) | Error::Malformed(_) => {
                    ExitStatus::Input
                }
                // Internal errors, and any future (non-exhaustive) variant, are
                // treated as internal so new kinds fail loudly.
                _ => ExitStatus::Internal,
            });
        }
    }

    // Deterministic finding order regardless of extraction order.
    findings.sort_by(|a, b| a.id.cmp(&b.id));

    // Correlate against advisories, if an index was provided.
    let (advisory_matches, advisory_source_commit) = match advisory_index {
        None => (None, None),
        Some(index) => {
            let source_commit = index.source_commit.clone();
            // Resolve a scanned (component, version) to the CUDA toolkit
            // release(s) that shipped it, using the first-party mapping the
            // fingerprint DB carries (derived from redist `release_label`).
            let toolkit_releases = |component: &str, version: &str| -> Vec<String> {
                db.components
                    .iter()
                    .find(|c| c.name == component)
                    .and_then(|c| c.release_versions.get(version))
                    .cloned()
                    .unwrap_or_default()
            };
            let matches = match_findings_with_toolkit(&findings, &index, toolkit_releases);
            (Some(matches), source_commit)
        }
    };

    // Aggregate the GPU capability manifest across every file's GPU code.
    let capability = build_capability(&files);

    // Assemble the per-binary composition (links vs contains) from findings,
    // annotated with advisory verdicts when an index was supplied.
    let composition = crate::commands::composition::build(&findings, advisory_matches.as_deref());

    // Build the descriptive catalog for the components that were found, from
    // the DB's first-party metadata. Only components present in findings are
    // included, and only when the DB carried a description or license.
    let mut catalog = std::collections::BTreeMap::new();
    for finding in &findings {
        let name = &finding.component.name;
        if catalog.contains_key(name) {
            continue;
        }
        if let Some(c) = db.components.iter().find(|c| &c.name == name) {
            // Dates of the release(s) that shipped this found version, if the
            // merged DB carried release dates (from_dir folds them in).
            let mut release_dates = std::collections::BTreeMap::new();
            if let Some(version) = &finding.component.version {
                if let Some(labels) = c.release_versions.get(version) {
                    for label in labels {
                        if let Some(date) = db.release_dates.get(label) {
                            release_dates.insert(label.clone(), date.clone());
                        }
                    }
                }
            }
            if c.description.is_some() || c.license.is_some() || !release_dates.is_empty() {
                catalog.insert(
                    name.clone(),
                    ComponentInfo {
                        description: c.description.clone(),
                        license: c.license.clone(),
                        release_dates,
                    },
                );
            }
        }
    }

    Ok(PipelineOutcome {
        files,
        findings,
        advisory_matches,
        advisory_source_commit,
        capability,
        composition,
        catalog,
    })
}

/// Aggregate the SM-architecture capability manifest from all scanned files:
/// standalone GPU code and every embedded fatbin.
fn build_capability(files: &[FileReport]) -> CapabilityManifest {
    let mut builder = cudabom_fatbin::CapabilityBuilder::new();
    for file in files {
        if let Some(code) = &file.gpu_code {
            builder.add_gpu_code(code);
        }
        for embedded in &file.embedded_fatbins {
            builder.add_embedded_fatbin(&embedded.facts);
        }
    }
    builder.build()
}

/// True if any finding was identified at Likely or Exact confidence.
pub(crate) fn has_positive_finding(findings: &[Finding]) -> bool {
    findings
        .iter()
        .any(|f| f.confidence >= cudabom_core::Confidence::Likely)
}

/// Load the fingerprint database from `path`, or fall back to the per-user data
/// directory's shard set when no path is given.
///
/// `path` may be a single shard file or a directory of `*.json` shards; a
/// directory is merged via [`FingerprintDb::from_dir`]. When `path` is `None`,
/// the resolved data directory (`<data>/fingerprints/cuda`) is used if it
/// exists; otherwise an empty database is returned (structural signals only).
pub(crate) fn load_db(path: Option<&str>) -> anyhow::Result<FingerprintDb> {
    // An explicit path wins; else fall back to the installed data dir.
    let resolved: Option<std::path::PathBuf> = match path {
        Some(p) => Some(std::path::PathBuf::from(p)),
        None => crate::datadir::default_db_dir(),
    };
    match resolved {
        None => Ok(FingerprintDb::default()),
        Some(p) if p.is_dir() => {
            let (db, report) = FingerprintDb::from_dir(&p).map_err(|e| anyhow::anyhow!("{e}"))?;
            // Version sets absorb the former "same bytes, different version"
            // case, so a clean load reports no conflicts. Any future genuine
            // conflict is surfaced as a count at normal verbosity and in full
            // under `-v`, never silently.
            if !report.conflicts.is_empty() {
                crate::verbosity::status!(
                    "cudabom: {} fingerprint DB conflict(s) across shards (use -v to list)",
                    report.conflicts.len()
                );
                for conflict in &report.conflicts {
                    crate::verbosity::detail!("cudabom: fingerprint DB conflict: {conflict}");
                }
            }
            Ok(db)
        }
        Some(p) => {
            let bytes = std::fs::read(&p).map_err(|e| {
                anyhow::anyhow!("cannot read fingerprint database {}: {e}", p.display())
            })?;
            FingerprintDb::from_json(&bytes).map_err(|e| anyhow::anyhow!("{e}"))
        }
    }
}

/// Load the advisory index from `path`, or fall back to the per-user data
/// directory's index when no path is given. Returns `None` when neither exists.
pub(crate) fn load_advisories(path: Option<&str>) -> anyhow::Result<Option<AdvisoryIndex>> {
    let resolved: Option<std::path::PathBuf> = match path {
        Some(p) => Some(std::path::PathBuf::from(p)),
        None => crate::datadir::default_advisories_file(),
    };
    match resolved {
        None => Ok(None),
        Some(p) => {
            let bytes = std::fs::read(&p)
                .map_err(|e| anyhow::anyhow!("cannot read advisory index {}: {e}", p.display()))?;
            let index = AdvisoryIndex::from_json(&bytes).map_err(|e| anyhow::anyhow!("{e}"))?;
            Ok(Some(index))
        }
    }
}

/// Load the fingerprint database and advisory index together, the common pair
/// every scan-oriented command needs. Prints the first failure as a `cudabom:`
/// diagnostic and returns [`ExitStatus::Input`] so callers can `?`-propagate it.
pub(crate) fn load_db_and_advisories(
    db: Option<&str>,
    advisories: Option<&str>,
) -> Result<(FingerprintDb, Option<AdvisoryIndex>), crate::exit::ExitStatus> {
    let db = crate::commands::or_input_error(load_db(db))?;
    let advisories = crate::commands::or_input_error(load_advisories(advisories))?;
    Ok((db, advisories))
}

/// Parse ELF facts for ELF files; find embedded fatbins; recognize standalone
/// GPU code (fatbin/PTX) for non-ELF files. Returns both the serializable
/// report entry and the neutral [`FileFacts`] the identifier consumes.
///
/// Returns one [`FileFacts`] for the host file plus one for each ELF found
/// embedded at a non-zero offset inside an otherwise unrecognized file, so the
/// identifier sees a CUDA library even when it is hidden behind a junk prefix
/// or wrapped in a container cudabom does not natively unpack.
fn build_file_report(file: ScannedFile) -> (FileReport, Vec<FileFacts>) {
    let mut elf = None;
    let mut pe = None;
    let mut parse_error = None;
    let mut embedded_fatbins = Vec::new();
    let mut embedded_elfs = Vec::new();
    let mut gpu_code = None;

    if file.kind == FileKind::Elf {
        match cudabom_elf::parse(&file.bytes) {
            Ok(facts) => elf = Some(facts),
            Err(e) => parse_error = Some(e.to_string()),
        }
        // An ELF may carry one or more fatbin containers in its
        // `.nv_fatbin`/`__nv_fatbin` sections. Scanning the whole ELF for the
        // wrapper magic catches them regardless of section naming and validates
        // each by fully parsing it.
        embedded_fatbins = cudabom_fatbin::find_embedded_fatbins(&file.bytes, MAX_EMBEDDED_FATBINS)
            .into_iter()
            .map(|(offset, facts)| EmbeddedFatbin { offset, facts })
            .collect();
    } else if file.kind == FileKind::Pe {
        // A Windows PE image (DLL/EXE): extract PE facts (machine, imports,
        // exports, sections, and the VS_VERSIONINFO version strings). A parse
        // failure is recorded, never fatal.
        match cudabom_pe::parse(&file.bytes) {
            Ok(facts) => pe = Some(facts),
            Err(e) => parse_error = Some(e.to_string()),
        }
    } else {
        // An unrecognized leaf. First, it may be a standalone fatbin or PTX
        // module surfaced directly (or from an archive): recognize it.
        gpu_code = cudabom_fatbin::inspect(&file.bytes);
        // Otherwise it may hide a real ELF at a non-zero offset: a CUDA `.so`
        // behind a junk prefix, or wrapped in a container we do not natively
        // unpack. Scan for ELF headers past offset 0 and validate each by a
        // full parse, so only genuine libraries are surfaced, never a stray
        // run of magic bytes. This is reported honestly as *embedded at offset
        // N*, distinct from a host-file ELF.
        if gpu_code.is_none() {
            embedded_elfs = cudabom_elf::find_embedded_elf(&file.bytes, MAX_EMBEDDED_ELFS)
                .into_iter()
                .map(|(offset, facts)| EmbeddedElf { offset, facts })
                .collect();
        }
    }

    // The host file's facts.
    let host_facts = FileFacts {
        path: file.location.path.clone(),
        sha256: file.location.sha256.clone(),
        layer_digest: file.location.layer_digest.clone(),
        elf: elf.clone(),
        pe: pe.clone(),
        gpu_code: gpu_code.clone(),
    };

    // One identification input per embedded ELF, tagged with its offset in the
    // logical path so a finding is traceable to where the library was hidden.
    // The embedded bytes are not re-hashed as the host file's sha256 (that
    // would misattribute the whole-file hash to a sub-slice); identity comes
    // from the embedded ELF's own build-id/symbols.
    let mut facts = vec![host_facts];
    for embedded in &embedded_elfs {
        facts.push(FileFacts {
            path: format!("{}@{}", file.location.path, embedded.offset),
            sha256: None,
            layer_digest: file.location.layer_digest.clone(),
            elf: Some(embedded.facts.clone()),
            pe: None,
            gpu_code: None,
        });
    }

    let report = FileReport {
        path: file.location.path,
        sha256: file.location.sha256,
        kind: file.kind,
        elf,
        pe,
        embedded_fatbins,
        embedded_elfs,
        gpu_code,
        parse_error,
    };

    (report, facts)
}
