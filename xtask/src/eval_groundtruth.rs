//! `cargo xtask eval`: measured comparison against other tools.
//!
//! This runs cudabom and (when installed) OWASP blint, Syft, and Trivy against
//! the same set of real artifacts and records, per tool and per capability,
//! what each one actually reports. The point is a *fair, reproducible* answer
//! to "is cudabom more authoritative for CUDA identity?": grounded in tool
//! output, not assertion.
//!
//! Design choices that keep it honest:
//!
//! - **No invented data.** Every cell is derived from a tool's own output on
//!   the artifact in front of it. A tool that is not installed is recorded as
//!   `not installed`, never as a failure or a win for cudabom.
//! - **cudabom is run exactly as a user would**, through the release binary and
//!   the committed fingerprint DB + advisory index: no privileged path.
//! - **Ground truth is the artifact itself.** For each target we record whether
//!   a tool (a) named the CUDA component, (b) pinned its exact version, and
//!   (c) correlated it to any CVE. Those are the three steps that matter for
//!   CUDA identity, and they are observable in each tool's output.
//!
//! Targets: pass `--targets <dir>` to scan every regular file under a
//! directory (e.g. an unpacked `./corpus`), or `--target <file>` one or more
//! times. With neither, the harness scans the committed NGC fixtures as a
//! smoke run so `eval` always does *something* from a clean clone, and prints a
//! note that a real artifact corpus produces the authoritative numbers.
//!
//! Output: a machine-readable `eval.json` (under `--out`, default `target/`)
//! and, with `--write-comparison`, the rendered capability table spliced into
//! `docs/comparison.md` between its result markers.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};
use cudabom_identify::CorpusLock;

use crate::eval_tools::{blint_in_venv, human_bytes, human_ms, probe, yesno, TimedRun};
use crate::verbosity::{detail, status};
use crate::{flag, has_flag};

/// Reduce a timed tool run to the two performance figures the comparison keeps.
fn perf_of(run: &TimedRun) -> Perf {
    Perf {
        wall_ms: run.wall_ms,
        peak_rss_bytes: run.peak_rss_bytes,
    }
}

/// cudabom's classification plus findings, CVE count, and run performance.
type CudabomEval = (GtStatus, Vec<(String, String, String)>, usize, Option<Perf>);

/// Classify every target against ground truth across all tools, producing one
/// accuracy row per binary. Per-binary timing is retained for the JSON detail;
/// the headline performance comes from the fair whole-corpus run.
fn build_accuracy_rows<'a>(
    targets: &'a [GtTarget],
    cudabom: &Path,
    db: &str,
    advisories: &str,
    have_blint: bool,
    have_syft: bool,
    have_trivy: bool,
) -> Vec<GtRow<'a>> {
    let mut rows: Vec<GtRow<'a>> = Vec::new();
    for t in targets {
        detail!("xtask: eval {} ({} {})", t.name, t.component, t.version);
        let (cb_status, cb_got, cb_cves, cb_perf) = eval_cudabom(cudabom, t, db, advisories);
        let (syft_named, syft_perf) = if have_syft {
            let (named, run) =
                crate::eval_tools::syft_names_cuda_timed(&t.path.display().to_string(), false);
            (Some(named), run.as_ref().map(perf_of))
        } else {
            (None, None)
        };
        let (trivy_cve, trivy_perf) = if have_trivy {
            let (cve, run) =
                crate::eval_tools::trivy_has_cve_timed(&t.path.display().to_string(), false);
            (Some(cve), run.as_ref().map(perf_of))
        } else {
            (None, None)
        };
        let (blint_ran, blint_named, blint_perf) = if have_blint {
            let (ran, named, run) = crate::eval_tools::blint_probe_timed(&t.path);
            (Some(ran), Some(named), run.as_ref().map(perf_of))
        } else {
            (None, None, None)
        };
        rows.push(GtRow {
            target: t,
            cb_status,
            cb_got,
            cb_cves,
            cb_perf,
            syft_named,
            syft_perf,
            trivy_cve,
            trivy_perf,
            blint_ran,
            blint_named,
            blint_perf,
        });
    }
    rows
}

/// Stage every resolved target into one flat directory of symlinks so each tool
/// can be launched **once** over the whole corpus (amortizing process startup
/// over an identical input), then measure cudabom and each installed competitor
/// with a single whole-tree invocation. This is the fair performance measure:
/// outcome recorded beside cost, no tool credited for a fast empty run.
fn measure_corpus_perf(
    targets: &[GtTarget],
    cudabom: &Path,
    db: &str,
    advisories: &str,
    have_blint: bool,
    have_syft: bool,
    have_trivy: bool,
) -> Result<Vec<FairRow>> {
    let stage = std::env::temp_dir().join("cudabom-eval-corpus-stage");
    let _ = std::fs::remove_dir_all(&stage);
    std::fs::create_dir_all(&stage)
        .with_context(|| format!("creating stage dir {}", stage.display()))?;
    // Each input gets its own uniquely named subdirectory, so any path a tool
    // reports (even a static-archive member nested below the file) still
    // contains that segment and can be attributed back to one top-level input.
    // Width is sized to the corpus so attribution stays unambiguous past 999.
    let width = targets.len().max(1).to_string().len();
    let stage_dirs: Vec<String> = (0..targets.len())
        .map(|i| format!("input{i:0width$}"))
        .collect();
    for (t, dir) in targets.iter().zip(&stage_dirs) {
        // Hard-link (fall back to copy across filesystems) rather than symlink:
        // the directory walkers do not follow symlinks (a deliberate safety
        // choice), so a symlinked stage would scan as empty.
        let name = t.path.file_name().and_then(|n| n.to_str()).unwrap_or("bin");
        let sub = stage.join(dir);
        std::fs::create_dir_all(&sub)
            .with_context(|| format!("creating stage subdir {}", sub.display()))?;
        let link = sub.join(name);
        if std::fs::hard_link(&t.path, &link).is_err() {
            std::fs::copy(&t.path, &link)
                .with_context(|| format!("staging {} -> {}", t.path.display(), link.display()))?;
        }
    }

    let mut rows = vec![
        FairRow {
            tool: "cudabom",
            scan: crate::eval_tools::cudabom_scan_dir(cudabom, &stage, db, advisories),
            absent: "error",
        },
        FairRow {
            tool: "blint",
            scan: have_blint
                .then(|| crate::eval_tools::blint_scan_dir(&stage))
                .flatten(),
            absent: "not installed",
        },
        FairRow {
            tool: "Syft",
            scan: have_syft
                .then(|| crate::eval_tools::syft_scan_dir(&stage.to_string_lossy(), false))
                .flatten(),
            absent: "not installed",
        },
        FairRow {
            tool: "Trivy",
            scan: have_trivy
                .then(|| crate::eval_tools::trivy_scan_dir(&stage.to_string_lossy(), false))
                .flatten(),
            absent: "not installed",
        },
    ];
    // Normalize every tool's "named" figure to a comparable unit: the number of
    // distinct top-level input files (the `NNN` stage subdirs) it associated
    // with a CUDA verdict. This removes the static-archive member explosion that
    // makes blint's raw object count (hundreds per `.a`) look incomparable to
    // cudabom's per-component identities.
    for row in &mut rows {
        if let Some(scan) = &mut row.scan {
            if !scan.cuda_paths.is_empty() {
                scan.named_files = Some(distinct_input_files(&scan.cuda_paths, &stage_dirs));
            }
        }
    }
    Ok(rows)
}

/// Count distinct top-level input files from a tool's reported CUDA paths, by
/// matching each path's segments against the known staged subdirectory names.
/// Paths with no recognizable stage segment cannot be attributed and are
/// ignored.
fn distinct_input_files(paths: &[String], stage_dirs: &[String]) -> usize {
    let known: std::collections::BTreeSet<&str> = stage_dirs.iter().map(String::as_str).collect();
    let mut seen = std::collections::BTreeSet::new();
    for p in paths {
        if let Some(dir) = p.split(['/', '\\']).find(|seg| known.contains(*seg)) {
            seen.insert(dir);
        }
    }
    seen.len()
}

/// Pull + export a container image and measure cudabom, Syft, and Trivy over
/// the same CUDA subtree (blint is per-binary forensics, reported `n/a`). Opt-in
/// via `--container-image <ref>`; returns `None` (so the row renders as pending)
/// when Docker is unavailable or the pull/export fails.
fn measure_container_perf(
    image: &str,
    cudabom: &Path,
    db: &str,
    advisories: &str,
    have_syft: bool,
    have_trivy: bool,
) -> Option<ContainerPerf> {
    if !crate::eval_tools::probe_docker() {
        status!("xtask: container row skipped (docker not available)");
        return None;
    }
    let work = std::env::temp_dir().join("cudabom-eval-container");
    let _ = std::fs::remove_dir_all(&work);
    let exported = match crate::eval_tools::export_image_rootfs(image, &work) {
        Ok(e) => e,
        Err(e) => {
            status!("xtask: container row skipped ({e:#})");
            return None;
        }
    };
    let dir_s = exported.scan_dir.to_string_lossy().to_string();
    let rows = vec![
        FairRow {
            tool: "cudabom",
            scan: crate::eval_tools::cudabom_scan_dir(cudabom, &exported.scan_dir, db, advisories),
            absent: "error",
        },
        FairRow {
            tool: "blint",
            scan: None,
            absent: "n/a (per-binary)",
        },
        FairRow {
            tool: "Syft",
            scan: have_syft
                .then(|| crate::eval_tools::syft_scan_dir(&dir_s, false))
                .flatten(),
            absent: "not installed",
        },
        FairRow {
            tool: "Trivy",
            scan: have_trivy
                .then(|| crate::eval_tools::trivy_scan_dir(&dir_s, false))
                .flatten(),
            absent: "not installed",
        },
    ];
    Some(ContainerPerf {
        image: image.to_string(),
        digest: exported.digest,
        scope: exported.scope,
        rows,
    })
}

/// Default directory written to when `--out` is omitted.
const DEFAULT_OUT_DIR: &str = "target";
/// Comparison doc whose result section `--write-comparison` rewrites.
const COMPARISON_DOC: &str = "docs/comparison.md";
/// Markers in `comparison.md` the generated table is spliced between.
const RESULT_BEGIN: &str = "<!-- eval:results:begin -->";
const RESULT_END: &str = "<!-- eval:results:end -->";
/// Fallback smoke targets when the caller supplies none.
const SMOKE_TARGETS: &[&str] = &[
    "fixtures/ngc/sbom.cyclonedx.json",
    "fixtures/ngc/vex.cyclonedx.json",
];

/// Committed eval corpus manifest (a `CorpusLock`): the real NVIDIA archives,
/// with per-entry ground truth (component/version/platform) and NVIDIA's own
/// sha256. Text only: the binaries it points at are never committed.
const DEFAULT_MANIFEST: &str = "eval/groundtruth.manifest.json";
/// Directory the eval corpus is downloaded + unpacked into (gitignored).
const DEFAULT_CORPUS_DIR: &str = "corpus/eval";

/// The tools we compare, in table column order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tool {
    Cudabom,
    Blint,
    Syft,
    Trivy,
}

impl Tool {
    const ALL: [Tool; 4] = [Tool::Cudabom, Tool::Blint, Tool::Syft, Tool::Trivy];

    fn label(self) -> &'static str {
        match self {
            Tool::Cudabom => "cudabom",
            Tool::Blint => "blint",
            Tool::Syft => "Syft",
            Tool::Trivy => "Trivy",
        }
    }
}

/// What a single tool reported about a single target, reduced to the three
/// CUDA-identity steps plus a liveness flag.
///
/// The four booleans are intentionally distinct observable facts (not a state
/// enum): a tool can run, name the component, pin the version, and correlate a
/// CVE in any combination, and the comparison table reports each independently.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Default)]
struct ToolResult {
    /// The tool is installed and ran to completion on this target.
    ran: bool,
    /// The tool named a CUDA component (by name or an unmistakable soname).
    named_cuda: bool,
    /// The tool pinned the exact CUDA version string.
    pinned_version: bool,
    /// The tool correlated the component to at least one CVE.
    correlated_cve: bool,
    /// Raw count of components/findings the tool emitted (diagnostic only).
    item_count: usize,
}

/// Per-target record across all tools.
#[derive(Debug)]
struct TargetReport {
    target: String,
    results: BTreeMap<&'static str, ToolResult>,
}

/// `cargo xtask eval [--manifest <lock>] [--download] [--corpus <dir>]
/// [--target <file>]... [--targets <dir>] [--out <dir>] [--write-comparison]`
pub(crate) fn run(args: &[String]) -> Result<()> {
    // Distribution mode: evaluate against real distribution artifacts (PyPI
    // wheels, conda packages, container images, stripped/renamed copies) rather
    // than pristine redist archives. This is the "cast a wider net" run.
    if has_flag(args, "--distribution") {
        return crate::eval_distribution::run(args);
    }
    // Ground-truth mode: when a corpus manifest is in play (either explicitly,
    // or the default manifest exists), evaluate cudabom and the competitors
    // against real binaries whose expected identity is known, classifying each
    // as OK / version-mismatch / miss / crash. This is the authoritative
    // "what do we miss, where are the bugs?" run.
    let manifest_arg = flag(args, "--manifest");
    let use_manifest = manifest_arg.is_some()
        || has_flag(args, "--download")
        || (flag(args, "--targets").is_none()
            && !has_flag(args, "--target")
            && Path::new(DEFAULT_MANIFEST).exists());
    if use_manifest {
        let manifest = manifest_arg.unwrap_or_else(|| DEFAULT_MANIFEST.to_string());
        return run_ground_truth(args, &manifest);
    }
    run_targets(args)
}

/// A single tool's classification against a known-truth binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GtStatus {
    /// Named the component and pinned the exact ground-truth version.
    Exact,
    /// Named the component but with a different / imprecise version.
    VersionMismatch,
    /// Produced no finding for a binary that is a known CUDA library (a miss).
    Miss,
    /// A static `.a` with more ELF members than the fingerprinter indexes
    /// (`MAX_STATIC_MEMBERS`): `cudabom` intentionally skips these
    /// build-artifact aggregates (member hashes don't survive static linking),
    /// so producing no finding is correct, not a miss.
    SkippedAggregate,
    /// cudabom errored / crashed on the input (a bug).
    Error,
}

impl GtStatus {
    fn label(self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::VersionMismatch => "version-mismatch",
            Self::Miss => "MISS",
            Self::SkippedAggregate => "skipped-aggregate",
            Self::Error => "ERROR",
        }
    }
}

/// One real binary resolved from the corpus, with its known identity.
struct GtTarget {
    path: PathBuf,
    name: String,
    component: String,
    version: String,
    platform: String,
}

/// Per-tool performance for one binary: wall time and peak RSS.
#[derive(Clone, Copy, Default)]
struct Perf {
    wall_ms: u128,
    peak_rss_bytes: u64,
}

/// One tool's fair, whole-corpus performance: a single invocation over an
/// identical input tree, carrying the outcome it produced alongside its cost.
struct FairRow {
    tool: &'static str,
    /// `None` when the tool was not run (not installed, or n/a for this corpus).
    scan: Option<crate::eval_tools::DirScan>,
    /// Reason shown when `scan` is `None` (e.g. "not installed", "n/a").
    absent: &'static str,
}

/// The two fair performance tables: loose-binary corpus and container corpus.
struct FairPerf {
    /// How many binaries the loose-binary single-run scanned.
    corpus_n: usize,
    corpus: Vec<FairRow>,
    /// `None` when no container row was produced (Docker/image unavailable).
    container: Option<ContainerPerf>,
}

/// The container-corpus fair table plus provenance for the note.
struct ContainerPerf {
    image: String,
    digest: String,
    scope: String,
    rows: Vec<FairRow>,
}

/// A row of the ground-truth report: one binary across all tools.
struct GtRow<'a> {
    target: &'a GtTarget,
    cb_status: GtStatus,
    cb_got: Vec<(String, String, String)>, // (name, version, confidence)
    cb_cves: usize,                        // advisories cudabom correlated for this binary
    cb_perf: Option<Perf>,
    syft_named: Option<bool>,
    syft_perf: Option<Perf>,
    trivy_cve: Option<bool>,
    trivy_perf: Option<Perf>,
    blint_ran: Option<bool>,
    blint_named: Option<bool>,
    blint_perf: Option<Perf>,
}

/// Ground-truth evaluation: fetch (optionally) and unpack the corpus manifest,
/// resolve each archive to its real primary library, then run cudabom and the
/// competitors against every binary and classify the result against the known
/// identity. Emits `eval-groundtruth.json` and a readable summary.
fn run_ground_truth(args: &[String], manifest_path: &str) -> Result<()> {
    let cudabom = locate_cudabom()?;
    // Default to the fingerprints parent so every per-product shard tree
    // (cuda, cudnn, nccl, ...) is loaded; the DB loader reads it recursively.
    let db =
        flag(args, "--db").unwrap_or_else(|| cudabom_core::paths::FINGERPRINTS_DIR.to_string());
    let advisories = flag(args, "--advisories")
        .unwrap_or_else(|| cudabom_core::paths::ADVISORY_INDEX.to_string());
    let corpus_dir =
        PathBuf::from(flag(args, "--corpus").unwrap_or_else(|| DEFAULT_CORPUS_DIR.to_string()));

    let bytes = std::fs::read(manifest_path)
        .with_context(|| format!("reading eval manifest {manifest_path}"))?;
    let lock =
        CorpusLock::from_json(&bytes).map_err(|e| anyhow::anyhow!("{manifest_path}: {e}"))?;
    if lock.entries.is_empty() {
        bail!("eval manifest {manifest_path} has no entries");
    }
    status!(
        "xtask: eval ground-truth from {manifest_path} ({} archive(s))",
        lock.entries.len()
    );

    if has_flag(args, "--download") {
        download_and_unpack(&lock, &corpus_dir)?;
    } else if !corpus_dir.exists() {
        bail!(
            "eval corpus not found at {}; pass --download to fetch it (into the gitignored \
             corpus dir), or point --corpus at an existing unpacked corpus",
            corpus_dir.display()
        );
    }

    let targets = resolve_targets(&lock, &corpus_dir);
    if targets.is_empty() {
        bail!(
            "no primary libraries resolved under {}; did the download/unpack succeed?",
            corpus_dir.display()
        );
    }

    let (have_blint, have_syft, have_trivy) = crate::eval_tools::probe_competitors();
    status!(
        "xtask: competitors: blint: {}, syft: {}, trivy: {}",
        yesno(have_blint),
        yesno(have_syft),
        yesno(have_trivy)
    );

    let rows = build_accuracy_rows(
        &targets,
        &cudabom,
        &db,
        &advisories,
        have_blint,
        have_syft,
        have_trivy,
    );

    let out_dir = flag(args, "--out").unwrap_or_else(|| DEFAULT_OUT_DIR.to_string());
    std::fs::create_dir_all(&out_dir).with_context(|| format!("creating {out_dir}"))?;
    let json_path = Path::new(&out_dir).join("eval-groundtruth.json");
    std::fs::write(&json_path, ground_truth_json(&rows))
        .with_context(|| format!("writing {}", json_path.display()))?;
    status!("xtask: wrote {}", json_path.display());

    // Fair performance: one invocation per tool over the whole corpus (and,
    // optionally, over a container image), outcome recorded beside cost.
    status!("xtask: measuring whole-corpus performance (one run per tool)");
    let corpus_rows = measure_corpus_perf(
        &targets,
        &cudabom,
        &db,
        &advisories,
        have_blint,
        have_syft,
        have_trivy,
    )?;
    let container = flag(args, "--container-image").and_then(|image| {
        status!("xtask: measuring container performance on {image}");
        measure_container_perf(&image, &cudabom, &db, &advisories, have_syft, have_trivy)
    });
    let fair = FairPerf {
        corpus_n: targets.len(),
        corpus: corpus_rows,
        container,
    };

    print_ground_truth_report(&rows, have_blint, have_syft, have_trivy);
    print_fair_perf(&fair);

    if has_flag(args, "--write-comparison") {
        write_ground_truth_comparison(&rows, &fair, have_blint, have_syft, have_trivy)?;
        status!("xtask: updated {COMPARISON_DOC}");
    }
    Ok(())
}

/// Download + verify each archive (reusing the corpus fetch primitive) and
/// unpack it in place so the real binaries are available for scanning.
fn download_and_unpack(lock: &CorpusLock, corpus_dir: &Path) -> Result<()> {
    use cudabom_fetch::verify_sha256;

    std::fs::create_dir_all(corpus_dir)
        .with_context(|| format!("creating {}", corpus_dir.display()))?;
    let total = lock.entries.len();
    for (i, entry) in lock.entries.iter().enumerate() {
        let file_name = entry.url.rsplit('/').next().unwrap_or("archive");
        let dest = corpus_dir
            .join(&entry.component)
            .join(&entry.version)
            .join(&entry.platform)
            .join(file_name);
        let present = std::fs::read(&dest).is_ok_and(|b| verify_sha256(&b, &entry.sha256).is_ok());
        if !present {
            status!(
                "xtask: [{}/{total}] fetching {} {} ({})",
                i + 1,
                entry.component,
                entry.version,
                entry.platform
            );
        }
        crate::eval_tools::fetch_verified(&entry.url, &entry.sha256, &dest)?;
        unpack_archive(&dest)?;
    }
    status!("xtask: corpus ready under {}", corpus_dir.display());
    Ok(())
}

/// Unpack a `.tar.xz` (via system `tar`) or a zip-family archive, `.zip`/`.whl`/
/// `.jar`/`.egg` (via system `unzip`), into a sibling `<stem>-unpacked`
/// directory. Idempotent.
pub(crate) fn unpack_archive(archive: &Path) -> Result<()> {
    /// Zip-family extensions system `unzip` handles but GNU `tar` does not.
    const ZIP_EXTS: &[&str] = &["zip", "whl", "jar", "egg"];

    let name = archive.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let parent = archive.parent().unwrap_or_else(|| Path::new("."));
    let stem = name
        .trim_end_matches(".tar.xz")
        .trim_end_matches(".zip")
        .trim_end_matches(".whl");
    let dest = parent.join(format!("{stem}-unpacked"));
    if dest.exists() {
        return Ok(());
    }
    std::fs::create_dir_all(&dest).with_context(|| format!("creating {}", dest.display()))?;
    let is_zip = std::path::Path::new(name)
        .extension()
        .is_some_and(|e| ZIP_EXTS.iter().any(|z| e.eq_ignore_ascii_case(z)));
    let ok = if is_zip {
        Command::new("unzip")
            .arg("-oq")
            .arg(archive)
            .arg("-d")
            .arg(&dest)
            .status()
            .is_ok_and(|s| s.success())
    } else {
        Command::new("tar")
            .arg("-xf")
            .arg(archive)
            .arg("-C")
            .arg(&dest)
            .status()
            .is_ok_and(|s| s.success())
    };
    if !ok {
        let _ = std::fs::remove_dir_all(&dest);
        bail!("failed to unpack {}", archive.display());
    }
    Ok(())
}

/// Resolve each lock entry to its real *primary* library file on disk.
fn resolve_targets(lock: &CorpusLock, corpus_dir: &Path) -> Vec<GtTarget> {
    let mut out = Vec::new();
    for entry in &lock.entries {
        let base = corpus_dir
            .join(&entry.component)
            .join(&entry.version)
            .join(&entry.platform);
        for path in walk_files(&base) {
            if std::fs::symlink_metadata(&path).is_ok_and(|m| m.file_type().is_symlink()) {
                continue;
            }
            let fname = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("")
                .to_string();
            if is_primary_library(&fname, &entry.component) {
                out.push(GtTarget {
                    path: path.clone(),
                    name: fname,
                    component: entry.component.clone(),
                    version: entry.version.clone(),
                    platform: entry.platform.clone(),
                });
            }
        }
    }
    out.sort_by(|a, b| {
        (
            a.component.as_str(),
            a.platform.as_str(),
            a.version.as_str(),
        )
            .cmp(&(
                b.component.as_str(),
                b.platform.as_str(),
                b.version.as_str(),
            ))
    });
    out
}

/// Whether `path` is a static `.a` archive that cudabom intentionally does not
/// member-fingerprint because it has more ELF members than the fingerprinter's
/// cap (`MAX_STATIC_MEMBERS` in `xtask::fingerprints`). These are build-artifact
/// aggregates (e.g. `libcutensor_static.a`, `libnccl_static.a`,
/// `libcudss_static.a`, with hundreds-to-thousands of `.o` members) whose member
/// hashes do not survive static linking, so an empty scan result is correct.
///
/// Kept in lock-step with the fingerprinter: both apply the same cap to the same
/// ELF-member count, so the eval never flags a deliberately-skipped archive as a
/// miss and never masks a genuinely-indexable one.
fn is_skipped_static_aggregate(path: &Path) -> bool {
    use object::read::archive::ArchiveFile;

    let is_dot_a = path
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("a"));
    if !is_dot_a {
        return false;
    }
    let Ok(bytes) = std::fs::read(path) else {
        return false;
    };
    let Ok(archive) = ArchiveFile::parse(&*bytes) else {
        return false;
    };
    let elf_members = archive
        .members()
        .flatten()
        .filter_map(|m| m.data(&*bytes).ok())
        .filter(|data| object::read::File::parse(*data).is_ok())
        .count();
    elf_members > crate::fingerprints::MAX_STATIC_MEMBERS
}

/// Is `name` the primary library for `component` (not a stub/symlink/aux)?
fn is_primary_library(name: &str, component: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    let is_dll = std::path::Path::new(name)
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("dll"));
    let versioned_so = |stem: &str| {
        lower.starts_with(stem) && lower.contains(".so.") && lower.matches('.').count() >= 3
    };
    // The self-contained static runtime (e.g. `libcudart_static.a`) is a real
    // deployment artifact: a statically linked app compiles it in. We identify
    // it by member hash, so treat it as a primary target too.
    let static_runtime = lower == format!("lib{component}_static.a");
    match component {
        "cudart" => {
            versioned_so("libcudart.so")
                || static_runtime
                || (lower.starts_with("cudart") && is_dll)
        }
        "cublas" => versioned_so("libcublas.so") || (lower.starts_with("cublas64") && is_dll),
        _ => versioned_so(&format!("lib{component}.so")) || static_runtime,
    }
}

/// Run cudabom on a target and classify against ground truth, with timing.
fn eval_cudabom(bin: &Path, t: &GtTarget, db: &str, advisories: &str) -> CudabomEval {
    let (report, run) = crate::eval_tools::run_cudabom_scan_timed(bin, &t.path, db, advisories);
    let perf = run.as_ref().map(perf_of);
    let Some(json) = report else {
        return (GtStatus::Error, Vec::new(), 0, perf);
    };
    let findings = json
        .get("findings")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let got = crate::eval_tools::parse_findings(&json);

    // A strong-signal match whose build-id/hash is shared across several
    // releases reports the lowest version as the representative and the full set
    // in `component.candidate_versions` (see cudabom-identify). For the exactness
    // check, ground truth counts as matched if it equals the representative OR
    // appears anywhere in that candidate set: the binary genuinely *is* that
    // version, NVIDIA just shipped identical bytes under several labels.
    let got_candidate_sets: Vec<Vec<String>> = findings
        .iter()
        .map(|f| {
            f.pointer("/component/candidate_versions")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(ToString::to_string))
                        .collect()
                })
                .unwrap_or_default()
        })
        .collect();

    let truth_matched = got.iter().any(|(_, v, _)| v == &t.version)
        || got_candidate_sets
            .iter()
            .any(|set| set.iter().any(|v| v == &t.version));
    let status = if got.is_empty() {
        // No finding. This is only a real miss if cudabom was *expected* to
        // index this binary. Large static `.a` aggregates (more ELF members
        // than the fingerprinter's `MAX_STATIC_MEMBERS` cap) are intentionally
        // skipped, member hashes do not survive static linking, so an empty
        // result for one of those is correct behaviour, not a bug.
        if is_skipped_static_aggregate(&t.path) {
            GtStatus::SkippedAggregate
        } else {
            GtStatus::Miss
        }
    } else if truth_matched {
        GtStatus::Exact
    } else {
        GtStatus::VersionMismatch
    };

    // Count the advisories cudabom correlated for this binary (direct +
    // toolkit-wide). This is the apples-to-apples CVE-correlation figure to
    // compare against Trivy, which operates on the same loose binary.
    let cve_count = affected_match_count(&json);

    (status, got, cve_count, perf)
}

/// Count `affected` advisory matches in a cudabom scan JSON document.
fn affected_match_count(json: &serde_json::Value) -> usize {
    json.pointer("/advisories/matches")
        .and_then(|v| v.as_array())
        .map_or(0, |m| {
            m.iter()
                .filter(|x| x.get("verdict").and_then(|v| v.as_str()) == Some("affected"))
                .count()
        })
}

/// Serialize the full ground-truth report as pretty JSON.
fn ground_truth_json(rows: &[GtRow<'_>]) -> String {
    let value = serde_json::json!({
        "targets": rows.iter().map(|r| {
            serde_json::json!({
                "name": r.target.name,
                "platform": r.target.platform,
                "ground_truth": { "component": r.target.component, "version": r.target.version },
                "cudabom": {
                    "status": r.cb_status.label(),
                    "findings": r.cb_got.iter().map(|(n, v, c)| serde_json::json!({
                        "name": n, "version": v, "confidence": c,
                    })).collect::<Vec<_>>(),
                    "cve_matches": r.cb_cves,
                    "wall_ms": r.cb_perf.map(|p| p.wall_ms),
                    "peak_rss_bytes": r.cb_perf.map(|p| p.peak_rss_bytes),
                },
                "syft_named_cuda": r.syft_named,
                "syft_wall_ms": r.syft_perf.map(|p| p.wall_ms),
                "syft_peak_rss_bytes": r.syft_perf.map(|p| p.peak_rss_bytes),
                "trivy_cve": r.trivy_cve,
                "trivy_wall_ms": r.trivy_perf.map(|p| p.wall_ms),
                "trivy_peak_rss_bytes": r.trivy_perf.map(|p| p.peak_rss_bytes),
                "blint_ran": r.blint_ran,
                "blint_named_cuda": r.blint_named,
                "blint_wall_ms": r.blint_perf.map(|p| p.wall_ms),
                "blint_peak_rss_bytes": r.blint_perf.map(|p| p.peak_rss_bytes),
            })
        }).collect::<Vec<_>>(),
    });
    serde_json::to_string_pretty(&value).unwrap_or_else(|_| "{}".to_string())
}

/// Aggregate head-to-head counts over all ground-truth rows. Computed once and
/// shared by the console report and the comparison-doc writer so the two can
/// never disagree.
struct GtSummary {
    total: usize,
    cb_exact: usize,
    cb_named: usize,
    cb_cve_binaries: usize,
    cb_cve_total: usize,
    syft_named: usize,
    trivy_cve: usize,
    blint_named: usize,
}

fn summarize(rows: &[GtRow<'_>]) -> GtSummary {
    GtSummary {
        total: rows.len(),
        cb_exact: rows
            .iter()
            .filter(|r| r.cb_status == GtStatus::Exact)
            .count(),
        cb_named: rows
            .iter()
            .filter(|r| matches!(r.cb_status, GtStatus::Exact | GtStatus::VersionMismatch))
            .count(),
        cb_cve_binaries: rows.iter().filter(|r| r.cb_cves > 0).count(),
        cb_cve_total: rows.iter().map(|r| r.cb_cves).sum(),
        syft_named: rows.iter().filter(|r| r.syft_named == Some(true)).count(),
        trivy_cve: rows.iter().filter(|r| r.trivy_cve == Some(true)).count(),
        blint_named: rows.iter().filter(|r| r.blint_named == Some(true)).count(),
    }
}

/// Print the fair whole-corpus (and container) performance: one invocation per
/// tool over an identical input tree, with outcome shown beside cost.
fn print_fair_perf(fair: &FairPerf) {
    let print_rows = |title: &str, rows: &[FairRow]| {
        println!("\n{title}");
        for r in rows {
            match &r.scan {
                Some(s) => println!(
                    "  {:8} : {:>9}  peak RSS {:>10}  ({})",
                    r.tool,
                    human_ms(s.run.wall_ms),
                    human_bytes(s.run.peak_rss_bytes),
                    outcome_summary(s)
                ),
                None => println!("  {:8} : {}", r.tool, r.absent),
            }
        }
    };
    print_rows(
        &format!(
            "fair performance (one run per tool over the same {} binaries):",
            fair.corpus_n
        ),
        &fair.corpus,
    );
    if let Some(c) = &fair.container {
        print_rows(
            &format!("fair performance (container {} / {}):", c.image, c.scope),
            &c.rows,
        );
    }
}

/// Print a readable ground-truth summary.
fn print_ground_truth_report(
    rows: &[GtRow<'_>],
    have_blint: bool,
    have_syft: bool,
    have_trivy: bool,
) {
    println!(
        "\n=== cudabom vs ground truth ({} real binaries) ===\n",
        rows.len()
    );

    let mut by_plat: BTreeMap<&str, (usize, usize)> = BTreeMap::new();
    for r in rows {
        let e = by_plat.entry(r.target.platform.as_str()).or_default();
        e.1 += 1;
        if r.cb_status == GtStatus::Exact {
            e.0 += 1;
        }
    }
    println!("cudabom exact-identification by platform:");
    for (plat, (ok, tot)) in &by_plat {
        println!("  {plat:16} {ok}/{tot} exact");
    }

    let s = summarize(rows);
    println!("\nhead-to-head over {} binaries:", s.total);
    println!("  cudabom names a CUDA component : {}", s.cb_named);
    println!(
        "  cudabom correlates a CVE       : {} binaries ({} advisory match(es) total)",
        s.cb_cve_binaries, s.cb_cve_total
    );
    if have_syft {
        println!("  Syft names a CUDA component    : {}", s.syft_named);
    }
    if have_blint {
        // blint names the library (SONAME/symbols) but pins no version and
        // correlates no CVE for a bare native binary.
        println!(
            "  blint names a CUDA component   : {} (no version, no CVE)",
            s.blint_named
        );
    }
    if have_trivy {
        println!("  Trivy correlates a CVE         : {}", s.trivy_cve);
    }

    println!("\nper-binary:");
    for r in rows {
        let got = if r.cb_got.is_empty() {
            "-".to_string()
        } else {
            r.cb_got
                .iter()
                .map(|(n, v, c)| format!("{n} {v} ({c})"))
                .collect::<Vec<_>>()
                .join(", ")
        };
        let flag = if r.cb_status == GtStatus::Exact {
            String::new()
        } else {
            format!("   <<< {}", r.cb_status.label())
        };
        println!(
            "  [{:16}] {:14} {:26} gt={} {:10} -> {}{}",
            r.cb_status.label(),
            r.target.platform,
            r.target.name,
            r.target.component,
            r.target.version,
            got,
            flag,
        );
    }

    let misses: Vec<&GtRow<'_>> = rows
        .iter()
        .filter(|r| matches!(r.cb_status, GtStatus::Miss | GtStatus::Error))
        .collect();
    if misses.is_empty() {
        println!("\nNo misses or crashes: cudabom identified every known binary.");
    } else {
        println!("\n{} miss(es)/bug(s) to investigate:", misses.len());
        for r in misses {
            println!(
                "  [{}] {} ({} {} on {})",
                r.cb_status.label(),
                r.target.name,
                r.target.component,
                r.target.version,
                r.target.platform
            );
        }
    }
}

/// The legacy, target-list evaluation: run every tool over a set of files and
/// emit the aggregated capability table. Retained for ad-hoc runs over an
/// arbitrary directory of artifacts.
fn run_targets(args: &[String]) -> Result<()> {
    let cudabom = locate_cudabom()?;
    let db =
        flag(args, "--db").unwrap_or_else(|| cudabom_core::paths::FINGERPRINTS_DIR.to_string());
    let advisories = flag(args, "--advisories")
        .unwrap_or_else(|| cudabom_core::paths::ADVISORY_INDEX.to_string());

    let targets = collect_targets(args);
    if targets.is_empty() {
        bail!("eval: no targets found (pass --target <file> or --targets <dir>)");
    }

    // Probe each competitor once; a missing tool is recorded, never fatal.
    let (have_blint, have_syft, have_trivy) = crate::eval_tools::probe_competitors();
    status!(
        "xtask: eval tools present: cudabom: yes, blint: {}, syft: {}, trivy: {}",
        yesno(have_blint),
        yesno(have_syft),
        yesno(have_trivy)
    );

    let mut reports = Vec::with_capacity(targets.len());
    for target in &targets {
        detail!("xtask: eval target {}", target.display());
        let mut results: BTreeMap<&'static str, ToolResult> = BTreeMap::new();

        results.insert(
            Tool::Cudabom.label(),
            run_cudabom(&cudabom, target, &db, &advisories)?,
        );
        results.insert(
            Tool::Blint.label(),
            if have_blint {
                run_blint(target)
            } else {
                ToolResult::default()
            },
        );
        results.insert(
            Tool::Syft.label(),
            if have_syft {
                run_syft(target)
            } else {
                ToolResult::default()
            },
        );
        results.insert(
            Tool::Trivy.label(),
            if have_trivy {
                run_trivy(target)
            } else {
                ToolResult::default()
            },
        );

        reports.push(TargetReport {
            target: target.display().to_string(),
            results,
        });
    }

    let out_dir = flag(args, "--out").unwrap_or_else(|| DEFAULT_OUT_DIR.to_string());
    std::fs::create_dir_all(&out_dir).with_context(|| format!("creating {out_dir}"))?;
    let json_path = Path::new(&out_dir).join("eval.json");
    std::fs::write(&json_path, eval_json(&reports))
        .with_context(|| format!("writing {}", json_path.display()))?;
    status!("xtask: wrote {}", json_path.display());

    let table = capability_table(&reports);
    println!("{table}");

    if has_flag(args, "--write-comparison") {
        write_comparison(&table, &reports)?;
        status!("xtask: updated {COMPARISON_DOC}");
    }
    Ok(())
}

/// Resolve the cudabom binary: prefer an explicit `CUDABOM_BIN`, then the
/// release build, then debug. Built via `cargo build --release` in CI.
pub(crate) fn locate_cudabom() -> Result<PathBuf> {
    if let Ok(explicit) = std::env::var("CUDABOM_BIN") {
        let p = PathBuf::from(explicit);
        if p.exists() {
            return Ok(p);
        }
    }
    for candidate in ["target/release/cudabom", "target/debug/cudabom"] {
        let p = PathBuf::from(candidate);
        if p.exists() {
            return Ok(p);
        }
    }
    bail!("eval: cudabom binary not found; run `cargo build --release` first (or set CUDABOM_BIN)")
}

/// Build the target list from flags, or fall back to the committed smoke set.
fn collect_targets(args: &[String]) -> Vec<PathBuf> {
    let mut targets = Vec::new();
    for (i, a) in args.iter().enumerate() {
        if a == "--target" {
            if let Some(v) = args.get(i + 1) {
                targets.push(PathBuf::from(v));
            }
        }
    }
    if let Some(dir) = flag(args, "--targets") {
        for entry in walk_files(Path::new(&dir)) {
            targets.push(entry);
        }
    }
    if targets.is_empty() {
        for t in SMOKE_TARGETS {
            let p = PathBuf::from(t);
            if p.exists() {
                targets.push(p);
            }
        }
        if !targets.is_empty() {
            status!(
                "xtask: eval running on committed smoke targets; pass --targets <unpacked corpus> \
                 for the authoritative numbers"
            );
        }
    }
    targets
}

/// Every regular file under `dir`, sorted for deterministic output.
pub(crate) fn walk_files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&d) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.is_file() {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}

/// Run cudabom through its JSON output and reduce to the three identity steps.
fn run_cudabom(bin: &Path, target: &Path, db: &str, advisories: &str) -> Result<ToolResult> {
    let output = Command::new(bin)
        .arg("scan")
        .arg(target)
        .args(["--db", db, "--advisories", advisories, "--format", "json"])
        .output()
        .with_context(|| format!("running cudabom on {}", target.display()))?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap_or(serde_json::Value::Null);

    let findings = json.get("findings").and_then(|v| v.as_array());
    let named_cuda = findings.is_some_and(|f| !f.is_empty());
    let pinned_version = findings.is_some_and(|f| {
        f.iter().any(|x| {
            x.pointer("/component/version")
                .and_then(|v| v.as_str())
                .is_some_and(|s| !s.is_empty())
        })
    });
    let correlated_cve = json
        .pointer("/advisories/matches")
        .and_then(|v| v.as_array())
        .is_some_and(|m| !m.is_empty());
    let item_count = findings.map_or(0, Vec::len);
    Ok(ToolResult {
        ran: true,
        named_cuda,
        pinned_version,
        correlated_cve,
        item_count,
    })
}

/// Run blint (preferring a `blint` on PATH, else a known venv) and reduce.
fn run_blint(target: &Path) -> ToolResult {
    let out_dir = std::env::temp_dir().join("cudabom-eval-blint");
    let _ = std::fs::remove_dir_all(&out_dir);
    let bin = if probe(&["blint", "--help"]) {
        "blint".to_string()
    } else {
        match blint_in_venv() {
            Some(p) => p,
            None => return ToolResult::default(),
        }
    };
    let status = Command::new(&bin)
        .args(["-i"])
        .arg(target)
        .arg("-o")
        .arg(&out_dir)
        .args(["--no-banner", "--no-reviews"])
        .output();
    if status.is_err() {
        return ToolResult::default();
    }
    // blint writes <name>-metadata.json; it records soname/symbol strings and
    // security findings, but no CUDA version pin and no CVE correlation.
    let mut named_cuda = false;
    let mut item_count = 0usize;
    if let Ok(entries) = std::fs::read_dir(&out_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name.ends_with("-metadata.json") {
                if let Ok(text) = std::fs::read_to_string(&path) {
                    let lower = text.to_ascii_lowercase();
                    named_cuda |= crate::eval_tools::names_cuda_token(&lower);
                    item_count += 1;
                }
            }
        }
    }
    ToolResult {
        ran: true,
        named_cuda,
        // blint does not pin CUDA release versions or correlate CVEs for a
        // bare native library; both remain false unless its output shows them.
        pinned_version: false,
        correlated_cve: false,
        item_count,
    }
}

/// Run Syft (CycloneDX JSON) and reduce to whether it named a CUDA component.
fn run_syft(target: &Path) -> ToolResult {
    let output = Command::new("syft")
        .arg(format!("file:{}", target.display()))
        .args(["-o", "cyclonedx-json", "-q"])
        .output();
    let Ok(output) = output else {
        return ToolResult::default();
    };
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).unwrap_or(serde_json::Value::Null);
    let comps = json.get("components").and_then(|v| v.as_array());
    let named_cuda = comps.is_some_and(|c| {
        c.iter().any(|x| {
            x.get("name")
                .and_then(|n| n.as_str())
                .is_some_and(|s| crate::eval_tools::names_cuda_token(&s.to_ascii_lowercase()))
        })
    });
    ToolResult {
        ran: true,
        named_cuda,
        pinned_version: named_cuda,
        correlated_cve: false,
        item_count: comps.map_or(0, Vec::len),
    }
}

/// Run Trivy (rootfs, JSON) and reduce to whether it reported any CVE.
fn run_trivy(target: &Path) -> ToolResult {
    let output = Command::new("trivy")
        .arg("rootfs")
        .arg(target)
        .args(["--quiet", "--format", "json"])
        .output();
    let Ok(output) = output else {
        return ToolResult::default();
    };
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).unwrap_or(serde_json::Value::Null);
    let results = json.get("Results").and_then(|v| v.as_array());
    let mut vulns = 0usize;
    if let Some(results) = results {
        for r in results {
            vulns += r
                .get("Vulnerabilities")
                .and_then(|v| v.as_array())
                .map_or(0, Vec::len);
        }
    }
    ToolResult {
        ran: true,
        named_cuda: false,
        pinned_version: false,
        correlated_cve: vulns > 0,
        item_count: vulns,
    }
}

/// A predicate that extracts one capability bit from a tool's result.
type Capability = fn(&ToolResult) -> bool;

/// Aggregate a per-capability support cell across all targets for a tool.
///
/// A tool "supports" a capability if it demonstrated it on *any* target where
/// the capability is applicable. Cells are `yes` / `no` / `n/a` (not
/// installed), so the table never overstates.
fn cell(reports: &[TargetReport], tool: Tool, pick: Capability) -> &'static str {
    let label = tool.label();
    let any_ran = reports
        .iter()
        .any(|r| r.results.get(label).is_some_and(|t| t.ran));
    if !any_ran {
        return "n/a";
    }
    let any = reports
        .iter()
        .filter_map(|r| r.results.get(label))
        .any(pick);
    if any {
        "yes"
    } else {
        "no"
    }
}

/// Render the capability comparison as a Markdown table.
fn capability_table(reports: &[TargetReport]) -> String {
    use std::fmt::Write as _;
    let rows: &[(&str, Capability)] = &[
        ("Names a CUDA component", |t| t.named_cuda),
        ("Pins the exact CUDA version", |t| t.pinned_version),
        ("Correlates to a CVE", |t| t.correlated_cve),
    ];
    let mut out = String::new();
    out.push_str("| Capability | cudabom | blint | Syft | Trivy |\n");
    out.push_str("|---|---|---|---|---|\n");
    for (name, pick) in rows {
        let _ = writeln!(
            out,
            "| {} | {} | {} | {} | {} |",
            name,
            cell(reports, Tool::Cudabom, *pick),
            cell(reports, Tool::Blint, *pick),
            cell(reports, Tool::Syft, *pick),
            cell(reports, Tool::Trivy, *pick),
        );
    }
    out
}

/// Serialize the full per-target record as pretty JSON.
fn eval_json(reports: &[TargetReport]) -> String {
    let value = serde_json::json!({
        "targets": reports.iter().map(|r| {
            serde_json::json!({
                "target": r.target,
                "tools": Tool::ALL.iter().map(|tool| {
                    let d = ToolResult::default();
                    let t = r.results.get(tool.label()).unwrap_or(&d);
                    serde_json::json!({
                        "tool": tool.label(),
                        "ran": t.ran,
                        "named_cuda": t.named_cuda,
                        "pinned_version": t.pinned_version,
                        "correlated_cve": t.correlated_cve,
                        "item_count": t.item_count,
                    })
                }).collect::<Vec<_>>(),
            })
        }).collect::<Vec<_>>(),
    });
    serde_json::to_string_pretty(&value).unwrap_or_else(|_| "{}".to_string())
}

/// Splice a freshly-rendered block between the result markers in the comparison
/// doc, preserving everything outside them. Shared by the legacy target-list
/// writer and the ground-truth writer.
fn splice_comparison_block(block_body: &str) -> Result<()> {
    let doc = std::fs::read_to_string(COMPARISON_DOC)
        .with_context(|| format!("reading {COMPARISON_DOC}"))?;
    let (Some(begin), Some(end)) = (doc.find(RESULT_BEGIN), doc.find(RESULT_END)) else {
        bail!("{COMPARISON_DOC} is missing the {RESULT_BEGIN}/{RESULT_END} markers");
    };
    let block = format!("{RESULT_BEGIN}\n\n{block_body}\n\n{RESULT_END}");
    let mut rebuilt = String::with_capacity(doc.len());
    rebuilt.push_str(&doc[..begin]);
    rebuilt.push_str(&block);
    rebuilt.push_str(&doc[end + RESULT_END.len()..]);
    std::fs::write(COMPARISON_DOC, rebuilt).with_context(|| format!("writing {COMPARISON_DOC}"))?;
    Ok(())
}

/// Rewrite the comparison doc's result section from a ground-truth run: a
/// count-based capability table over all `rows` real binaries, which is more
/// honest than a yes/no cell when the corpus has dozens of binaries. A tool
/// that was not installed is rendered `n/a`, never a loss.
fn write_ground_truth_comparison(
    rows: &[GtRow<'_>],
    fair: &FairPerf,
    have_blint: bool,
    have_syft: bool,
    have_trivy: bool,
) -> Result<()> {
    let s = summarize(rows);
    let n = s.total;

    // Competitors we did not run are reported as n/a, not zero.
    let syft_cell = if have_syft {
        format!("{} / {n}", s.syft_named)
    } else {
        "n/a".to_string()
    };
    let trivy_name_cell = if have_trivy { "-" } else { "n/a" };
    let trivy_cve_cell = if have_trivy {
        format!("{} / {n}", s.trivy_cve)
    } else {
        "n/a".to_string()
    };
    // blint names a soname (measured) but neither pins the CUDA release version
    // nor correlates a CVE: it has no such output for a bare native library.
    let (blint_name_cell, blint_version_cell, blint_cve_cell) = if have_blint {
        (
            format!("{} / {n}", s.blint_named),
            "no".to_string(),
            "no".to_string(),
        )
    } else {
        ("n/a".to_string(), "n/a".to_string(), "n/a".to_string())
    };

    let table = format!(
        "| Capability | cudabom | blint | Syft | Trivy |\n\
         |---|---|---|---|---|\n\
         | Names a CUDA component | {cb_named} / {n} | {blint_name_cell} | {syft_cell} | {trivy_name_cell} |\n\
         | Pins the exact CUDA version | {cb_exact} / {n} | {blint_version_cell} | no | no |\n\
         | Correlates to a CVE | {cb_cve_binaries} / {n} | {blint_cve_cell} | no | {trivy_cve_cell} |\n",
        cb_named = s.cb_named,
        cb_exact = s.cb_exact,
        cb_cve_binaries = s.cb_cve_binaries,
    );

    let blint_note = if have_blint {
        "\n\nblint names the library (SONAME/symbols) but does not pin the \
         CUDA release version or correlate CVEs for a bare native binary, so its \
         version and CVE cells are `no`."
    } else {
        ""
    };

    // Performance: the fair, whole-corpus measurement (one invocation per tool
    // over an identical input tree), with each tool's outcome shown beside its
    // cost so a cheap empty scan cannot look like a win.
    let perf_table = fair_perf_table(
        "Performance: same corpus, one run per tool",
        &fair.corpus,
        Some(fair.corpus_n),
    );
    let container_section = fair.container.as_ref().map_or_else(
        || {
            "\n\n_Container row pending: run `cargo xtask eval --container-image \
             <ref> --write-comparison` on a host with Docker (CI provides the \
             PyTorch/amd64 figure)._"
                .to_string()
        },
        |c| {
            let t = fair_perf_table(
                "Performance: same container, one run per tool",
                &c.rows,
                None,
            );
            format!(
                "\n\n{t}\n_Container row: `{image}` (`{digest}`), all tools scanning the \
                 identical {scope}. blint is per-binary forensics, not a tree cataloguer, so \
                 it is `n/a` here._",
                image = c.image,
                digest = c.digest,
                scope = c.scope,
            )
        },
    );

    let body = format!(
        "{table}\n_Measured by `cargo xtask eval` across {n} real labeled binaries \
         (counts are binaries matched / total). Correlation totals: cudabom correlated \
         {cb_cve_total} advisory match(es) across {cb_cve_binaries} binaries._{blint_note}\n\n\
         {perf_table}\n_Each tool is run once over the whole corpus (identical input, \
         process startup amortized once) and timed under the system `time` utility (wall \
         clock, kernel peak RSS). The outcome in each cell is what that run actually \
         produced, so a fast or low-memory run that found nothing is visible as such rather \
         than counted as a win. Lower cost is better only when the outcome is equal. \
         The raw \"named\" figures are not like-for-like units (cudabom counts component \
         identities; blint counts individual objects and explodes each static `.a` into its \
         hundreds of members; Syft counts packages), so the \"Input files identified\" row \
         normalizes each to the comparable unit: distinct top-level input files out of the \
         corpus total. cudabom's \"advisory \
         match(es)\" counts every affected-advisory hit over the whole-corpus run and is a \
         superset of the per-binary CVE count in the accuracy table above. A tool shown as \
         `n/a` was not installed on the host that generated this table.\
         _{container_section}",
        cb_cve_total = s.cb_cve_total,
        cb_cve_binaries = s.cb_cve_binaries,
    );
    splice_comparison_block(&body)
}

/// Render a fair-performance markdown table: one column per tool, with each
/// capability on its own labeled row (input files identified, exact version
/// pinned, CVE / advisory matches, raw items named) followed by wall time and
/// peak RSS, so cost is always read beside what the run produced and a gap like
/// "no CVE" lines up visibly across tools. `denom`, when set, is the shared
/// input-file total used as the `identified / total` denominator. A tool that
/// did not run shows its `absent` reason.
fn fair_perf_table(title: &str, rows: &[FairRow], denom: Option<usize>) -> String {
    let header: Vec<&str> = rows.iter().map(|r| r.tool).collect();
    let sep = vec!["---"; rows.len() + 1].join(" | ");
    let cell = |f: &dyn Fn(&crate::eval_tools::DirScan) -> String| -> Vec<String> {
        rows.iter()
            .map(|r| match &r.scan {
                Some(s) => f(s),
                None => r.absent.to_string(),
            })
            .collect::<Vec<_>>()
    };
    let wall = cell(&|s| human_ms(s.run.wall_ms));
    let rss = cell(&|s| human_bytes(s.run.peak_rss_bytes));
    let pinned = cell(&|s| match s.pins_version {
        Some(true) => "yes".to_string(),
        Some(false) => "no".to_string(),
        None => "n/a".to_string(),
    });
    let cves = cell(&|s| match s.cve_matches {
        Some(c) => c.to_string(),
        None => "n/a".to_string(),
    });
    let named = cell(&|s| {
        if s.named_label.is_empty() {
            "-".to_string()
        } else {
            s.named_label.clone()
        }
    });
    // The "distinct input files" normalization only has meaning when inputs were
    // staged as discrete files with a shared total (the loose-binary corpus).
    // The container scope scans a real subtree with no such denominator, so the
    // row is omitted there and "Items named (raw)" carries the finding count.
    let files_row = denom.map_or(String::new(), |n| {
        let files = cell(&|s| match s.named_files {
            Some(f) => format!("{f} / {n}"),
            None => "-".to_string(),
        });
        format!("| Input files identified | {} |\n", files.join(" | "))
    });
    format!(
        "| {title} | {} |\n| {sep} |\n\
         {files_row}\
         | Exact version pinned | {} |\n\
         | CVE / advisory matches | {} |\n\
         | Items named (raw) | {} |\n\
         | Wall time | {} |\n\
         | Peak RSS | {} |\n",
        header.join(" | "),
        pinned.join(" | "),
        cves.join(" | "),
        named.join(" | "),
        wall.join(" | "),
        rss.join(" | "),
    )
}

/// One-line outcome summary for console output, built from a scan's structured
/// capability fields.
fn outcome_summary(s: &crate::eval_tools::DirScan) -> String {
    let mut parts = Vec::new();
    if let Some(f) = s.named_files {
        parts.push(format!("{f} files"));
    }
    if !s.named_label.is_empty() {
        parts.push(format!("named {}", s.named_label));
    }
    match s.pins_version {
        Some(true) => parts.push("pins version".to_string()),
        Some(false) => parts.push("no version".to_string()),
        None => {}
    }
    if let Some(c) = s.cve_matches {
        parts.push(format!("{c} CVE match(es)"));
    }
    parts.join(", ")
}

fn write_comparison(table: &str, reports: &[TargetReport]) -> Result<()> {
    let target_list = reports
        .iter()
        .map(|r| format!("- `{}`", r.target))
        .collect::<Vec<_>>()
        .join("\n");
    let body = format!(
        "{table}\n_Measured by `cargo xtask eval` across {n} target(s):_\n\n{target_list}",
        n = reports.len(),
    );
    splice_comparison_block(&body)
}
