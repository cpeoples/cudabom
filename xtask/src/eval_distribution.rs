//! `cargo xtask eval --distribution`: comparison against in-the-wild CUDA artifacts.
//!
//! The pristine redist corpus (`eval/corpus.manifest.json`) measures cudabom on
//! NVIDIA's own tarballs: its home turf. This harness casts a wider net over
//! the forms CUDA actually ships to users:
//!
//! - **PyPI wheels** (`nvidia-*-cu12`, and third-party wheels like `cupy` that
//!   *vendor and rename* CUDA libraries with no package metadata of their own),
//! - **conda packages** (`.conda` = zip of zstd tarballs),
//! - **container images** (pinned by digest; exported and scanned),
//! - **synthetic adversarial copies** (a real library, stripped and renamed to
//!   defeat name/soname heuristics: only a content hash or build-id survives).
//!
//! Every artifact is content-pinned (sha256 for downloads, image digest for
//! containers) so the run is reproducible. For a fair comparison, Syft and
//! Trivy are run on the *native* artifact (the wheel/image, where their package
//! metadata lives), while cudabom and blint are run on the CUDA libraries found
//! inside. Scoring is detect-plus-known: where the package declares a version
//! we grade exact/mismatch; otherwise we record detection only.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};

use crate::eval_groundtruth::{locate_cudabom, walk_files};
use crate::eval_tools::{blint_probe, syft_names_cuda, trivy_has_cve, yesno};
use crate::verbosity::{detail, status};
use crate::{flag, has_flag};

/// Default distribution manifest.
const DEFAULT_MANIFEST: &str = "eval/distribution.manifest.json";
/// Gitignored directory distribution artifacts are downloaded + unpacked into.
const DEFAULT_CORPUS_DIR: &str = "corpus/distribution";
/// The redist corpus a `synthetic` entry sources its real library from.
const REDIST_CORPUS_DIR: &str = "corpus/eval";

/// `cargo xtask eval --distribution [--manifest <f>] [--corpus <dir>] [--download]
/// [--db <dir>] [--advisories <f>] [--out <dir>] [--stream] [--tier a|b]
/// [--kind wheel,conda,...]`
pub(crate) fn run(args: &[String]) -> Result<()> {
    let cudabom = locate_cudabom()?;
    let db =
        flag(args, "--db").unwrap_or_else(|| cudabom_core::paths::FINGERPRINTS_DIR.to_string());
    let advisories = flag(args, "--advisories")
        .unwrap_or_else(|| cudabom_core::paths::ADVISORY_INDEX.to_string());
    let manifest_path = flag(args, "--manifest").unwrap_or_else(|| DEFAULT_MANIFEST.to_string());
    let corpus_dir =
        PathBuf::from(flag(args, "--corpus").unwrap_or_else(|| DEFAULT_CORPUS_DIR.to_string()));
    let download = has_flag(args, "--download");
    // Streaming mode: reclaim each artifact's download/rootfs (and `docker rmi`
    // its image) as soon as it is scored, so peak disk is one artifact rather
    // than the whole set. This is what lets the fat-container tier fit a
    // disk-constrained CI runner (GitHub's guaranteed free space is 14 GB).
    let stream = has_flag(args, "--stream");

    let bytes = std::fs::read(&manifest_path)
        .with_context(|| format!("reading distribution manifest {manifest_path}"))?;
    let mut artifacts =
        parse_manifest(&bytes).with_context(|| format!("parsing {manifest_path}"))?;
    if artifacts.is_empty() {
        bail!("distribution manifest {manifest_path} has no artifacts");
    }

    // Optional scope filtering. `--tier a` is the light, always-CI-safe subset
    // (wheels/conda/synthetic: a few GB peak); `--tier b` is everything
    // including fat container images. `--kind` is an explicit comma-separated
    // override (e.g. `--kind wheel,conda`). The two compose: tier narrows the
    // default kind set, `--kind` replaces it.
    let allowed = resolve_kind_filter(args)?;
    if let Some(allowed) = &allowed {
        let before = artifacts.len();
        artifacts.retain(|a| allowed.contains(&a.kind));
        if artifacts.is_empty() {
            bail!("no artifacts match the requested scope ({before} in manifest, 0 after filter)");
        }
    }

    status!(
        "xtask: eval --distribution from {manifest_path} ({} artifact(s){})",
        artifacts.len(),
        if stream { ", streaming" } else { "" }
    );

    let (have_blint, have_syft, have_trivy) = crate::eval_tools::probe_competitors();
    let have_docker = crate::eval_tools::probe_docker();
    status!(
        "xtask: competitors: blint: {}, syft: {}, trivy: {}; docker: {}",
        yesno(have_blint),
        yesno(have_syft),
        yesno(have_trivy),
        yesno(have_docker),
    );

    std::fs::create_dir_all(&corpus_dir)
        .with_context(|| format!("creating {}", corpus_dir.display()))?;

    let tools = Tools {
        have_blint,
        have_syft,
        have_trivy,
        have_docker,
    };
    let ctx = EvalCtx {
        cudabom: &cudabom,
        db: &db,
        advisories: &advisories,
        corpus_dir: &corpus_dir,
        download,
        stream,
        tools,
    };

    let mut rows: Vec<DistRow> = Vec::new();
    for artifact in &artifacts {
        match evaluate_artifact(&ctx, artifact) {
            Ok(row) => rows.push(row),
            Err(e) => {
                status!("xtask: [skip] {}: {e:#}", artifact.id);
                rows.push(DistRow::skipped(artifact, format!("{e:#}")));
                // Streaming invariant: reclaim the artifact's working tree even
                // on the error/skip path (e.g. "no CUDA libraries found"), which
                // bails before the success-path reclaim. Downloaded wheels/conda
                // and synthetic transforms unpack under corpus_dir/<id>; dropping
                // it keeps peak disk at one artifact rather than leaking skips.
                if stream {
                    let dir = corpus_dir.join(&artifact.id);
                    if dir.exists() {
                        remove_working_dir(&dir);
                    }
                }
            }
        }
    }

    let out_dir = flag(args, "--out").unwrap_or_else(|| "target".to_string());
    std::fs::create_dir_all(&out_dir).with_context(|| format!("creating {out_dir}"))?;
    let json_path = Path::new(&out_dir).join("eval-distribution.json");
    std::fs::write(&json_path, distribution_json(&rows))
        .with_context(|| format!("writing {}", json_path.display()))?;
    status!("xtask: wrote {}", json_path.display());

    print_report(&rows, ctx.tools);
    Ok(())
}

/// Resolve the artifact-kind scope filter from `--tier` and/or `--kind`.
///
/// Returns `None` when no filter is requested (evaluate everything). `--kind`
/// is an explicit comma-separated set and takes precedence over `--tier`.
/// `--tier a` is the light, always-CI-safe subset (wheels, conda, and local
/// synthetic transforms: a few GB peak, no fat container images); `--tier b`
/// is the full set (everything, including containers), expressed as `None` so
/// nothing is filtered out.
fn resolve_kind_filter(args: &[String]) -> Result<Option<Vec<Kind>>> {
    if let Some(kinds) = flag(args, "--kind") {
        let mut set = Vec::new();
        for token in kinds.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            set.push(Kind::parse(token)?);
        }
        if set.is_empty() {
            bail!("--kind was given but listed no kinds");
        }
        return Ok(Some(set));
    }
    match flag(args, "--tier")
        .as_deref()
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        // No tier, or tier b: evaluate the full set (no kind filter).
        None | Some("b") => Ok(None),
        Some("a") => Ok(Some(vec![Kind::Wheel, Kind::Conda, Kind::Synthetic])),
        Some(other) => bail!("unknown --tier {other:?} (expected 'a' or 'b')"),
    }
}

// ---------------------------------------------------------------------------
// Manifest schema (parsed from serde_json::Value; xtask has no serde-derive)
// ---------------------------------------------------------------------------

/// One in-the-wild artifact. Fields are a superset across kinds; only those
/// relevant to a kind are populated.
#[derive(Debug)]
struct Artifact {
    id: String,
    kind: Kind,
    note: String,
    url: Option<String>,
    sha256: Option<String>,
    image: Option<String>,
    digest: Option<String>,
    from_corpus: Option<FromCorpus>,
    rename_to: Option<String>,
    strip: bool,
    /// Synthetic transform: how the sourced library is mutated before scanning.
    transform: Transform,
    /// Known ground truth. Empty => detection-only scoring.
    expect: Vec<Expect>,
}

/// How a `synthetic` artifact mutates its sourced corpus library.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Transform {
    /// Copy (+ optional strip) + rename to an innocuous name. Content hash and
    /// build-id survive, so cudabom still identifies it exactly.
    Rename,
    /// Statically link the component's `.a` into an executable (no `.so`); if a
    /// matching toolchain is unavailable, fall back to scanning the `.a` so the
    /// static-member fingerprint path is still exercised.
    StaticExe,
    /// UPX-compress the copied library. The on-disk bytes change, so a file-hash
    /// match is defeated; whether any signal survives is the finding.
    Upx,
    /// Embed the library inside a larger blob (prepend padding), as a vendored
    /// payload would appear concatenated into another file.
    Embed,
}

impl Transform {
    fn parse(s: &str) -> Result<Self> {
        Ok(match s {
            "rename" => Transform::Rename,
            "static-exe" => Transform::StaticExe,
            "upx" => Transform::Upx,
            "embed" => Transform::Embed,
            other => bail!("unknown synthetic transform {other:?}"),
        })
    }

    fn label(self) -> &'static str {
        match self {
            Transform::Rename => "rename",
            Transform::StaticExe => "static-exe",
            Transform::Upx => "upx",
            Transform::Embed => "embed",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Wheel,
    Conda,
    Archive,
    Container,
    Synthetic,
}

impl Kind {
    fn label(self) -> &'static str {
        match self {
            Kind::Wheel => "wheel",
            Kind::Conda => "conda",
            Kind::Archive => "archive",
            Kind::Container => "container",
            Kind::Synthetic => "synthetic",
        }
    }

    fn parse(s: &str) -> Result<Self> {
        Ok(match s {
            "wheel" => Kind::Wheel,
            "conda" => Kind::Conda,
            "archive" => Kind::Archive,
            "container" => Kind::Container,
            "synthetic" => Kind::Synthetic,
            other => bail!("unknown artifact kind {other:?}"),
        })
    }
}

#[derive(Debug)]
struct FromCorpus {
    component: String,
    version: String,
    platform: String,
    /// Substring the source library file name must contain (e.g. `libcudart.so`).
    match_substr: String,
}

#[derive(Debug, Clone)]
struct Expect {
    component: String,
    version: Option<String>,
}

/// Parse the distribution manifest from JSON.
fn parse_manifest(bytes: &[u8]) -> Result<Vec<Artifact>> {
    let v: serde_json::Value = serde_json::from_slice(bytes).context("manifest is not JSON")?;
    let arr = v
        .get("artifacts")
        .and_then(|a| a.as_array())
        .context("manifest has no `artifacts` array")?;
    arr.iter().map(parse_artifact).collect()
}

fn parse_artifact(v: &serde_json::Value) -> Result<Artifact> {
    let s = |k: &str| v.get(k).and_then(|x| x.as_str()).map(str::to_string);
    let id = s("id").context("artifact missing id")?;
    let kind = Kind::parse(v.get("kind").and_then(|x| x.as_str()).unwrap_or_default())
        .with_context(|| format!("artifact {id}"))?;
    let from_corpus = v.get("from_corpus").and_then(|fc| {
        Some(FromCorpus {
            component: fc.get("component")?.as_str()?.to_string(),
            version: fc.get("version")?.as_str()?.to_string(),
            platform: fc.get("platform")?.as_str()?.to_string(),
            match_substr: fc.get("match")?.as_str()?.to_string(),
        })
    });
    let expect = v
        .get("expect")
        .and_then(|e| e.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|e| {
                    Some(Expect {
                        component: e.get("component")?.as_str()?.to_string(),
                        version: e
                            .get("version")
                            .and_then(|x| x.as_str())
                            .map(str::to_string),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    Ok(Artifact {
        id,
        kind,
        note: s("note").unwrap_or_default(),
        url: s("url"),
        sha256: s("sha256"),
        image: s("image"),
        digest: s("digest"),
        from_corpus,
        rename_to: s("rename_to"),
        strip: v
            .get("strip")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false),
        transform: Transform::parse(
            v.get("transform")
                .and_then(|x| x.as_str())
                .unwrap_or("rename"),
        )
        .with_context(|| {
            format!(
                "artifact {}",
                v.get("id").and_then(|x| x.as_str()).unwrap_or("?")
            )
        })?,
        expect,
    })
}

// ---------------------------------------------------------------------------
// Evaluation context + results
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
#[allow(clippy::struct_excessive_bools)]
struct Tools {
    have_blint: bool,
    have_syft: bool,
    have_trivy: bool,
    have_docker: bool,
}

struct EvalCtx<'a> {
    cudabom: &'a Path,
    db: &'a str,
    advisories: &'a str,
    corpus_dir: &'a Path,
    download: bool,
    /// Reclaim each artifact's working set as soon as it is scored (see
    /// `--stream`). Keeps peak disk to a single artifact.
    stream: bool,
    tools: Tools,
}

/// What cudabom reported for one inner library.
#[derive(Debug, Clone)]
struct CbFinding {
    lib: String,
    name: String,
    version: String,
    confidence: String,
}

/// How cudabom's findings scored against an artifact's expectations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Grade {
    /// Named the expected component(s) and pinned the exact expected version(s).
    Exact,
    /// Named the component and a version *consistent* with ground truth (a
    /// family/major prefix like `12.x` for `12.4.127`) but not pinned exactly.
    /// This is the expected outcome when a wheel ships only the SONAME-major
    /// library (`libcudart.so.12`) whose exact bytes are not yet fingerprinted.
    FamilyMatch,
    /// Named the component but with a version that contradicts ground truth.
    VersionMismatch,
    /// Detection-only entry (no version ground truth); cudabom named CUDA.
    DetectedKnownNoVersion,
    /// cudabom found nothing for an artifact that contains CUDA.
    Miss,
    /// The artifact could not be acquired/unpacked (not scored against cudabom).
    Skipped,
}

impl Grade {
    fn label(self) -> &'static str {
        match self {
            Grade::Exact => "exact",
            Grade::FamilyMatch => "family-match",
            Grade::VersionMismatch => "version-mismatch",
            Grade::DetectedKnownNoVersion => "detected",
            Grade::Miss => "MISS",
            Grade::Skipped => "skipped",
        }
    }
}

/// One artifact's full cross-tool result.
struct DistRow {
    id: String,
    kind: Kind,
    note: String,
    grade: Grade,
    skip_reason: Option<String>,
    cb_findings: Vec<CbFinding>,
    cb_cves: usize,
    /// cudabom extracted embedded GPU device code (fatbin/PTX).
    cb_gpu_code: bool,
    /// Distinct SM cubin targets cudabom found (0 if none).
    cb_sm_targets: usize,
    /// Count of CUDA libraries found inside the artifact.
    inner_libs: usize,
    syft_named: Option<bool>,
    trivy_cve: Option<bool>,
    blint_named: Option<bool>,
}

impl DistRow {
    fn skipped(a: &Artifact, reason: String) -> Self {
        Self {
            id: a.id.clone(),
            kind: a.kind,
            note: a.note.clone(),
            grade: Grade::Skipped,
            skip_reason: Some(reason),
            cb_findings: Vec::new(),
            cb_cves: 0,
            cb_gpu_code: false,
            cb_sm_targets: 0,
            inner_libs: 0,
            syft_named: None,
            trivy_cve: None,
            blint_named: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Per-artifact evaluation
// ---------------------------------------------------------------------------

/// Acquire, unpack, and evaluate one artifact across all tools.
fn evaluate_artifact(ctx: &EvalCtx<'_>, a: &Artifact) -> Result<DistRow> {
    /// blint is a slow Python tool; naming CUDA in a sample is representative.
    const BLINT_SAMPLE: usize = 3;
    detail!("xtask: dist [{}] {}: {}", a.kind.label(), a.id, a.note);

    // 1. Acquire + unpack. Returns the directory tree to search for CUDA libs,
    //    and the "native artifact" path competitors scan directly (the wheel,
    //    the image ref, or the file itself).
    let acquired = acquire(ctx, a)?;

    // 2. Find the CUDA libraries inside.
    let libs = find_cuda_libraries(&acquired.scan_root, a.kind);
    if libs.is_empty() && a.kind != Kind::Container {
        bail!(
            "no CUDA libraries found under {}",
            acquired.scan_root.display()
        );
    }

    // 3. cudabom (on every CUDA lib) + blint (on a bounded sample; it is a
    //    slow Python tool and naming one CUDA lib is representative). Findings
    //    are de-duplicated so a wheel bundling many copies is not double-counted.
    let mut cb_findings: Vec<CbFinding> = Vec::new();
    let mut cb_cves = 0usize;
    let mut cb_gpu_code = false;
    let mut cb_sm_targets: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut blint_named = ctx.tools.have_blint.then_some(false);
    for (i, lib) in libs.iter().enumerate() {
        let scan = run_cudabom(ctx.cudabom, lib, ctx.db, ctx.advisories);
        cb_cves += scan.cves;
        cb_gpu_code |= scan.has_gpu_code;
        cb_sm_targets.extend(scan.sm_targets);
        for (name, version, confidence) in scan.findings {
            let already = cb_findings
                .iter()
                .any(|f| f.name == name && f.version == version);
            if !already {
                let lib_name = lib
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("?")
                    .to_string();
                cb_findings.push(CbFinding {
                    lib: lib_name,
                    name,
                    version,
                    confidence,
                });
            }
        }
        if ctx.tools.have_blint && i < BLINT_SAMPLE && blint_probe(lib).1 {
            blint_named = Some(true);
        }
    }

    // 4. Syft + Trivy on the NATIVE artifact (where their package metadata is).
    let native = &acquired.native;
    let syft_named = ctx
        .tools
        .have_syft
        .then(|| syft_names_cuda(native, acquired.is_image));
    let trivy_cve = ctx
        .tools
        .have_trivy
        .then(|| trivy_has_cve(native, acquired.is_image));

    // 5. Grade cudabom against expectations.
    let grade = grade_cudabom(a, &cb_findings, libs.len());

    // 6. In streaming mode, reclaim this artifact's working set now, before
    //    the next artifact is acquired, so peak disk is one artifact, not the
    //    whole set. Best-effort: a cleanup failure must not fail the eval.
    if ctx.stream {
        reclaim_artifact(ctx, &acquired);
    }

    Ok(DistRow {
        id: a.id.clone(),
        kind: a.kind,
        note: a.note.clone(),
        grade,
        skip_reason: None,
        cb_findings,
        cb_cves,
        cb_gpu_code,
        cb_sm_targets: cb_sm_targets.len(),
        inner_libs: libs.len(),
        syft_named,
        trivy_cve,
        blint_named,
    })
}

/// The result of acquiring an artifact: where to search for libraries, and the
/// native thing competitors scan directly.
struct Acquired {
    /// Directory tree to search for CUDA `.so`/`.dll` files.
    scan_root: PathBuf,
    /// What Syft/Trivy scan directly (a file path, or an image ref string).
    native: String,
    /// True if `native` is a container image reference (not a filesystem path).
    is_image: bool,
    /// The on-disk working set to delete in `--stream` mode once this artifact
    /// is scored (the downloaded file + any unpacked tree). `None` for
    /// synthetic artifacts, whose source is the shared redist corpus and must
    /// not be removed.
    cleanup_dir: Option<PathBuf>,
    /// A pinned image reference to `docker rmi` in `--stream` mode once scored,
    /// so a multi-GB image layer cache does not persist. `None` for non-image
    /// artifacts.
    cleanup_image: Option<String>,
}

/// Dispatch acquisition by kind.
fn acquire(ctx: &EvalCtx<'_>, a: &Artifact) -> Result<Acquired> {
    match a.kind {
        Kind::Wheel | Kind::Conda | Kind::Archive => acquire_download(ctx, a),
        Kind::Container => acquire_container(ctx, a),
        Kind::Synthetic => acquire_synthetic(ctx, a),
    }
}

/// Reclaim an artifact's on-disk working set (and image cache, for containers)
/// after it has been scored. Best-effort: cleanup failures are logged at detail
/// level and never fail the eval. Called only in `--stream` mode; without it
/// the full `corpus/distribution` tree persists for inspection and re-runs.
fn reclaim_artifact(ctx: &EvalCtx<'_>, acquired: &Acquired) {
    if let Some(dir) = &acquired.cleanup_dir {
        remove_working_dir(dir);
    }
    if let Some(image) = &acquired.cleanup_image {
        if ctx.tools.have_docker {
            // Drop the pulled image so its (multi-GB) layers do not accumulate
            // across the container tier. `--force` ignores "no such image".
            let _ = Command::new("docker")
                .args(["rmi", "--force", image])
                .status();
        }
    }
}

/// Best-effort removal of a streaming working directory. A failure is only
/// logged (at detail level) when the directory still exists afterward, since it
/// may already be gone or only partially held; it never fails the eval.
fn remove_working_dir(dir: &Path) {
    if let Err(e) = std::fs::remove_dir_all(dir) {
        if dir.exists() {
            detail!(
                "xtask: stream cleanup: could not remove {}: {e}",
                dir.display()
            );
        }
    }
}

/// Download (sha256-verified) and unpack a wheel/conda/archive. Wheels and
/// `.conda` are zip containers; a `.conda` nests zstd-compressed tars that are
/// expanded in a second pass.
fn acquire_download(ctx: &EvalCtx<'_>, a: &Artifact) -> Result<Acquired> {
    use cudabom_fetch::verify_sha256;

    let url = a.url.as_deref().context("entry has no url")?;
    let sha = a.sha256.as_deref().context("entry has no sha256")?;
    let file_name = url.rsplit('/').next().unwrap_or("artifact");
    let dest = ctx.corpus_dir.join(&a.id).join(file_name);
    std::fs::create_dir_all(dest.parent().unwrap())?;

    let present = std::fs::read(&dest).is_ok_and(|b| verify_sha256(&b, sha).is_ok());
    if !present {
        if !ctx.download && dest.exists() {
            // A file is there but fails verification: refuse to trust it.
            bail!(
                "{} exists but sha256 mismatch; re-run with --download",
                dest.display()
            );
        }
        if !ctx.download {
            bail!(
                "{} not present; re-run with --download to fetch it",
                dest.display()
            );
        }
        status!("xtask: fetching {} ({})", a.id, file_name);
        crate::eval_tools::fetch_verified(url, sha, &dest)?;
    }

    // Both `.whl` and `.conda` are zip containers; `unpack_as_zip` runs `unzip`
    // directly regardless of extension.
    let unpacked = unpack_as_zip(&dest)?;
    if a.kind == Kind::Conda {
        expand_conda_inner_tars(&unpacked)?;
    }

    Ok(Acquired {
        scan_root: unpacked,
        native: dest.display().to_string(),
        is_image: false,
        // The per-artifact directory holds both the download and the unpacked
        // tree; reclaim the whole thing in --stream mode.
        cleanup_dir: Some(ctx.corpus_dir.join(&a.id)),
        cleanup_image: None,
    })
}

/// Unpack a zip-shaped file (wheel/conda) into a sibling `-unpacked` dir,
/// returning that dir. Wheels end in `.whl` and conda in `.conda`; neither is
/// `.zip`, so we unzip explicitly here rather than via extension sniffing.
fn unpack_as_zip(path: &Path) -> Result<PathBuf> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let stem = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("artifact");
    let dest = parent.join(format!("{stem}-unpacked"));
    if dest.exists() {
        return Ok(dest);
    }
    std::fs::create_dir_all(&dest)?;
    let ok = Command::new("unzip")
        .arg("-oq")
        .arg(path)
        .arg("-d")
        .arg(&dest)
        .status()
        .is_ok_and(|s| s.success());
    if !ok {
        let _ = std::fs::remove_dir_all(&dest);
        bail!("failed to unzip {}", path.display());
    }
    Ok(dest)
}

/// A `.conda` package is a zip whose payload is `pkg-*.tar.zst` (+ `info-*`).
/// Expand each inner zstd tar in place so the real libraries become visible.
fn expand_conda_inner_tars(dir: &Path) -> Result<()> {
    for path in walk_files(dir) {
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if name.ends_with(".tar.zst") {
            let out = path.with_extension("").with_extension("");
            let out_dir = path.parent().unwrap().join(format!(
                "{}-expanded",
                out.file_name().and_then(|n| n.to_str()).unwrap_or("inner")
            ));
            std::fs::create_dir_all(&out_dir)?;
            // `tar` with zstd support (`--zstd`) handles .tar.zst directly.
            let ok = Command::new("tar")
                .arg("--zstd")
                .arg("-xf")
                .arg(&path)
                .arg("-C")
                .arg(&out_dir)
                .status()
                .is_ok_and(|s| s.success());
            if !ok {
                detail!("xtask: could not expand {} (skipping)", path.display());
            }
        }
    }
    Ok(())
}

/// Pull (by digest) and export a container image to a tar, then unpack its
/// layers so the root filesystem's CUDA libraries are visible. Requires docker.
fn acquire_container(ctx: &EvalCtx<'_>, a: &Artifact) -> Result<Acquired> {
    let image = a.image.as_deref().context("container entry has no image")?;
    let digest = a
        .digest
        .as_deref()
        .context("container entry has no digest")?;
    // Pin by digest so the pull is reproducible regardless of tag drift.
    let pinned = format!("{}@{}", image.split(':').next().unwrap_or(image), digest);

    if !ctx.tools.have_docker {
        bail!("docker not available to pull {pinned}");
    }
    if !ctx.download {
        bail!("container {pinned} requires --download (docker pull)");
    }

    status!("xtask: docker pull {pinned}");
    let pulled = Command::new("docker")
        .args(["pull", "--quiet", &pinned])
        .status()
        .is_ok_and(|s| s.success());
    if !pulled {
        bail!("docker pull {pinned} failed");
    }

    let work = ctx.corpus_dir.join(&a.id);
    let rootfs = work.join("rootfs");
    if !rootfs.exists() {
        std::fs::create_dir_all(&rootfs)?;
        // `docker create` + `docker export` flattens all layers into one tar:
        // simpler and more reliable than reassembling `docker save` layers.
        let cid = Command::new("docker").args(["create", &pinned]).output()?;
        let cid = String::from_utf8_lossy(&cid.stdout).trim().to_string();
        if cid.is_empty() {
            bail!("docker create {pinned} produced no container id");
        }
        let tar_path = work.join("rootfs.tar");
        let exported = Command::new("docker")
            .args(["export", "-o"])
            .arg(&tar_path)
            .arg(&cid)
            .status()
            .is_ok_and(|s| s.success());
        let _ = Command::new("docker").args(["rm", "-f", &cid]).status();
        if !exported {
            bail!("docker export {cid} failed");
        }
        let ok = Command::new("tar")
            .arg("-xf")
            .arg(&tar_path)
            .arg("-C")
            .arg(&rootfs)
            .status()
            .is_ok_and(|s| s.success());
        if !ok {
            bail!("unpacking exported rootfs failed");
        }
        // The flattened tar is no longer needed once extracted. Removing it now
        // (rather than at end-of-artifact) roughly halves peak disk for a fat
        // image, since the tar and the extracted tree would otherwise coexist.
        let _ = std::fs::remove_file(&tar_path);
    }

    Ok(Acquired {
        scan_root: rootfs,
        // Competitors scan the image natively (by its pinned ref).
        native: pinned.clone(),
        is_image: true,
        cleanup_dir: Some(work),
        cleanup_image: Some(pinned),
    })
}

/// Synthesize an adversarial artifact from an already-present redist corpus
/// library, per the entry's transform (rename / static-exe / upx / embed).
fn acquire_synthetic(ctx: &EvalCtx<'_>, a: &Artifact) -> Result<Acquired> {
    let fc = a
        .from_corpus
        .as_ref()
        .context("synthetic entry has no from_corpus")?;
    let source = resolve_corpus_library(fc).with_context(|| {
        format!(
            "resolving {} {} {} ~{} from {REDIST_CORPUS_DIR}; run the redist eval with --download first",
            fc.component, fc.version, fc.platform, fc.match_substr
        )
    })?;

    let work = ctx.corpus_dir.join(&a.id);
    // Rebuild the synthesized output each run so a changed transform/source is
    // reflected; the inputs are tiny local copies.
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(&work)?;

    let dest = match a.transform {
        Transform::Rename => synth_rename(a, &source, &work)?,
        Transform::StaticExe => synth_static_exe(&source, &work)?,
        Transform::Upx => synth_upx(a, &source, &work)?,
        Transform::Embed => synth_embed(a, &source, &work)?,
    };
    detail!(
        "xtask: synth [{}] {} -> {}",
        a.transform.label(),
        source.display(),
        dest.display()
    );

    Ok(Acquired {
        scan_root: work.clone(),
        native: dest.display().to_string(),
        is_image: false,
        // Only the synthesized copy under corpus_dir/<id> is ours to remove;
        // the shared redist corpus the source came from is left untouched.
        cleanup_dir: Some(work),
        cleanup_image: None,
    })
}

/// Transform `rename`: copy, optionally strip, rename to an innocuous name.
fn synth_rename(a: &Artifact, source: &Path, work: &Path) -> Result<PathBuf> {
    let renamed = a.rename_to.as_deref().unwrap_or("libanon.so");
    let dest = work.join(renamed);
    std::fs::copy(source, &dest)
        .with_context(|| format!("copying {} -> {}", source.display(), dest.display()))?;
    if a.strip {
        // Best-effort strip; a cross-platform host may no-op, which is fine
        // because the rename already defeats name/soname heuristics and the
        // content hash is unchanged.
        let stripped = run_quiet("llvm-strip", &["--strip-all", dest.to_str().unwrap_or("")])
            || run_quiet("strip", &["--strip-all", dest.to_str().unwrap_or("")]);
        detail!("xtask: strip {} -> {}", dest.display(), yesno(stripped));
    }
    Ok(dest)
}

/// Transform `static-exe`: link the component's static library into an
/// executable so there is no `.so` at all: the pure static-deployment case.
///
/// cudabom identifies static CUDA by hashing the `.a`'s member objects; the
/// linked executable embeds those same objects. Linking a foreign-platform `.a`
/// requires a matching cross-toolchain, which is often absent (e.g. a Linux
/// x86_64 `.a` on a macOS arm64 host). When linking is not possible we fall
/// back to placing the `.a` itself in the scan root: cudabom's static-member
/// fingerprint path, the mechanism under test, runs either way.
fn synth_static_exe(source: &Path, work: &Path) -> Result<PathBuf> {
    // The source here is the `.a` resolved by from_corpus.match (e.g.
    // `libcudart_static.a`). Try to link a trivial program against it.
    let archive = work.join(source.file_name().unwrap_or_default());
    std::fs::copy(source, &archive)?;

    let csrc = work.join("main.c");
    std::fs::write(&csrc, b"int main(void){return 0;}\n")?;
    let exe = work.join("staticapp");
    // Only attempt a native link; a foreign-ELF `.a` will fail here and we fall
    // back. We do not force a cross-target because we cannot assume a sysroot.
    let linked = run_quiet(
        "cc",
        &[
            csrc.to_str().unwrap_or(""),
            archive.to_str().unwrap_or(""),
            "-o",
            exe.to_str().unwrap_or(""),
        ],
    );
    if linked && exe.exists() {
        // Drop the loose `.a` so only the executable is scanned.
        let _ = std::fs::remove_file(&archive);
        return Ok(exe);
    }
    detail!(
        "xtask: static link not possible on this host; scanning the archive directly ({})",
        archive.display()
    );
    let _ = std::fs::remove_file(&csrc);
    let _ = std::fs::remove_file(&exe);
    Ok(archive)
}

/// Transform `upx`: UPX-compress a renamed copy. The on-disk bytes change, so a
/// file-hash match is defeated; the finding is whether any signal survives.
///
/// If packing does not actually happen (UPX missing, or it refuses the input:
/// e.g. a foreign-platform ELF on this host), we do *not* silently fall back to
/// the unpacked copy, because that would mislabel a plain copy as a UPX result.
/// Instead the entry is skipped with a clear reason.
fn synth_upx(a: &Artifact, source: &Path, work: &Path) -> Result<PathBuf> {
    let name = a.rename_to.as_deref().unwrap_or("libpacked.so");
    let dest = work.join(name);
    std::fs::copy(source, &dest)?;
    let packed = run_quiet("upx", &["-q", "--best", dest.to_str().unwrap_or("")]);
    if !packed || !has_upx_magic(&dest) {
        bail!(
            "upx did not pack the input on this host (upx missing or refused the \
             foreign-platform binary); skipping rather than mislabel an unpacked copy"
        );
    }
    detail!("xtask: upx packed {}", dest.display());
    Ok(dest)
}

/// Does the file carry the `UPX!` marker, i.e. was it actually UPX-packed?
fn has_upx_magic(path: &Path) -> bool {
    std::fs::read(path).is_ok_and(|b| b.windows(4).any(|w| w == b"UPX!"))
}

/// Transform `embed`: prepend padding so the real library sits at a non-zero
/// offset inside a larger blob, mimicking a vendored payload concatenated into
/// another file.
fn synth_embed(a: &Artifact, source: &Path, work: &Path) -> Result<PathBuf> {
    let name = a.rename_to.as_deref().unwrap_or("blob.bin");
    let dest = work.join(name);
    let mut blob = vec![0xABu8; 64 * 1024]; // 64 KiB of junk header
    blob.extend_from_slice(b"\n--- embedded payload below ---\n");
    let lib = std::fs::read(source)?;
    blob.extend_from_slice(&lib);
    std::fs::write(&dest, &blob)?;
    Ok(dest)
}

/// Find the real library file in the redist corpus matching a `from_corpus`
/// resolver (component/version/platform tree, file name containing a substring).
fn resolve_corpus_library(fc: &FromCorpus) -> Result<PathBuf> {
    let base = Path::new(REDIST_CORPUS_DIR)
        .join(&fc.component)
        .join(&fc.version)
        .join(&fc.platform);
    if !base.exists() {
        bail!("corpus path {} does not exist", base.display());
    }
    let mut best: Option<PathBuf> = None;
    for path in walk_files(&base) {
        if std::fs::symlink_metadata(&path).is_ok_and(|m| m.file_type().is_symlink()) {
            continue;
        }
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        // Match on the (specific) substring only; it already encodes the file
        // kind (e.g. `libcudart.so`, `libcudart_static.a`). Among matches,
        // prefer the longest name (the concrete versioned object over a short
        // symlink stem).
        if name.contains(&fc.match_substr) {
            let longer = best.as_ref().is_none_or(|b| {
                name.len() > b.file_name().and_then(|n| n.to_str()).map_or(0, str::len)
            });
            if longer {
                best = Some(path);
            }
        }
    }
    best.with_context(|| {
        format!(
            "no file matching {} under {}",
            fc.match_substr,
            base.display()
        )
    })
}

// ---------------------------------------------------------------------------
// Library discovery + tool invocations
// ---------------------------------------------------------------------------

/// Every file under `root` that is a CUDA-relevant native library.
///
/// For most kinds this means a shared object or DLL whose name looks like a
/// CUDA library (`libcud*`, `libnccl*`, `libnv*`, `cudart64_*.dll`, ...). This
/// matters most for containers, whose root filesystem holds thousands of
/// unrelated OS binaries we must not scan.
///
/// For the `synthetic` kind the whole point is a renamed/stripped copy whose
/// name no longer matches, so there we accept any regular ELF file (the scan
/// root is a tiny dedicated directory holding only the synthesized copy).
fn find_cuda_libraries(root: &Path, kind: Kind) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for path in walk_files(root) {
        if std::fs::symlink_metadata(&path).is_ok_and(|m| m.file_type().is_symlink()) {
            continue;
        }
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        let is_so = name.contains(".so");
        let is_dll = std::path::Path::new(&name)
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("dll"));
        let keep = if kind == Kind::Synthetic {
            // Adversarial case: the scan root is a tiny dedicated directory
            // holding only the synthesized artifact, whose name/format is
            // intentionally non-obvious (renamed ELF, a `.a`, a UPX-packed blob,
            // or a library embedded at an offset in a larger blob). Scan every
            // regular file so the transform under test is actually exercised.
            true
        } else {
            (is_so || is_dll) && looks_like_cuda_library(&name)
        };
        if keep {
            out.push(path);
        }
    }
    out
}

/// Does a lowercased library file name look like an NVIDIA/CUDA library?
/// Deliberately broad on the NVIDIA prefix set but anchored enough to exclude
/// generic OS libraries so a container scan stays focused.
fn looks_like_cuda_library(name: &str) -> bool {
    const PREFIXES: &[&str] = &[
        "libcud",    // cudart, cudnn, cublas (libcublas), cufft, cusolver, cusparse, cudss
        "libcu",     // cutensor, cupti, cufile, curand (covers libcu*)
        "libnccl",   //
        "libnv",     // libnvrtc, libnvjpeg, libnvperf, libnvToolsExt, libnvinfer
        "libcublas", //
        "libcufft",  //
        "libcusolver",
        "libcusparse",
        "libcurand",
        "libnpp", // NPP image/signal libs
    ];
    if PREFIXES.iter().any(|p| name.starts_with(p)) {
        return true;
    }
    // Windows DLL naming: cudart64_12.dll, cublas64_11.dll, nvrtc64_*, nccl*.dll
    name.starts_with("cudart")
        || name.starts_with("cublas")
        || name.starts_with("cudnn")
        || name.starts_with("nvrtc")
        || name.starts_with("nccl")
        || name.starts_with("cufft")
        || name.starts_with("cusolver")
        || name.starts_with("cusparse")
}

/// Run a command with output suppressed; true on a clean exit. Used for
/// best-effort tooling (e.g. `strip`) where failure is non-fatal.
fn run_quiet(bin: &str, args: &[&str]) -> bool {
    Command::new(bin)
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// Run cudabom on one library; return its (name, version, confidence) findings
/// and the number of correlated advisories.
fn run_cudabom(bin: &Path, lib: &Path, db: &str, advisories: &str) -> CbScan {
    let Some(json) = crate::eval_tools::run_cudabom_scan(bin, lib, db, advisories) else {
        return CbScan::default();
    };
    let findings = json
        .get("findings")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let cves = findings
        .iter()
        .map(|f| {
            f.get("advisories")
                .and_then(|v| v.as_array())
                .map_or(0, Vec::len)
        })
        .sum();
    let got = crate::eval_tools::parse_findings(&json);
    // GPU-code (fatbin/PTX) capability: a signal no general SBOM/CVE tool
    // reports. Collect the distinct SM targets cudabom extracted from embedded
    // fatbins/PTX, so the report can show "cudabom saw executable GPU code".
    let cap = json.get("capability");
    let has_gpu_code = cap
        .and_then(|c| c.get("gpu_code_units"))
        .and_then(serde_json::Value::as_u64)
        .is_some_and(|n| n > 0)
        || cap
            .and_then(|c| c.get("has_cubin"))
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
    let sm_targets = cap
        .and_then(|c| c.get("cubin_sm_targets"))
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    CbScan {
        findings: got,
        cves,
        has_gpu_code,
        sm_targets,
    }
}

/// What one cudabom scan of one library yielded.
#[derive(Debug, Default)]
struct CbScan {
    findings: Vec<(String, String, String)>,
    cves: usize,
    /// cudabom extracted embedded GPU device code (fatbin cubins / PTX).
    has_gpu_code: bool,
    /// The distinct SM (compute-capability) cubin targets found in this
    /// library, by name, so callers can union them across many libraries.
    sm_targets: Vec<String>,
}

/// Grade cudabom's findings against the artifact's expectations.
fn grade_cudabom(a: &Artifact, findings: &[CbFinding], inner_libs: usize) -> Grade {
    let named_any = !findings.is_empty();
    // Detection-only entry (no version ground truth).
    if a.expect.is_empty() || a.expect.iter().all(|e| e.version.is_none()) {
        if a.expect.is_empty() {
            // Fully open: any CUDA naming counts as detection.
            return if named_any {
                Grade::DetectedKnownNoVersion
            } else if inner_libs == 0 {
                Grade::Skipped
            } else {
                Grade::Miss
            };
        }
        // Component known, version not: require the named component.
        let want: Vec<&str> = a.expect.iter().map(|e| e.component.as_str()).collect();
        let hit = findings.iter().any(|f| want.contains(&f.name.as_str()));
        return if hit {
            Grade::DetectedKnownNoVersion
        } else {
            Grade::Miss
        };
    }

    // Versioned ground truth: every expected (component, version) must be met.
    // A finding meets it exactly (`12.4.127` == `12.4.127`), by family (the
    // finding is a prefix family of the truth, e.g. `12.x` for `12.4.127`, or a
    // dotted prefix like `12.4`), or not at all.
    let mut all_exact = true;
    let mut all_consistent = true;
    let mut any_component_named = false;
    for e in &a.expect {
        let Some(want_ver) = &e.version else { continue };
        let component_hits: Vec<&CbFinding> =
            findings.iter().filter(|f| f.name == e.component).collect();
        if !component_hits.is_empty() {
            any_component_named = true;
        }
        let exact = component_hits.iter().any(|f| &f.version == want_ver);
        let consistent = component_hits
            .iter()
            .any(|f| version_is_consistent(&f.version, want_ver));
        if !exact {
            all_exact = false;
        }
        if !consistent {
            all_consistent = false;
        }
    }
    if all_exact {
        Grade::Exact
    } else if any_component_named && all_consistent {
        Grade::FamilyMatch
    } else if any_component_named {
        Grade::VersionMismatch
    } else {
        Grade::Miss
    }
}

/// Is `got` a version consistent with (not contradicting) ground truth `truth`?
///
/// True when:
///   - equal (`12.4.127` == `12.4.127`), or
///   - `got` is a family/prefix of `truth` (`12.x` or `12.4` for `12.4.127`), or
///   - `got` *extends* `truth` with extra trailing components (`2.8.1.0` for a
///     ground truth of `2.8.1`). This arises when the derived binary version is
///     more precise than the shorter version a package advertises (e.g. a PyPI
///     wheel pins `cutensor-cu12 2.8.1` but the library's own version is
///     `2.8.1.0`). The shared leading components agree, so it is not a mismatch.
fn version_is_consistent(got: &str, truth: &str) -> bool {
    if got == truth {
        return true;
    }
    // Family form `N.x` / `N.M.x`: strip the trailing `.x` and require the
    // remaining dotted prefix to match the truth's leading components.
    let got_prefix = got.strip_suffix(".x").unwrap_or(got);
    let g: Vec<&str> = got_prefix.split('.').filter(|s| !s.is_empty()).collect();
    let t: Vec<&str> = truth.split('.').filter(|s| !s.is_empty()).collect();
    if g.is_empty() || t.is_empty() {
        return false;
    }
    // Consistent when one is a dotted prefix of the other (in either direction):
    // `got` is a family of `truth` (g shorter), or `got` extends `truth` with
    // extra precision (g longer). The overlapping components must all agree.
    let shared = g.len().min(t.len());
    g[..shared].iter().zip(&t[..shared]).all(|(a, b)| a == b)
}

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

fn distribution_json(rows: &[DistRow]) -> String {
    let value = serde_json::json!({
        "artifacts": rows.iter().map(|r| serde_json::json!({
            "id": r.id,
            "kind": r.kind.label(),
            "note": r.note,
            "grade": r.grade.label(),
            "skip_reason": r.skip_reason,
            "inner_libs": r.inner_libs,
            "cudabom": {
                "findings": r.cb_findings.iter().map(|f| serde_json::json!({
                    "lib": f.lib, "name": f.name, "version": f.version, "confidence": f.confidence,
                })).collect::<Vec<_>>(),
                "cve_matches": r.cb_cves,
                "gpu_code": r.cb_gpu_code,
                "sm_targets": r.cb_sm_targets,
            },
            "syft_named_cuda": r.syft_named,
            "trivy_cve": r.trivy_cve,
            "blint_named_cuda": r.blint_named,
        })).collect::<Vec<_>>(),
    });
    serde_json::to_string_pretty(&value).unwrap_or_else(|_| "{}".to_string())
}

#[allow(clippy::cognitive_complexity)]
fn print_report(rows: &[DistRow], tools: Tools) {
    println!(
        "\n=== cudabom vs competitors on in-the-wild artifacts ({} artifact(s)) ===\n",
        rows.len()
    );

    let scored: Vec<&DistRow> = rows.iter().filter(|r| r.grade != Grade::Skipped).collect();
    let exact = scored.iter().filter(|r| r.grade == Grade::Exact).count();
    let family = scored
        .iter()
        .filter(|r| r.grade == Grade::FamilyMatch)
        .count();
    let detected = scored
        .iter()
        .filter(|r| r.grade == Grade::DetectedKnownNoVersion)
        .count();
    let mismatch = scored
        .iter()
        .filter(|r| r.grade == Grade::VersionMismatch)
        .count();
    let miss = scored.iter().filter(|r| r.grade == Grade::Miss).count();
    let skipped = rows.len() - scored.len();

    println!("cudabom outcomes over {} scored artifact(s):", scored.len());
    println!("  exact version pin   : {exact}");
    println!("  family-consistent   : {family}  (named + major family, exact bytes not yet fingerprinted)");
    println!("  detected (no gt ver): {detected}");
    println!("  version mismatch    : {mismatch}");
    println!("  miss                : {miss}");
    if skipped > 0 {
        println!("  skipped (acquire)   : {skipped}");
    }

    let cb_named = scored.iter().filter(|r| !r.cb_findings.is_empty()).count();
    let cb_cve_total: usize = scored.iter().map(|r| r.cb_cves).sum();
    let cb_cve_arts = scored.iter().filter(|r| r.cb_cves > 0).count();
    let cb_gpu = scored.iter().filter(|r| r.cb_gpu_code).count();
    let syft = scored.iter().filter(|r| r.syft_named == Some(true)).count();
    let trivy = scored.iter().filter(|r| r.trivy_cve == Some(true)).count();
    let blint = scored
        .iter()
        .filter(|r| r.blint_named == Some(true))
        .count();

    println!("\nhead-to-head over {} scored artifact(s):", scored.len());
    println!("  cudabom names a CUDA component : {cb_named}");
    println!(
        "  cudabom correlates a CVE       : {cb_cve_arts} artifact(s) ({cb_cve_total} advisory match(es) total)"
    );
    println!("  cudabom sees GPU code (fatbin) : {cb_gpu}  (no SBOM/CVE tool reports this)");
    println!(
        "  Syft names a CUDA component    : {}",
        tool_cell(tools.have_syft, syft)
    );
    println!(
        "  blint names a CUDA component   : {}",
        tool_cell(tools.have_blint, blint)
    );
    println!(
        "  Trivy correlates a CVE         : {}",
        tool_cell(tools.have_trivy, trivy)
    );

    println!("\nper-artifact:");
    for r in rows {
        let cb = if r.cb_findings.is_empty() {
            "-".to_string()
        } else {
            r.cb_findings
                .iter()
                .map(|f| format!("{} {} ({})", f.name, f.version, f.confidence))
                .collect::<Vec<_>>()
                .join(", ")
        };
        let flag = match r.grade {
            Grade::Exact | Grade::FamilyMatch | Grade::DetectedKnownNoVersion => String::new(),
            Grade::Skipped => format!("   <<< skipped: {}", r.skip_reason.as_deref().unwrap_or("")),
            g => format!("   <<< {}", g.label()),
        };
        let gpu = if r.cb_gpu_code {
            format!("gpu={}sm", r.cb_sm_targets)
        } else {
            "gpu=no".to_string()
        };
        println!(
            "  [{:16}] {:10} {:28} syft={} trivy={} blint={} {} -> cudabom: {}{}",
            r.grade.label(),
            r.kind.label(),
            r.id,
            opt(r.syft_named),
            opt(r.trivy_cve),
            opt(r.blint_named),
            gpu,
            cb,
            flag,
        );
    }
    println!();
}

fn tool_cell(installed: bool, count: usize) -> String {
    if installed {
        count.to_string()
    } else {
        "not installed".to_string()
    }
}

fn opt(b: Option<bool>) -> &'static str {
    match b {
        Some(true) => "yes",
        Some(false) => "no",
        None => "n/a",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_consistency_matches_families_prefixes_and_extensions() {
        // Exact.
        assert!(version_is_consistent("12.4.127", "12.4.127"));
        // Major family `N.x`.
        assert!(version_is_consistent("12.x", "12.4.127"));
        // Dotted prefix.
        assert!(version_is_consistent("12.4", "12.4.127"));
        // Wrong major is not consistent.
        assert!(!version_is_consistent("11.x", "12.4.127"));
        // A derived version that EXTENDS the truth with extra precision is
        // consistent (the overlapping components agree): a wheel advertising
        // `cutensor 2.8.1` vs the library's own `2.8.1.0`.
        assert!(version_is_consistent("2.8.1.0", "2.8.1"));
        assert!(version_is_consistent("12.4.127.1", "12.4.127"));
        // ...but only when the shared components agree; a differing trailing
        // component before the extension still contradicts.
        assert!(!version_is_consistent("2.8.2.0", "2.8.1"));
        // Different minor contradicts.
        assert!(!version_is_consistent("12.5", "12.4.127"));
    }

    fn finding(name: &str, version: &str) -> CbFinding {
        CbFinding {
            lib: format!("lib{name}.so"),
            name: name.to_string(),
            version: version.to_string(),
            confidence: "likely".to_string(),
        }
    }

    fn artifact(expect: Vec<Expect>) -> Artifact {
        Artifact {
            id: "t".to_string(),
            kind: Kind::Wheel,
            note: String::new(),
            url: None,
            sha256: None,
            image: None,
            digest: None,
            from_corpus: None,
            rename_to: None,
            strip: false,
            transform: Transform::Rename,
            expect,
        }
    }

    #[test]
    fn grade_exact_when_version_pinned() {
        let a = artifact(vec![Expect {
            component: "cudart".into(),
            version: Some("12.4.99".into()),
        }]);
        let f = vec![finding("cudart", "12.4.99")];
        assert_eq!(grade_cudabom(&a, &f, 1), Grade::Exact);
    }

    #[test]
    fn grade_family_when_only_major_known() {
        let a = artifact(vec![Expect {
            component: "cudart".into(),
            version: Some("12.4.127".into()),
        }]);
        // A wheel's libcudart.so.12 resolves to the `12.x` family.
        let f = vec![finding("cudart", "12.x")];
        assert_eq!(grade_cudabom(&a, &f, 1), Grade::FamilyMatch);
    }

    #[test]
    fn grade_mismatch_on_wrong_major() {
        let a = artifact(vec![Expect {
            component: "cudart".into(),
            version: Some("12.4.127".into()),
        }]);
        let f = vec![finding("cudart", "11.x")];
        assert_eq!(grade_cudabom(&a, &f, 1), Grade::VersionMismatch);
    }

    #[test]
    fn grade_miss_when_component_absent() {
        let a = artifact(vec![Expect {
            component: "cudart".into(),
            version: Some("12.4.127".into()),
        }]);
        assert_eq!(grade_cudabom(&a, &[], 1), Grade::Miss);
    }

    #[test]
    fn grade_detected_when_no_version_ground_truth() {
        let a = artifact(vec![Expect {
            component: "cublas".into(),
            version: None,
        }]);
        let f = vec![finding("cublas", "13.x")];
        assert_eq!(grade_cudabom(&a, &f, 1), Grade::DetectedKnownNoVersion);
    }

    #[test]
    fn library_name_filter_is_focused() {
        assert!(looks_like_cuda_library("libcudart.so.12"));
        assert!(looks_like_cuda_library("libnccl.so.2"));
        assert!(looks_like_cuda_library("cudart64_12.dll"));
        assert!(looks_like_cuda_library("libnvrtc.so.12"));
        // Generic OS libraries must not be swept in from a container rootfs.
        assert!(!looks_like_cuda_library("libc.so.6"));
        assert!(!looks_like_cuda_library("libssl.so.3"));
        assert!(!looks_like_cuda_library("libpython3.11.so"));
    }

    #[test]
    fn transform_parses_all_known_kinds() {
        assert_eq!(Transform::parse("rename").unwrap(), Transform::Rename);
        assert_eq!(
            Transform::parse("static-exe").unwrap(),
            Transform::StaticExe
        );
        assert_eq!(Transform::parse("upx").unwrap(), Transform::Upx);
        assert_eq!(Transform::parse("embed").unwrap(), Transform::Embed);
        assert!(Transform::parse("nope").is_err());
    }

    /// A throwaway unique directory under the system temp dir (xtask has no
    /// tempfile dev-dependency; this keeps the test deps unchanged).
    fn scratch_dir(tag: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let dir = std::env::temp_dir().join(format!("cudabom-disttest-{tag}-{nanos}"));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn embed_puts_the_library_at_a_nonzero_offset() {
        let dir = scratch_dir("embed");
        let src = dir.join("libcudart.so.12.4.99");
        // A fake ELF payload: the magic must survive, shifted past the header.
        let payload = [0x7f, b'E', b'L', b'F', 1, 2, 3, 4, 5, 6, 7, 8];
        std::fs::write(&src, payload).unwrap();
        let a = artifact(vec![]);
        let out = synth_embed(&a, &src, &dir).unwrap();
        let blob = std::fs::read(&out).unwrap();
        // The ELF magic is present but not at offset 0 (prepended junk header).
        assert_ne!(&blob[0..4], &[0x7f, b'E', b'L', b'F']);
        let at = blob
            .windows(4)
            .position(|w| w == [0x7f, b'E', b'L', b'F'])
            .expect("payload embedded");
        assert!(at > 0, "library sits at a non-zero offset");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn upx_magic_detection() {
        let dir = scratch_dir("upx");
        let packed = dir.join("p");
        std::fs::write(&packed, b"....UPX!....").unwrap();
        assert!(has_upx_magic(&packed));
        let plain = dir.join("q");
        std::fs::write(&plain, b"just an elf").unwrap();
        assert!(!has_upx_magic(&plain));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
