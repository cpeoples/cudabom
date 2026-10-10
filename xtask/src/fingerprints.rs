//! `cargo xtask fingerprints build`: derive fingerprint shards.
//!
//! Two derivation sources feed the shards:
//!
//! 1. **Redist manifests** (`--from`): archive sha256 <-> version, mapped via the
//!    reviewed profile table. This is the manifest layer.
//! 2. **Unpacked corpus** (`--corpus`, optional): real `.so` files unpacked from
//!    the fetched archives yield build-id and file-hash signals for the
//!    individual libraries. This is the binary layer.
//!
//! Both are merged per shard (keyed by the manifest they came from) so a shard
//! contains everything known for that release. Unpacking `.tar.xz` uses the
//! system `tar`; xtask is dev/CI-only tooling and never ships, so shelling out
//! keeps the released binary free of an lzma dependency.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};
use cudabom_identify::{
    component_symbols, derive, fingerprint_binary, symbol_fingerprint, to_db, BinaryFingerprint,
    BinaryProvenance, FingerprintDb, Provenance, RedistManifest,
};

use crate::flag;
use crate::verbosity::{detail, status};

/// At or below this many ELF members, a `.a` is a small static runtime and its
/// members are hash-fingerprinted; above it, the archive is a build-artifact
/// aggregate fingerprinted by component symbol markers instead. The eval
/// ground-truth harness reads the same cap to mirror the fingerprinter.
pub(crate) const MAX_STATIC_MEMBERS: usize = 8;

/// Compute the derivation provenance for a shard from its exact inputs: the
/// redist manifest bytes, the corpus archives present on disk for this
/// manifest, and this tool's version. The build is a pure function of these, so
/// two builds with identical provenance produce byte-identical shards.
fn compute_provenance(
    manifest_bytes: &[u8],
    manifest: &RedistManifest,
    corpus_dir: Option<&str>,
) -> Provenance {
    use cudabom_identify::resolve_component;

    let mut corpus_sha256: Vec<String> = Vec::new();
    if let Some(corpus_dir) = corpus_dir {
        let corpus_dir = Path::new(corpus_dir);
        for (key, component) in &manifest.components {
            let Some(canonical) = resolve_component(key) else {
                continue;
            };
            for (platform, archive) in &component.archives {
                let file_name = archive.relative_path.rsplit('/').next().unwrap_or_default();
                let archive_path = crate::corpus::corpus_archive_path(
                    corpus_dir,
                    &canonical,
                    &component.version,
                    platform,
                    file_name,
                );
                // The archive's sha256 is NVIDIA's own, from the manifest; we
                // record it only when the archive is actually present, since
                // only then does it contribute to the binary layer.
                if archive_path.exists() {
                    corpus_sha256.push(archive.sha256.clone());
                }
            }
        }
    }
    corpus_sha256.sort();
    corpus_sha256.dedup();

    Provenance {
        manifest_sha256: Some(cudabom_fetch::hex_sha256(manifest_bytes)),
        corpus_sha256,
        tool_version: Some(env!("CARGO_PKG_VERSION").to_string()),
    }
}

/// True if an already-derived shard at `out_path` records exactly the same
/// provenance we would derive now. When so, re-deriving would reproduce
/// identical bytes, so the build can skip the expensive unpack/parse work.
fn shard_is_up_to_date(out_path: &Path, provenance: &Provenance) -> bool {
    let Ok(bytes) = std::fs::read(out_path) else {
        return false;
    };
    let Ok(existing) = FingerprintDb::from_json(&bytes) else {
        return false;
    };
    existing.provenance.as_ref() == Some(provenance)
}

/// `fingerprints build [--from <dir>] [--out <dir>] [--corpus <dir>] [--jobs N]`
pub(crate) fn build(args: &[String]) -> Result<()> {
    let from = flag(args, "--from").unwrap_or_else(|| "fixtures/redist".to_string());
    let out =
        flag(args, "--out").unwrap_or_else(|| cudabom_core::paths::CUDA_SHARD_DIR.to_string());
    let corpus = flag(args, "--corpus");
    let keep_downloads = crate::has_flag(args, "--keep-downloads");
    let jobs = resolve_jobs(flag(args, "--jobs").as_deref());
    let from_dir = PathBuf::from(&from);
    let out_dir = PathBuf::from(&out);

    let manifests = collect_manifests(&from_dir)
        .with_context(|| format!("reading redist manifests from {from}"))?;
    if manifests.is_empty() {
        bail!("no redistrib_*.json manifests found in {from}");
    }
    std::fs::create_dir_all(&out_dir)
        .with_context(|| format!("creating output directory {out}"))?;

    let force = crate::has_flag(args, "--force");
    let mut total_underived: Vec<String> = Vec::new();
    // Underived keys whose archive actually ships a shared library (so we are
    // silently missing a real library): key -> the SONAME stems observed.
    let mut unmapped_with_libs: std::collections::BTreeMap<String, Vec<String>> =
        std::collections::BTreeMap::new();
    let mut skipped = 0usize;
    let total_shards = manifests.len();
    for (shard_index, manifest_path) in manifests.iter().enumerate() {
        let position = shard_index + 1;
        build_one_shard(
            manifest_path,
            &from_dir,
            &out_dir,
            corpus.as_deref(),
            jobs,
            force,
            position,
            total_shards,
            &mut skipped,
            &mut total_underived,
            &mut unmapped_with_libs,
        )?;
    }

    if skipped > 0 {
        status!("xtask: {skipped} shard(s) already up to date (use --force to rebuild)");
    }

    total_underived.sort();
    total_underived.dedup();
    report_underived(&total_underived, &unmapped_with_libs);

    // Reclaim the downloaded corpus by default so peak local (and CI) disk stays
    // bounded to one batch: the archives are large, gitignored, and cheaply
    // re-fetched. `--keep-downloads` opts out to skip re-fetching on quick
    // iterative re-runs.
    if let Some(corpus_dir) = &corpus {
        let corpus_path = Path::new(corpus_dir);
        if keep_downloads {
            status!(
                "xtask: keeping downloaded corpus at {} (--keep-downloads)",
                corpus_path.display()
            );
        } else if corpus_path.exists() {
            std::fs::remove_dir_all(corpus_path)
                .with_context(|| format!("removing corpus {}", corpus_path.display()))?;
            detail!(
                "xtask: removed downloaded corpus at {} (pass --keep-downloads to retain)",
                corpus_path.display()
            );
        }
    }

    Ok(())
}

/// `fingerprints backfill [--shards fingerprints] [--locks fingerprints]
/// [--limit N] [--jobs N] [--corpus corpus] [--platform <p[,p...]>]
/// [--keep-downloads]`
///
/// Enrich *already-committed* shards that still lack the binary layer. The
/// nightly `fingerprint-refresh` only ever processes **newly discovered**
/// releases; the shards committed before binary-layer derivation existed are
/// manifest-only (archive hashes, no inner-`.so` hashes or build-ids) and would
/// never improve; and a blanket `fingerprints build --force` without their
/// corpus on disk would *regress* them back to manifest-only.
///
/// This task closes that gap safely: it finds a bounded batch of manifest-only
/// shards, fetches **only those releases'** archives, re-derives **only those
/// shards** (so nothing else can regress), and reclaims the corpus. Run nightly,
/// coverage back-fills a few releases at a time until the whole DB is enriched.
pub(crate) fn backfill(args: &[String]) -> Result<()> {
    let shards_dir =
        flag(args, "--shards").unwrap_or_else(|| cudabom_core::paths::FINGERPRINTS_DIR.to_string());
    let locks_dir =
        flag(args, "--locks").unwrap_or_else(|| cudabom_core::paths::FINGERPRINTS_DIR.to_string());
    let corpus = flag(args, "--corpus").unwrap_or_else(|| "corpus".to_string());
    let keep_downloads = crate::has_flag(args, "--keep-downloads");
    let jobs = resolve_jobs(flag(args, "--jobs").as_deref());
    let limit = flag(args, "--limit")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(2);
    // Optional platform scope passed straight through to `corpus fetch`. The
    // binary layer is platform-specific (build-ids differ per architecture), so
    // a shard is only ever "enriched for the platforms fetched". A full lock
    // spans 4 Linux architectures × ~14 components; scoping to the platform that
    // matters (e.g. `--platform linux-x86_64`, the dominant real-world target
    // and what the PyPI wheels ship) cuts a backfill run's download volume ~4×
    // without changing correctness for that platform. Omitted = every platform.
    let platforms = flag(args, "--platform");

    // 1. Find committed shards that still lack the binary layer. A shard is
    //    "manifest-only" when it records no corpus provenance AND no component
    //    carries a build-id: exactly the state a pre-binary-layer build left.
    let candidates = manifest_only_shards(Path::new(&shards_dir));
    if candidates.is_empty() {
        status!(
            "xtask: fingerprints backfill: all committed shards already carry the binary layer"
        );
        return Ok(());
    }
    status!(
        "xtask: fingerprints backfill: {} manifest-only shard(s); enriching up to {limit} this run",
        candidates.len()
    );

    // 2. Enrich up to `limit` shards. Candidates are oldest-first; those
    //    without a corpus lock (releases predating the lock files) are skipped
    //    and we move to the next, so a run always makes `limit` progress when
    //    enough lockable shards remain rather than stalling on an old one.
    let mut enriched = 0usize;
    for shard in &candidates {
        if enriched >= limit {
            break;
        }
        // 3. Each shard's archives come from its `corpus.<label>.lock.json`.
        let lock = Path::new(&locks_dir).join(format!("corpus.{}.lock.json", shard.label));
        if !lock.exists() {
            detail!(
                "xtask: [skip] {}: no corpus lock at {} (release predates lock files)",
                shard.label,
                lock.display()
            );
            continue;
        }

        // 4. Fetch only this release's archives, then re-derive only this shard
        //    (its own fixtures dir + output dir), with the corpus present so the
        //    binary layer is added. For cuda-root shards we stage a temp
        //    fixtures dir holding ONLY this release's manifest, so the recursive
        //    builder cannot rebuild (and regress) the other 50+ shards that have
        //    no corpus on disk this run. `--force` is then safe: scoped to one.
        status!("xtask: backfill {} <- {}", shard.label, lock.display());
        let mut fetch_args = vec![
            "--lock".to_string(),
            lock.to_string_lossy().into_owned(),
            "--out".to_string(),
            corpus.clone(),
        ];
        if let Some(platforms) = &platforms {
            fetch_args.push("--platform".to_string());
            fetch_args.push(platforms.clone());
        }
        crate::corpus::fetch(&fetch_args)
            .with_context(|| format!("fetching corpus for {}", shard.label))?;

        let staged = ScratchDir::new()?;
        let from_arg = stage_single_manifest(shard, &staged)?;

        build(&[
            "--from".to_string(),
            from_arg,
            "--out".to_string(),
            shard.out_dir.clone(),
            "--corpus".to_string(),
            corpus.clone(),
            "--force".to_string(),
            "--keep-downloads".to_string(),
            "--jobs".to_string(),
            jobs.to_string(),
        ])
        .with_context(|| format!("re-deriving shard for {}", shard.label))?;

        // 5. Reclaim between shards so peak disk stays at one release.
        if !keep_downloads {
            let _ = std::fs::remove_dir_all(&corpus);
        }
        enriched += 1;
    }

    status!("xtask: fingerprints backfill: enriched {enriched} shard(s)");
    Ok(())
}

/// A committed shard that still needs the binary layer.
struct ShardRef {
    /// Release label (`12.4.1`, `9.27.0`, ...): keys the corpus lock.
    label: String,
    /// Source redist manifest file name (`redistrib_12.4.1.json`).
    manifest_file: String,
    /// Fixtures directory the manifest lives in (`fixtures/redist` or
    /// `fixtures/redist/<family>`).
    fixtures_from: String,
    /// `--out` for re-deriving just this shard (its own product shard dir).
    out_dir: String,
}

/// Stage only this shard's source manifest into a scratch dir and return it as
/// the `--from` for a scoped re-derive. For cuda-root shards this is essential:
/// pointing `--from` at the real `fixtures/redist` would make the recursive
/// builder rebuild (and, lacking their corpus, regress) every other shard.
fn stage_single_manifest(shard: &ShardRef, scratch: &ScratchDir) -> Result<String> {
    let src = Path::new(&shard.fixtures_from).join(&shard.manifest_file);
    let dst = scratch.path().join(&shard.manifest_file);
    std::fs::copy(&src, &dst)
        .with_context(|| format!("staging {} -> {}", src.display(), dst.display()))?;
    Ok(scratch.path().to_string_lossy().into_owned())
}

/// Find committed shards lacking the binary layer, oldest label first.
///
/// Scans `<shards_dir>` recursively for `redistrib_*.json` and keeps those that
/// are manifest-only: no `provenance.corpus_sha256` and no component build-ids.
/// Each result carries the per-shard `--from`/`--out` so re-derivation touches
/// only that one shard (never a blanket rebuild that could regress others).
fn manifest_only_shards(shards_dir: &Path) -> Vec<ShardRef> {
    let mut shard_files = Vec::new();
    collect_manifests_recursive(shards_dir, &mut shard_files).ok();
    let mut out = Vec::new();
    for path in shard_files {
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
            continue;
        };
        // Only derived shards (schema_version/provenance present) qualify; raw
        // input manifests under fixtures are skipped by the shards_dir scope.
        let has_corpus_prov = value
            .get("provenance")
            .and_then(|p| p.get("corpus_sha256"))
            .and_then(|c| c.as_array())
            .is_some_and(|a| !a.is_empty());
        let has_build_id = value
            .get("components")
            .and_then(|c| c.as_array())
            .is_some_and(|comps| {
                comps.iter().any(|c| {
                    c.get("build_ids")
                        .and_then(|b| b.as_object())
                        .is_some_and(|o| !o.is_empty())
                })
            });
        if has_corpus_prov || has_build_id {
            continue; // already enriched
        }
        let label = value
            .get("release")
            .and_then(|r| r.get("label"))
            .and_then(|l| l.as_str())
            .map(str::to_string);
        let Some(label) = label else { continue };

        // Re-derivation scope: the shard's own directory maps back to the
        // matching fixtures subdirectory. `fingerprints/cuda/*` derives from
        // `fixtures/redist/*` (root); `fingerprints/<family>/*` from
        // `fixtures/redist/<family>/*`.
        let parent = path.parent().unwrap_or(Path::new("."));
        let product = parent
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("cuda");
        let (fixtures_from, out_dir) = if product == "cuda" {
            (
                "fixtures/redist".to_string(),
                cudabom_core::paths::CUDA_SHARD_DIR.to_string(),
            )
        } else {
            (
                format!("fixtures/redist/{product}"),
                format!("fingerprints/{product}"),
            )
        };
        let manifest_file = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or_default()
            .to_string();
        out.push(ShardRef {
            label,
            manifest_file,
            fixtures_from,
            out_dir,
        });
    }
    // Oldest-first by version-ish label for deterministic nightly progress.
    out.sort_by_key(|s| version_sort_key(&s.label));
    out
}

/// Parse a dotted release label into comparable numeric components for sorting
/// (`12.4.1` -> `[12, 4, 1]`); non-numeric parts sort as 0.
fn version_sort_key(label: &str) -> Vec<u64> {
    label
        .split(['.', '-'])
        .map(|p| {
            p.chars()
                .take_while(char::is_ascii_digit)
                .collect::<String>()
        })
        .map(|s| s.parse::<u64>().unwrap_or(0))
        .collect()
}

/// Build one fingerprint shard from a single redist manifest: skip when
/// provenance shows it is up to date, else derive the manifest and binary
/// layers, mirror the output path under `out_dir`, and guard against unmapped
/// libraries. Grouping it this way keeps the per-manifest flow (provenance skip,
/// manifest + binary layers, output path mirroring, unmapped-library guard) as
/// one unit. Mutates the caller's running tallies (`skipped`, `total_underived`,
/// `unmapped_with_libs`) rather than returning them, matching the
/// accumulate-across-shards loop.
#[allow(clippy::too_many_arguments)]
fn build_one_shard(
    manifest_path: &Path,
    from_dir: &Path,
    out_dir: &Path,
    corpus: Option<&str>,
    jobs: usize,
    force: bool,
    position: usize,
    total_shards: usize,
    skipped: &mut usize,
    total_underived: &mut Vec<String>,
    unmapped_with_libs: &mut std::collections::BTreeMap<String, Vec<String>>,
) -> Result<()> {
    let bytes = std::fs::read(manifest_path)
        .with_context(|| format!("reading {}", manifest_path.display()))?;
    let mut manifest = RedistManifest::from_json(&bytes)
        .map_err(|e| anyhow::anyhow!("{}: {e}", manifest_path.display()))?;

    let file_name = manifest_path
        .file_name()
        .context("manifest has no file name")?;
    // Mirror the manifest's subdirectory (relative to the fixtures root) under
    // the output directory, so per-product fixtures (`fixtures/redist/cudnn/`)
    // derive to per-product shard dirs (`<out>/cudnn/`). Manifests directly in
    // the root (the cuda tree) land directly in `<out>`.
    let relative_parent = manifest_path
        .parent()
        .and_then(|p| p.strip_prefix(from_dir).ok())
        .map(Path::to_path_buf)
        .unwrap_or_default();
    let shard_out_dir = out_dir.join(&relative_parent);
    std::fs::create_dir_all(&shard_out_dir)
        .with_context(|| format!("creating {}", shard_out_dir.display()))?;
    let out_path = shard_out_dir.join(file_name);

    backfill_release_label(&mut manifest, file_name);

    // Compute this build's provenance from the exact inputs: the manifest
    // bytes, the corpus archives that exist on disk for this manifest, and the
    // tool version. The build is a pure function of these, so if an existing
    // shard already records the same provenance, re-deriving would reproduce
    // identical bytes: skip it. This is what keeps the nightly job cheap.
    let provenance = compute_provenance(&bytes, &manifest, corpus);
    if !force && shard_is_up_to_date(&out_path, &provenance) {
        *skipped += 1;
        status!(
            "xtask: [{position}/{total_shards}] {} (up to date, skipped)",
            manifest_path.display(),
        );
        return Ok(());
    }

    status!(
        "xtask: [{position}/{total_shards}] deriving {}",
        manifest_path.display()
    );

    // Manifest layer: archive hash <-> version.
    let derived = derive(&manifest);
    let mut shard = derived.db;

    // Binary layer (optional): build-ids + file hashes from unpacked .so.
    let mut binary_count = 0usize;
    if let Some(corpus_dir) = corpus {
        let fps = binary_fingerprints_for_manifest(&manifest, Path::new(corpus_dir), jobs)?;
        binary_count = fps.len();
        if !fps.is_empty() {
            merge_into(&mut shard, &to_db(&fps));
        }
    }

    // Stamp the shard with the provenance we computed, so the next build can
    // detect it is up to date.
    shard.provenance = Some(provenance);

    let mut json = serde_json::to_string_pretty(&shard).context("serializing fingerprint shard")?;
    json.push('\n');
    std::fs::write(&out_path, json).with_context(|| format!("writing {}", out_path.display()))?;

    status!(
        "xtask: [{position}/{total_shards}] wrote {} ({} component(s), {} binary signal(s), {} underived)",
        out_path.display(),
        shard.components.len(),
        binary_count,
        derived.underived.len(),
    );
    total_underived.extend(derived.underived.clone());

    // Guard against silently missing a *new* shared library NVIDIA adds to the
    // redist (the "will we miss something new?" risk). When a corpus is
    // present, inspect each unmapped key's archive and record any that ship a
    // real `.so`, so the build can escalate to a loud warning below.
    if let Some(corpus_dir) = corpus {
        collect_unmapped_libraries(
            &manifest,
            &derived.underived,
            Path::new(corpus_dir),
            unmapped_with_libs,
        );
    }
    Ok(())
}
/// One unit of parallelizable work: a single fetched archive plus the
/// provenance and stem allowlist needed to attribute the binaries inside it.
struct ArchiveJob {
    archive_path: PathBuf,
    provenance: BinaryProvenance,
    allowed: Vec<&'static str>,
    label: String,
}

fn binary_fingerprints_for_manifest(
    manifest: &RedistManifest,
    corpus_dir: &Path,
    jobs: usize,
) -> Result<Vec<BinaryFingerprint>> {
    use cudabom_identify::{resolve_component, soname_stems_for};

    // 1. Enumerate the archive jobs. This is cheap (path existence checks only);
    //    the expensive unpack/hash work is deferred to the worker pool.
    let mut work: Vec<ArchiveJob> = Vec::new();
    for (key, component) in &manifest.components {
        let Some(canonical) = resolve_component(key) else {
            continue;
        };
        let allowed = soname_stems_for(&canonical);
        for (platform, archive) in &component.archives {
            let file_name = archive.relative_path.rsplit('/').next().unwrap_or_default();
            let archive_path = crate::corpus::corpus_archive_path(
                corpus_dir,
                &canonical,
                &component.version,
                platform,
                file_name,
            );
            if !archive_path.exists() {
                continue; // not fetched for this platform; skip silently
            }
            work.push(ArchiveJob {
                archive_path,
                provenance: BinaryProvenance {
                    component: canonical.clone(),
                    version: component.version.clone(),
                    release_label: manifest.release_label.clone(),
                },
                allowed: allowed.to_vec(),
                label: format!("{canonical} {} ({platform})", component.version),
            });
        }
    }

    if work.is_empty() {
        return Ok(Vec::new());
    }

    // 2. Process archives across a bounded pool. Bounded (not one-thread-per-
    //    archive) because each worker holds a large `.so` in memory while
    //    hashing it; capping the worker count caps peak memory so a big library
    //    set cannot OOM the machine or a CI runner. Each job extracts into its
    //    own temp dir that is removed as soon as the job finishes (see
    //    `fingerprint_archive`), so on-disk usage is also bounded to roughly
    //    `jobs` extracted archives at a time.
    let jobs = jobs.max(1).min(work.len());
    let queue = std::sync::Mutex::new(work.into_iter());
    let results = std::sync::Mutex::new(Vec::<BinaryFingerprint>::new());
    let errors = std::sync::Mutex::new(Vec::<String>::new());

    std::thread::scope(|scope| {
        for _ in 0..jobs {
            scope.spawn(|| loop {
                let job = {
                    let mut q = queue.lock().unwrap();
                    q.next()
                };
                let Some(job) = job else { break };
                detail!("xtask:   unpacking {}", job.label);
                match fingerprint_archive(&job) {
                    Ok(mut fps) => results.lock().unwrap().append(&mut fps),
                    Err(e) => errors
                        .lock()
                        .unwrap()
                        .push(format!("{}: {e:#}", job.archive_path.display())),
                }
            });
        }
    });

    let errors = errors.into_inner().unwrap();
    if let Some(first) = errors.first() {
        bail!(
            "{} archive(s) failed to derive; first: {first}",
            errors.len()
        );
    }

    // Deterministic order regardless of which worker finished first.
    let mut out = results.into_inner().unwrap();
    out.sort_by(|a, b| {
        (
            a.component.as_str(),
            a.version.as_str(),
            a.file_sha256.as_str(),
        )
            .cmp(&(
                b.component.as_str(),
                b.version.as_str(),
                b.file_sha256.as_str(),
            ))
    });
    Ok(out)
}

/// Extract one archive into a scratch directory, fingerprint every reviewed
/// `.so` inside it, and remove the scratch directory before returning.
///
/// Only `.so` files whose `DT_SONAME` stem is on the component's reviewed
/// allowlist (`job.allowed`) are attributed. NVIDIA archives bundle extra
/// libraries (e.g. a `libcuda.so` driver stub, `libOpenCL.so`) that would
/// otherwise be wrongly credited to the component whose archive carried them;
/// this keeps attribution a documented fact rather than "whatever `.so` was in
/// the tarball".
///
/// Files are processed one at a time so a worker holds at most a single `.so`
/// in memory. The scratch directory is cleaned up via [`ScratchDir`]'s `Drop`,
/// so it is removed even if fingerprinting returns early with an error; this is
/// what prevents the temp-dir accumulation that an earlier version leaked.
fn fingerprint_archive(job: &ArchiveJob) -> Result<Vec<BinaryFingerprint>> {
    let scratch = ScratchDir::new()?;
    extract_archive(&job.archive_path, scratch.path())?;

    let mut so_paths = Vec::new();
    collect_shared_object_paths(scratch.path(), &mut so_paths)?;

    let mut out = Vec::new();
    for so_path in so_paths {
        // Read one library at a time to keep peak memory bounded.
        let bytes =
            std::fs::read(&so_path).with_context(|| format!("reading {}", so_path.display()))?;
        let Ok(fp) = fingerprint_binary(&bytes, &job.provenance) else {
            continue; // not a parseable ELF; skip
        };
        // Attribute only libraries this component is reviewed to own.
        if let Some(stem) = &fp.soname_stem {
            if job.allowed.contains(&stem.as_str()) {
                out.push(fp);
            }
        }
    }

    // Windows DLLs: unlike ELF, a Windows CUDA DLL does not always stamp its
    // full micro version in the version resource (e.g. `cublas64_11.dll` carries
    // only `11.11.3`, not the archive's `11.11.3.6`). Fingerprinting the DLL by
    // its sha256 lets the hash path recover the exact archive version. Attribute
    // only DLLs whose name maps to a stem this component owns, so a bundled
    // unrelated DLL is never miscredited.
    let mut dll_paths = Vec::new();
    collect_dll_paths(scratch.path(), &mut dll_paths)?;
    for dll_path in dll_paths {
        if !dll_name_belongs_to(&dll_path, &job.allowed) {
            continue;
        }
        let bytes =
            std::fs::read(&dll_path).with_context(|| format!("reading {}", dll_path.display()))?;
        out.push(fingerprint_dll(&bytes, &job.provenance, &dll_path));
    }

    // Static libraries (`.a`): a statically linked application compiles these
    // members in, so there is no `.so` and no SONAME to key on. Fingerprint the
    // member objects by hash and attribute them to this component via the
    // archive name, so static CUDA is identified the same way dynamic CUDA is.
    let mut a_paths = Vec::new();
    collect_static_lib_paths(scratch.path(), &mut a_paths)?;
    for a_path in a_paths {
        if !static_lib_belongs_to(&a_path, &job.provenance.component) {
            continue; // a `.a` this component is not reviewed to own
        }
        let stem = a_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("lib.a")
            .to_string();
        let bytes =
            std::fs::read(&a_path).with_context(|| format!("reading {}", a_path.display()))?;
        out.extend(fingerprint_static_members(&bytes, &job.provenance, &stem));
    }

    Ok(out)
}

/// Recursively collect the paths of every `*.a` static library under `dir`.
fn collect_static_lib_paths(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            collect_static_lib_paths(&path, out)?;
        } else if path.extension().and_then(|e| e.to_str()) == Some("a") {
            out.push(path);
        }
    }
    Ok(())
}

/// Does a `.a` file belong to `component`? NVIDIA names static libraries
/// `lib<component>_static.a` (e.g. `libcudart_static.a`) or `lib<component>.a`.
/// Matching on the archive name keeps attribution first-party: the member has
/// no SONAME, so the archive it was shipped in is the source of truth.
fn static_lib_belongs_to(path: &Path, component: &str) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    let lower = name.to_ascii_lowercase();
    lower.starts_with(&format!("lib{component}"))
}

/// Fingerprint the member objects of a `.a` static library, attributing each to
/// the archive's component/version.
///
/// Small, self-contained static runtimes (e.g. `libcudart_static.a`, a single
/// `cudart_static.o`) are fingerprinted by member hash: an exact signal.
///
/// Large aggregates of per-translation-unit objects (hundreds/thousands of
/// `.o`s, e.g. `libcublas_static.a`) are *not* hash-fingerprinted: those member
/// hashes do not survive static *linking* into an application (the linker
/// relocates and may garbage-collect them), so they add large DB bloat without
/// a matchable signal. Instead, such an archive contributes a **symbol-marker**
/// fingerprint: the component's namespaced public API symbols (e.g. `nccl*`),
/// which *do* survive linking and name the component at `Likely` confidence.
/// This is the honest signal for the large static archives that a hash or
/// SONAME cannot cover.
fn fingerprint_static_members(
    bytes: &[u8],
    provenance: &BinaryProvenance,
    archive_stem: &str,
) -> Vec<BinaryFingerprint> {
    use object::read::archive::ArchiveFile;

    let Ok(archive) = ArchiveFile::parse(bytes) else {
        return Vec::new();
    };

    // Collect ELF members first so we can apply the aggregate-size cap before
    // committing any of them to the DB.
    let elf_members: Vec<&[u8]> = archive
        .members()
        .flatten()
        .filter_map(|m| m.data(bytes).ok())
        .filter(|data| object::read::File::parse(*data).is_ok())
        .collect();

    if elf_members.len() > MAX_STATIC_MEMBERS {
        // Large aggregate: derive the component's namespaced API symbols across
        // all members and record them as a single symbol-marker fingerprint.
        let mut symbols: Vec<String> = elf_members
            .iter()
            .flat_map(|data| component_symbols(data, &provenance.component))
            .collect();
        symbols.sort();
        symbols.dedup();
        return symbol_fingerprint(symbols, provenance)
            .into_iter()
            .collect();
    }

    let mut out = Vec::new();
    for data in elf_members {
        let file_sha256 = cudabom_fetch::hex_sha256(data);
        out.push(BinaryFingerprint {
            component: provenance.component.clone(),
            version: provenance.version.clone(),
            file_sha256,
            // A member object's hash is the signal; a `.o` carries no SONAME,
            // and its build-id (if any) is already covered by the hash.
            build_id: None,
            soname_stem: Some(archive_stem.to_string()),
            release_label: provenance.release_label.clone(),
            symbol_markers: Vec::new(),
        });
    }
    out
}

/// Recursively collect the paths of every `*.so*` file under `dir`.
fn collect_shared_object_paths(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            collect_shared_object_paths(&path, out)?;
        } else if is_shared_object(&path) {
            out.push(path);
        }
    }
    Ok(())
}

/// True if `path`'s file name contains `.so` (e.g. `libcudart.so.11.4`).
fn is_shared_object(path: &Path) -> bool {
    path.file_name()
        .and_then(|s| s.to_str())
        .is_some_and(|n| n.contains(".so"))
}

/// Extract an archive into `dest`, choosing `unzip` for `.zip` (Windows
/// archives), `extract_deb` for `.deb` (Jetson/L4T and per-distro packages),
/// `extract_rpm` for `.rpm` (per-distro RPM packages via libarchive/`bsdtar`),
/// and the system `tar` otherwise (`.tar.xz`/`.tar.gz`). xtask is dev/CI-only
/// tooling, so shelling out keeps the shipped binary dependency-free.
fn extract_archive(archive_path: &Path, dest: &Path) -> Result<()> {
    let name = archive_path.to_string_lossy();
    if name.ends_with(".deb") {
        return extract_deb(archive_path, dest);
    }
    if name.ends_with(".rpm") {
        return extract_rpm(archive_path, dest);
    }
    let status = if name.ends_with(".zip") {
        Command::new("unzip")
            .arg("-q")
            .arg(archive_path)
            .arg("-d")
            .arg(dest)
            .status()
            .context("running system unzip (is it installed?)")?
    } else {
        Command::new("tar")
            .arg("-xf")
            .arg(archive_path)
            .arg("-C")
            .arg(dest)
            .status()
            .context("running system tar (is it installed?)")?
    };
    if !status.success() {
        bail!("failed to extract {}", archive_path.display());
    }
    Ok(())
}

/// Extract a `.rpm` into `dest` using `bsdtar` (libarchive), which reads the
/// RPM header + cpio payload natively. This avoids `rpm2cpio`, which is not
/// present on macOS, mirroring the portable `.deb` handling.
fn extract_rpm(archive_path: &Path, dest: &Path) -> Result<()> {
    let status = Command::new("bsdtar")
        .arg("-xf")
        .arg(archive_path)
        .arg("-C")
        .arg(dest)
        .status()
        .context("running bsdtar to extract a .rpm (is libarchive/bsdtar installed?)")?;
    if !status.success() {
        bail!("failed to extract {}", archive_path.display());
    }
    Ok(())
}

/// Unpack a `.deb`'s inner `data.tar` member to a temp file and return it with
/// its owning scratch dir (removed on drop).
///
/// A `.deb` is an `ar` archive whose payload member is `data.tar.{xz,zst,gz}`;
/// the libraries live inside that inner tarball (for Jetson/L4T CUDA packages,
/// under `usr/local/cuda-*/targets/aarch64-linux/lib/`). The outer `ar` layer
/// is parsed with the `object` crate rather than the system `ar`: NVIDIA signs
/// these packages with a trailing `_gpgbuilder` member, and the BSD `ar` on
/// macOS misreads the GNU-style name table of such archives (it appends `/` to
/// member names and extracts nothing). `object` reads the member names
/// correctly on every platform. The caller runs the system `tar` on the
/// returned path (which auto-detects xz/zstd/gzip); `control.tar.*`,
/// `debian-binary`, and the GPG signature are metadata we do not scan.
fn stage_deb_data_member(archive_path: &Path) -> Result<(ScratchDir, PathBuf)> {
    use object::read::archive::ArchiveFile;

    let bytes = std::fs::read(archive_path)
        .with_context(|| format!("reading {}", archive_path.display()))?;
    let archive = ArchiveFile::parse(&bytes[..]).map_err(|e| {
        anyhow::anyhow!(
            "parsing {} as a .deb (ar) archive: {e}",
            archive_path.display()
        )
    })?;

    for member in archive.members() {
        let member = member.map_err(|e| anyhow::anyhow!("reading .deb member: {e}"))?;
        let name = std::str::from_utf8(member.name()).unwrap_or_default();
        if name.starts_with("data.tar") {
            let member_bytes = member.data(&bytes[..]).map_err(|e| {
                anyhow::anyhow!("reading data member of {}: {e}", archive_path.display())
            })?;
            let scratch = ScratchDir::new()?;
            let data_path = scratch.path().join(name);
            std::fs::write(&data_path, member_bytes)
                .with_context(|| format!("writing {}", data_path.display()))?;
            return Ok((scratch, data_path));
        }
    }
    bail!("no data.tar member in {}", archive_path.display())
}

/// Extract a Debian package (`.deb`) into `dest` by unpacking its inner
/// `data.tar` member (see [`stage_deb_data_member`]) with the system `tar`.
fn extract_deb(archive_path: &Path, dest: &Path) -> Result<()> {
    let (_scratch, data_path) = stage_deb_data_member(archive_path)?;
    let status = Command::new("tar")
        .arg("-xf")
        .arg(&data_path)
        .arg("-C")
        .arg(dest)
        .status()
        .context("running system tar (is it installed?)")?;
    if !status.success() {
        bail!(
            "failed to extract data member of {}",
            archive_path.display()
        );
    }
    Ok(())
}

/// Recursively collect the paths of every `*.dll` file under `dir`.
fn collect_dll_paths(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            collect_dll_paths(&path, out)?;
        } else if path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| e.eq_ignore_ascii_case("dll"))
        {
            out.push(path);
        }
    }
    Ok(())
}

/// Does a Windows DLL name map to a stem this component is reviewed to own?
///
/// NVIDIA names Windows CUDA DLLs `NAME64_<major>.dll` (e.g. `cublas64_11.dll`,
/// `cudart64_12.dll`), where `NAME` corresponds to the Linux stem `libNAME.so`.
/// This reduces the DLL base name to `NAME` and checks it against the stems in
/// `allowed` (which are `libNAME.so`), so a bundled unrelated DLL is never
/// miscredited to this component.
fn dll_name_belongs_to(path: &Path, allowed: &[&str]) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    let lower = name.to_ascii_lowercase();
    // Strip the `.dll` extension and any `64_<major>` / `_<major>` ABI suffix.
    let base = lower.strip_suffix(".dll").unwrap_or(&lower);
    let base = base.split("64_").next().unwrap_or(base);
    let base = base.split('_').next().unwrap_or(base);
    allowed.iter().any(|stem| {
        // `libcublas.so` -> `cublas`; also allow the mixed-case `libcublasLt.so`
        // style by lowercasing.
        let stem_lower = stem.to_ascii_lowercase();
        let stem_core = stem_lower
            .strip_prefix("lib")
            .and_then(|s| s.strip_suffix(".so"))
            .unwrap_or(&stem_lower);
        stem_core == base
    })
}

/// Fingerprint a Windows DLL by its sha256, attributing it to the archive's
/// component/version. DLLs carry no GNU build-id or `DT_SONAME`; only the file
/// hash is recorded (the matcher's strongest signal). The stem is left unset so
/// the DLL name does not pollute the component's `.so` SONAME allowlist.
fn fingerprint_dll(bytes: &[u8], provenance: &BinaryProvenance, _path: &Path) -> BinaryFingerprint {
    BinaryFingerprint {
        component: provenance.component.clone(),
        version: provenance.version.clone(),
        file_sha256: cudabom_fetch::hex_sha256(bytes),
        build_id: None,
        soname_stem: None,
        release_label: provenance.release_label.clone(),
        symbol_markers: Vec::new(),
    }
}

/// Merge `src` fingerprint db into `dst`, unioning component signals.
fn merge_into(dst: &mut FingerprintDb, src: &FingerprintDb) {
    let mut by_name: BTreeMap<String, usize> = dst
        .components
        .iter()
        .enumerate()
        .map(|(i, c)| (c.name.clone(), i))
        .collect();

    for incoming in &src.components {
        if let Some(&idx) = by_name.get(&incoming.name) {
            let existing = &mut dst.components[idx];
            if existing.description.is_none() {
                existing.description.clone_from(&incoming.description);
            }
            if existing.license.is_none() {
                existing.license.clone_from(&incoming.license);
            }
            union_version_map(&mut existing.file_hashes, &incoming.file_hashes);
            union_version_map(&mut existing.build_ids, &incoming.build_ids);
            for stem in &incoming.soname_stems {
                if !existing.soname_stems.contains(stem) {
                    existing.soname_stems.push(stem.clone());
                }
            }
            existing.soname_stems.sort();
            for symbol in &incoming.symbol_markers {
                if !existing.symbol_markers.contains(symbol) {
                    existing.symbol_markers.push(symbol.clone());
                }
            }
            existing.symbol_markers.sort();
            for (version, releases) in &incoming.release_versions {
                let set = existing
                    .release_versions
                    .entry(version.clone())
                    .or_default();
                for release in releases {
                    if !set.contains(release) {
                        set.push(release.clone());
                    }
                }
                set.sort();
            }
        } else {
            by_name.insert(incoming.name.clone(), dst.components.len());
            dst.components.push(incoming.clone());
        }
    }
    dst.components.sort_by(|a, b| a.name.cmp(&b.name));
}

/// Union one hash/build-id version map into another, keeping each key's version
/// list sorted and de-duplicated. Mirrors the merge in `cudabom-identify` so the
/// binary layer accumulates versions rather than overwriting them.
fn union_version_map(
    into: &mut BTreeMap<String, Vec<String>>,
    from: &BTreeMap<String, Vec<String>>,
) {
    for (key, versions) in from {
        let set = into.entry(key.clone()).or_default();
        for version in versions {
            if !set.contains(version) {
                set.push(version.clone());
            }
        }
        set.sort();
    }
}

/// List the shared libraries shipped by an unmapped manifest key, if any.
///
/// Given a manifest key with no reviewed `ComponentProfile`, this locates the
/// key's archive(s) under the corpus and lists the distinct SONAME stems
/// (`libfoo.so`) they contain, by reading the archive's table of contents
/// (`tar -t` / `unzip`) rather than extracting. Returns an empty vector when
/// the key ships no `.so` (the common, harmless case: compilers, headers,
/// docs). A non-empty result means a real library is going unattributed.
fn unmapped_shared_libraries(
    manifest: &RedistManifest,
    key: &str,
    corpus_dir: &Path,
) -> Vec<String> {
    let Some(component) = manifest.components.get(key) else {
        return Vec::new();
    };
    let mut stems: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for (platform, archive) in &component.archives {
        let file_name = archive.relative_path.rsplit('/').next().unwrap_or_default();
        // The corpus layout mirrors the fingerprint path: <key>/<version>/
        // <platform>/<file>. Unmapped keys have no canonical resolution, so the
        // directory uses the manifest key verbatim.
        let archive_path = crate::corpus::corpus_archive_path(
            corpus_dir,
            key,
            &component.version,
            platform,
            file_name,
        );
        if !archive_path.exists() {
            continue;
        }
        for name in archive_table_of_contents(&archive_path) {
            // Reduce each entry to its basename, keep only shared-library names,
            // normalized to the `.so` stem (drop the `.<version>` ABI suffix) so
            // repeated versioned entries collapse to one stem.
            let base = name.rsplit('/').next().unwrap_or(&name);
            if let Some(idx) = base.find(".so") {
                let stem = &base[..idx + 3];
                if stem.starts_with("lib") {
                    stems.insert(stem.to_string());
                }
            }
        }
    }
    stems.into_iter().collect()
}

/// Record unmapped keys whose archives ship a shared library into `out`.
///
/// Datacenter tools, compilers, headers, and docs ship no `.so` and are
/// harmlessly skipped; a key that *does* ship one is a real library going
/// unattributed, so it is collected for the loud build-time warning.
fn collect_unmapped_libraries(
    manifest: &RedistManifest,
    underived: &[String],
    corpus_dir: &Path,
    out: &mut std::collections::BTreeMap<String, Vec<String>>,
) {
    for key in underived {
        let stems = unmapped_shared_libraries(manifest, key, corpus_dir);
        if !stems.is_empty() {
            out.entry(key.clone()).or_insert(stems);
        }
    }
}

/// Report underived manifest keys, escalating any that ship a real shared
/// library to a loud warning (the tripwire for new, unattributed CUDA libraries).
fn report_underived(
    total_underived: &[String],
    unmapped_with_libs: &std::collections::BTreeMap<String, Vec<String>>,
) {
    if !total_underived.is_empty() {
        status!("");
        status!(
            "xtask: {} manifest key(s) had no reviewed component profile (extend the profile table in cudabom-identify):",
            total_underived.len()
        );
        for key in total_underived {
            status!("  {key}");
        }
    }

    // Loud guard: an unmapped key that ships a real `.so` is a library we are
    // silently failing to attribute. This is the automatic tripwire for new
    // CUDA libraries: surface it unmissably with the exact stems to add.
    if !unmapped_with_libs.is_empty() {
        status!("");
        status!(
            "xtask: WARNING: {} unmapped manifest key(s) ship a shared library but have NO component profile.",
            unmapped_with_libs.len()
        );
        status!("xtask: these libraries are NOT attributed when scanned directly. Add a ComponentProfile for each:");
        for (key, stems) in unmapped_with_libs {
            status!("  {key}: stems {}", stems.join(", "));
        }
    }
}

/// List an archive's entry names via the system `tar`/`unzip`, without
/// extracting. Returns an empty vector on any error (the guard is best-effort).
fn archive_table_of_contents(path: &Path) -> Vec<String> {
    let name = path.to_string_lossy();
    if name.ends_with(".deb") {
        return deb_table_of_contents(path);
    }
    let output = if name.ends_with(".zip") {
        Command::new("unzip").arg("-Z1").arg(path).output()
    } else if name.ends_with(".rpm") {
        // libarchive reads the RPM header + cpio payload; list without extract.
        Command::new("bsdtar").arg("-tf").arg(path).output()
    } else {
        // .tar.xz / .tar.gz / .tar: tar auto-detects compression.
        Command::new("tar").arg("-tf").arg(path).output()
    };
    let Ok(output) = output else {
        return Vec::new();
    };
    if !output.status.success() {
        return Vec::new();
    }
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(ToString::to_string)
        .collect()
}

/// List a `.deb`'s inner `data.tar` entry names without a full extract, by
/// staging the data member (see [`stage_deb_data_member`]) and running `tar
/// -t`. Returns an empty vector on any error (the guard is best-effort).
fn deb_table_of_contents(path: &Path) -> Vec<String> {
    let Ok((_scratch, data_path)) = stage_deb_data_member(path) else {
        return Vec::new();
    };
    let Ok(output) = Command::new("tar").arg("-tf").arg(&data_path).output() else {
        return Vec::new();
    };
    if !output.status.success() {
        return Vec::new();
    }
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(ToString::to_string)
        .collect()
}

/// Backfill the toolkit release label for an early redist manifest.
///
/// NVIDIA's `redistrib_*.json` only began carrying an explicit `release_label`
/// field in CUDA 12.2; the 11.0-12.1.1 manifests omit it. Without a release
/// label, toolkit-wide advisories (which are keyed to a CUDA release) can never
/// correlate to the libraries those early toolkits shipped: precisely the
/// oldest, often most-vulnerable versions. The release label for these
/// manifests is unambiguously encoded in the filename
/// (`redistrib_11.8.0.json` -> `11.8.0`), which is the directory label NVIDIA
/// publishes the release under, so derive it from there when the manifest
/// itself is silent. This is a first-party fact (the filename is NVIDIA's own),
/// not a guess. Manifests that already carry a label are left untouched.
fn backfill_release_label(manifest: &mut RedistManifest, file_name: &std::ffi::OsStr) {
    if manifest.release_label.is_none() {
        if let Some(label) = release_label_from_manifest_name(file_name) {
            manifest.release_label = Some(label);
        }
    }
}

/// Derive a CUDA toolkit release label from a `redistrib_*.json` filename, e.g.
/// `redistrib_11.8.0.json` -> `11.8.0`. Used to backfill the `release_label`
/// for early manifests (CUDA 11.0-12.1.1) that NVIDIA published without the
/// explicit field. Returns `None` if the name does not match the expected
/// `redistrib_<version>.json` shape.
fn release_label_from_manifest_name(file_name: &std::ffi::OsStr) -> Option<String> {
    let name = file_name.to_str()?;
    let stem = name.strip_prefix("redistrib_")?.strip_suffix(".json")?;
    // Guard against unexpected content: a release label is a dotted numeric
    // version (e.g. 11.8.0). Accept only ASCII digits and dots, non-empty, and
    // containing at least one dot.
    if stem.is_empty()
        || !stem.contains('.')
        || !stem.bytes().all(|b| b.is_ascii_digit() || b == b'.')
    {
        return None;
    }
    Some(stem.to_string())
}

/// Collect `redistrib_*.json` manifest paths from `dir`, sorted.
fn collect_manifests(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    collect_manifests_recursive(dir, &mut out)?;
    out.sort();
    Ok(out)
}

/// Recursively collect `redistrib_*.json` manifests under `dir`, so a parent
/// fixtures directory holding per-product subdirectories
/// (`fixtures/redist/cudnn`, ...) is picked up in one pass. Returns an error
/// only if the top-level directory cannot be read.
fn collect_manifests_recursive(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            let _ = collect_manifests_recursive(&path, out);
            continue;
        }
        let name_ok = path
            .file_name()
            .and_then(|s| s.to_str())
            .is_some_and(|n| n.starts_with("redistrib_"));
        let ext_ok = path
            .extension()
            .and_then(|s| s.to_str())
            .is_some_and(|e| e.eq_ignore_ascii_case("json"));
        if name_ok && ext_ok {
            out.push(path);
        }
    }
    Ok(())
}

/// A scratch directory that removes itself (and its contents) when dropped.
///
/// Derivation extracts each archive into one of these; on drop, whether the
/// worker finished normally or bailed with an error, the directory is removed.
/// This keeps on-disk temp usage bounded to the archives currently being
/// processed, and fixes an earlier leak where extracted trees accumulated in the
/// system temp directory across runs.
struct ScratchDir {
    path: PathBuf,
}

impl ScratchDir {
    fn new() -> Result<Self> {
        let base = std::env::temp_dir();
        // Unique per call: nanos plus the thread id, so parallel workers never
        // collide on a shared name.
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let tid = format!("{:?}", std::thread::current().id());
        let tid: String = tid.chars().filter(char::is_ascii_alphanumeric).collect();
        let path = base.join(format!("cudabom-xtask-{nanos}-{tid}"));
        std::fs::create_dir_all(&path).context("creating temp dir")?;
        Ok(Self { path })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        // Best-effort cleanup; a failure here should not mask the real result.
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// Resolve the worker count from an optional `--jobs` value.
///
/// Defaults to 4 (a conservative level that speeds up derivation without
/// letting many large libraries sit in memory at once), capped at the number of
/// available cores so it never over-subscribes a small machine or CI runner.
/// An explicit `--jobs N` is honored (minimum 1), also capped at core count.
fn resolve_jobs(flag: Option<&str>) -> usize {
    let cores = std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get);
    let requested = flag.and_then(|s| s.parse::<usize>().ok()).unwrap_or(4);
    requested.max(1).min(cores.max(1))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;

    #[test]
    fn dll_name_maps_to_owning_component_stem() {
        use std::path::Path;
        // cublas64_11.dll belongs to the cublas component (stem libcublas.so).
        assert!(dll_name_belongs_to(
            Path::new("/x/cublas64_11.dll"),
            &["libcublas.so", "libcublasLt.so"]
        ));
        // cudart64_12.dll belongs to cudart.
        assert!(dll_name_belongs_to(
            Path::new("cudart64_12.dll"),
            &["libcudart.so"]
        ));
        // A bundled unrelated DLL is never credited to this component.
        assert!(!dll_name_belongs_to(
            Path::new("cublas64_11.dll"),
            &["libcudart.so"]
        ));
        // Non-DLL names are rejected.
        assert!(!dll_name_belongs_to(
            Path::new("libcublas.so.11"),
            &["libcublas.so"]
        ));
    }

    #[test]
    fn archive_toc_lists_entries_and_detects_shared_libraries() {
        // Build a real .tar with a .so entry and a header, then confirm the
        // guard's table-of-contents read finds the shared library. This proves
        // the "new unmapped library" tripwire works on a genuine archive.
        let dir = std::env::temp_dir().join(format!(
            "cudabom-toc-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        std::fs::create_dir_all(dir.join("newlib/lib")).unwrap();
        std::fs::create_dir_all(dir.join("newlib/include")).unwrap();
        std::fs::write(dir.join("newlib/lib/libnewcuda.so.1.2.3"), b"\x7fELF").unwrap();
        std::fs::write(dir.join("newlib/include/newcuda.h"), b"// header").unwrap();
        let archive = dir.join("newlib.tar");
        let ok = Command::new("tar")
            .arg("-cf")
            .arg(&archive)
            .arg("-C")
            .arg(&dir)
            .arg("newlib")
            .status()
            .is_ok_and(|s| s.success());
        if ok {
            let toc = archive_table_of_contents(&archive);
            assert!(
                toc.iter().any(|e| e.contains("libnewcuda.so")),
                "table of contents should list the .so entry: {toc:?}"
            );
            // The stem-extraction logic the guard uses must reduce the versioned
            // entry to the `libnewcuda.so` stem.
            let stems: Vec<String> = toc
                .iter()
                .filter_map(|name| {
                    let base = name.rsplit('/').next().unwrap_or(name);
                    base.find(".so").and_then(|idx| {
                        let stem = &base[..idx + 3];
                        stem.starts_with("lib").then(|| stem.to_string())
                    })
                })
                .collect();
            assert_eq!(stems, vec!["libnewcuda.so".to_string()]);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn release_label_derived_from_early_manifest_name() {
        // The 11.0-12.1.1 manifests omit release_label; derive it from the name.
        assert_eq!(
            release_label_from_manifest_name(OsStr::new("redistrib_11.8.0.json")).as_deref(),
            Some("11.8.0")
        );
        assert_eq!(
            release_label_from_manifest_name(OsStr::new("redistrib_12.1.1.json")).as_deref(),
            Some("12.1.1")
        );
        assert_eq!(
            release_label_from_manifest_name(OsStr::new("redistrib_11.0.3.json")).as_deref(),
            Some("11.0.3")
        );
    }

    #[test]
    fn release_label_rejects_non_version_names() {
        // Guard: anything that is not redistrib_<dotted-numeric>.json is None.
        assert!(release_label_from_manifest_name(OsStr::new("redistrib_.json")).is_none());
        assert!(release_label_from_manifest_name(OsStr::new("redistrib_latest.json")).is_none());
        assert!(release_label_from_manifest_name(OsStr::new("redistrib_12.json")).is_none()); // no dot
        assert!(release_label_from_manifest_name(OsStr::new("something_else.json")).is_none());
        assert!(release_label_from_manifest_name(OsStr::new("redistrib_11.8.0.txt")).is_none());
    }
}
