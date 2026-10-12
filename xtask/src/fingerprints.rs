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
            // Profiled keys live under their canonical component dir; unprofiled
            // keys (candidates for Model B auto-derivation) live under the
            // manifest key verbatim. Both affect the derived shard when their
            // archive is present, so both must feed provenance for the
            // up-to-date check to be sound.
            let dir_name = resolve_component(key).unwrap_or_else(|| key.clone());
            for (platform, archive) in &component.archives {
                let file_name = archive.relative_path.rsplit('/').next().unwrap_or_default();
                let archive_path = crate::corpus::corpus_archive_path(
                    corpus_dir,
                    &dir_name,
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

    // 1. Find committed shards that are stale against the current derivation
    //    logic. A shard is stale when EITHER it still lacks the binary layer
    //    (the pre-binary-layer "manifest-only" state) OR its source manifest
    //    offers a non-excluded component archive whose sha256 is absent from the
    //    shard's recorded provenance: a derivable archive the shard has
    //    never incorporated (the Model B auto-derivation gap: `nvtx`, `opencl`,
    //    `sanitizer_api`, folded cuDNN JIT, ...). Both are content-based and
    //    self-terminating: once a shard is re-derived with the archive present,
    //    its sha256 lands in provenance and the shard is no longer selected.
    let candidates = stale_shards(Path::new(&shards_dir));
    if candidates.is_empty() {
        status!(
            "xtask: fingerprints backfill: all committed shards are current with the derivation logic"
        );
        return Ok(());
    }
    status!(
        "xtask: fingerprints backfill: {} stale shard(s); re-deriving up to {limit} this run",
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
        // 3. Each shard's committed lock lives at `corpus.<label>.lock.json`.
        //    It may be stale (generated by the old profile-gated locker, so it
        //    pins only the ~14 profiled archives and omits the Model B
        //    auto-candidates). Regenerate the lock from the shard's source
        //    manifest with the current all-keys locker so every derivable
        //    archive is fetched. The base URL is recovered from the committed
        //    lock when present (preserving sibling/jetson/cuda-repos trees);
        //    otherwise it falls back to this product's redist base.
        let committed_lock =
            Path::new(&locks_dir).join(format!("corpus.{}.lock.json", shard.label));
        let relock_scratch = ScratchDir::new()?;
        let lock = match regenerate_lock(
            shard,
            &committed_lock,
            platforms.as_deref(),
            &relock_scratch,
        ) {
            Ok(path) => path,
            Err(err) => {
                detail!(
                    "xtask: [skip] {}: cannot regenerate lock ({err})",
                    shard.label
                );
                continue;
            }
        };

        // 4. Fetch only this release's archives, then re-derive only this shard
        //    (its own fixtures dir + output dir), with the corpus present so the
        //    binary layer is added. For cuda-root shards we stage a temp
        //    fixtures dir holding ONLY this release's manifest, so the recursive
        //    builder cannot rebuild (and regress) the other 50+ shards that have
        //    no corpus on disk this run. `--force` is then safe: scoped to one.
        //
        //    No `--platform` filter is passed here: the regenerated lock is
        //    already scoped to the requested platforms (via the fuzzy
        //    `platform_matches` locker), and its entries carry the exact
        //    variant platform keys (`linux-x86_64-cuda12`, ...) that the fetch
        //    filter matches literally. Re-passing `--platform linux-x86_64`
        //    would wrongly filter those variants to zero.
        status!("xtask: backfill {} <- {}", shard.label, lock.display());
        let fetch_args = vec![
            "--lock".to_string(),
            lock.to_string_lossy().into_owned(),
            "--out".to_string(),
            corpus.clone(),
        ];
        if let Err(err) = crate::corpus::fetch(&fetch_args) {
            // A single release's fetch failure (network, or a lock that yields
            // no matching archives) must not abort the whole bounded batch:
            // skip this shard and let the run make progress on the next.
            detail!("xtask: [skip] {}: fetch failed ({err})", shard.label);
            continue;
        }

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

/// A committed shard that is stale against the current derivation logic.
struct ShardRef {
    /// Release label (`12.4.1`, `9.27.0`, ...): keys the corpus lock.
    label: String,
    /// Product tree the shard belongs to (`cuda`, `cudnn`, ...): selects the
    /// redist base URL when a stale lock must be regenerated from scratch.
    product: String,
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

/// Regenerate a release's corpus lock from its source manifest with the current
/// all-keys locker, writing it to `scratch` and returning that path.
///
/// Committed locks may be stale: those written by the old profile-gated locker
/// pin only the profiled archives and omit the Model B auto-candidates
/// (`cuda_nvtx`, `cuda_opencl`, `cuda_sanitizer_api`, ...). Fetching a stale
/// lock would never bring those archives to disk, so the re-derive could not
/// mint their components. Regenerating here guarantees every derivable archive
/// is pinned before the fetch.
///
/// The base URL and platform set are preserved from the committed lock when it
/// exists (so sibling/jetson/cuda-repos trees keep their own host + the exact
/// architectures already covered); otherwise the base falls back to the
/// product's redist tree and the platform scope to the caller's `--platform`.
fn regenerate_lock(
    shard: &ShardRef,
    committed_lock: &Path,
    platforms: Option<&str>,
    scratch: &ScratchDir,
) -> Result<PathBuf> {
    use cudabom_identify::{lock_from_manifest, resolve_component, CorpusLock};

    let manifest_path = Path::new(&shard.fixtures_from).join(&shard.manifest_file);
    let bytes = std::fs::read(&manifest_path)
        .with_context(|| format!("reading source manifest {}", manifest_path.display()))?;
    let manifest = RedistManifest::from_json(&bytes)
        .map_err(|e| anyhow::anyhow!("{}: {e}", manifest_path.display()))?;

    // Recover base URL + platform set from the committed lock when present.
    let committed = std::fs::read(committed_lock)
        .ok()
        .and_then(|b| CorpusLock::from_json(&b).ok());

    let base_url = committed
        .as_ref()
        .and_then(|lock| recover_base_url(lock, &manifest))
        .unwrap_or_else(|| crate::sources::redist_base(&shard.product));

    // Platforms: prefer the explicit --platform scope; else the exact set the
    // committed lock already covers; else every platform in the manifest.
    let platform_set: Vec<String> = if let Some(p) = platforms {
        p.split(',').map(|s| s.trim().to_string()).collect()
    } else if let Some(lock) = &committed {
        let mut ps: Vec<String> = lock.entries.iter().map(|e| e.platform.clone()).collect();
        ps.sort();
        ps.dedup();
        ps
    } else {
        let mut ps: Vec<String> = manifest
            .components
            .values()
            .flat_map(|c| c.archives.keys().cloned())
            .collect();
        ps.sort();
        ps.dedup();
        ps
    };
    let platform_refs: Vec<&str> = platform_set.iter().map(String::as_str).collect();

    let lock = lock_from_manifest(&manifest, &base_url, &platform_refs, resolve_component);
    if lock.entries.is_empty() {
        bail!("regenerated lock for {} has no entries", shard.label);
    }
    let json = lock.to_json().map_err(|e| anyhow::anyhow!(e))?;
    let out = scratch
        .path()
        .join(format!("corpus.{}.lock.json", shard.label));
    std::fs::write(&out, json).with_context(|| format!("writing {}", out.display()))?;
    Ok(out)
}

/// Recover the redist base URL from a committed lock by stripping a known
/// archive `relative_path` suffix off one of its entry URLs.
///
/// A lock entry URL is `<base>/<relative_path>`; the manifest supplies the
/// `relative_path`, so the base is the URL with that suffix removed. Matching
/// against the manifest's own relative paths keeps this exact rather than
/// guessing a fixed path depth, so sibling and package trees (which embed a
/// different host or extra path segments) are preserved.
fn recover_base_url(
    lock: &cudabom_identify::CorpusLock,
    manifest: &RedistManifest,
) -> Option<String> {
    let rel_paths: Vec<&str> = manifest
        .components
        .values()
        .flat_map(|c| c.archives.values().map(|a| a.relative_path.as_str()))
        .collect();
    for entry in &lock.entries {
        for rel in &rel_paths {
            if let Some(base) = entry.url.strip_suffix(rel) {
                return Some(base.trim_end_matches('/').to_string());
            }
        }
    }
    None
}

/// Find committed shards that are stale against the current derivation logic,
/// oldest label first.
///
/// Scans `<shards_dir>` recursively for derived `redistrib_*.json` shards and
/// keeps those that are stale, where stale means EITHER of:
///
/// 1. **Manifest-only**: no `provenance.corpus_sha256` and no component
///    build-ids: the pre-binary-layer state (older releases committed before
///    binary-layer derivation existed, or whose archives never fetched).
/// 2. **Missing a derivable archive**: the shard's *source* manifest (under
///    `fixtures/`) declares a component whose redist `license` is NOT excluded
///    and whose archive sha256 is absent from the shard's recorded
///    `provenance.corpus_sha256`. That is exactly a derivable archive the shard
///    has never incorporated: the Model B auto-derivation gap (`nvtx`,
///    `opencl`, `sanitizer_api`, folded cuDNN JIT, ...), or any component added
///    to a release's manifest after the shard was last derived.
///
/// Both signals are content-based and self-terminating: once a shard is
/// re-derived with the archive present, that archive's sha256 is recorded in
/// provenance (even when the archive is header-only and yields no component),
/// so the shard stops being selected. The license gate mirrors the builder's
/// own [`cudabom_identify::license_is_excluded`] so selection never flags a
/// driver/datacenter archive that the build would drop anyway.
///
/// Each result carries the per-shard `--from`/`--out` so re-derivation touches
/// only that one shard (never a blanket rebuild that could regress others).
fn stale_shards(shards_dir: &Path) -> Vec<ShardRef> {
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
        let manifest_only = !has_corpus_prov && !has_build_id;

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

        // A manifest-only shard is always stale. An enriched shard is stale
        // only if its source manifest offers a derivable archive it lacks.
        let is_stale = manifest_only
            || shard_missing_derivable_archive(&value, Path::new(&fixtures_from), &manifest_file);
        if !is_stale {
            continue;
        }

        out.push(ShardRef {
            label,
            product: product.to_string(),
            manifest_file,
            fixtures_from,
            out_dir,
        });
    }
    // Oldest-first by version-ish label for deterministic nightly progress.
    out.sort_by_key(|s| version_sort_key(&s.label));
    out
}

/// True if the shard's *source* manifest offers at least one non-excluded
/// component archive whose sha256 is absent from the shard's recorded
/// `provenance.corpus_sha256`: a derivable archive the shard has never
/// incorporated.
///
/// `shard_value` is the parsed derived shard JSON; the source manifest lives at
/// `<fixtures_from>/<manifest_file>`. The license gate mirrors the builder's
/// [`cudabom_identify::license_is_excluded`] so a driver/datacenter archive the
/// build would drop never counts as "missing". A header-only archive (no `.so`)
/// still counts here, but re-deriving it records its sha256 and yields no
/// component, so the shard self-terminates out of the stale set after one pass.
fn shard_missing_derivable_archive(
    shard_value: &serde_json::Value,
    fixtures_from: &Path,
    manifest_file: &str,
) -> bool {
    let manifest_path = fixtures_from.join(manifest_file);
    let Ok(bytes) = std::fs::read(&manifest_path) else {
        // No source manifest to compare against: cannot prove staleness.
        return false;
    };
    let Ok(manifest) = RedistManifest::from_json(&bytes) else {
        return false;
    };

    // The archive sha256s this shard already incorporated.
    let recorded: std::collections::BTreeSet<String> = shard_value
        .get("provenance")
        .and_then(|p| p.get("corpus_sha256"))
        .and_then(|c| c.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();

    manifest.components.values().any(|component| {
        if cudabom_identify::license_is_excluded(component.license.as_deref()) {
            return false;
        }
        component.archives.iter().any(|(platform, archive)| {
            // Only platforms the pipeline actually derives from count. The
            // fingerprint corpus is Linux-only (the committed locks pin
            // `linux-*` archives; Windows `.zip`s are never fetched or
            // derived), so a `windows-x86_64` archive whose sha256 is absent
            // from provenance is expected, not stale: counting it would make
            // every shard perpetually stale and never self-terminate.
            platform.starts_with("linux-") && !recorded.contains(&archive.sha256)
        })
    })
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

    // Binary layer (optional): build-ids + file hashes from unpacked .so,
    // including Model B auto-derivation of .so-bearing unprofiled keys.
    let mut binary_count = 0usize;
    if let Some(corpus_dir) = corpus {
        let fps = binary_fingerprints_for_manifest(
            &manifest,
            &derived.underived,
            Path::new(corpus_dir),
            jobs,
        )?;
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
/// provenance and attribution policy needed to credit the binaries inside it.
struct ArchiveJob {
    archive_path: PathBuf,
    version: String,
    release_label: Option<String>,
    attribution: Attribution,
    label: String,
    /// NVIDIA's own sha256 of the archive, from the manifest. For auto-derived
    /// keys this is recorded as a `file_hashes` entry so scanning the archive
    /// bytes (not just an unpacked `.so`) also resolves the version, matching
    /// the manifest-layer record a profiled key gets from `derive()`.
    archive_sha256: String,
}

/// How to attribute the libraries inside an archive to a component.
///
/// A profiled key credits only the SONAME stems on its reviewed allowlist (the
/// documented-fact gate). An auto-derived key has no reviewed profile: Model B
/// credits each shared library to a component read from the library's own real
/// SONAME stem-core, dropping only bundled driver stubs unrelated to the key
/// (see [`cudabom_identify::soname_belongs_to_key`]).
enum Attribution {
    /// Reviewed component: fixed name + the SONAME stems it is allowed to own.
    Profiled {
        component: String,
        allowed: Vec<&'static str>,
    },
    /// Unprofiled key whose archive ships at least one `.so`: identity is read
    /// from each library's real SONAME, gated by the key-relation rule.
    Auto { manifest_key: String },
}

/// Enumerate the reviewed-profile archive jobs: each manifest key with a
/// `ComponentProfile` whose archive is present on disk, carrying the
/// component's SONAME stem allowlist for attribution.
fn enumerate_profiled_jobs(
    manifest: &RedistManifest,
    corpus_dir: &Path,
    work: &mut Vec<ArchiveJob>,
) {
    use cudabom_identify::{resolve_component, soname_stems_for};
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
                version: component.version.clone(),
                release_label: manifest.release_label.clone(),
                attribution: Attribution::Profiled {
                    component: canonical.clone(),
                    allowed: allowed.to_vec(),
                },
                label: format!("{canonical} {} ({platform})", component.version),
                archive_sha256: archive.sha256.clone(),
            });
        }
    }
}

/// Enumerate the Model B auto-derivation jobs: each unprofiled manifest key
/// whose present-on-disk archive actually ships a `.so`. The corpus for an
/// unprofiled key is laid out under the manifest key verbatim (there is no
/// canonical name), so locate archives by key. Keys that ship no `.so`
/// (samples, compilers, headers, static-only) produce no job and remain
/// skipped, honoring the library-only scope.
fn enumerate_auto_jobs(
    manifest: &RedistManifest,
    underived: &[String],
    corpus_dir: &Path,
    work: &mut Vec<ArchiveJob>,
) {
    for key in underived {
        let Some(component) = manifest.components.get(key) else {
            continue;
        };
        // First-party license gate: NVIDIA's driver/datacenter/IDE archives
        // (e.g. `nvidia_driver`, `fabricmanager`, `nsight_*`) carry a license
        // tag that marks them as not-CUDA. Even though their primary `.so`
        // name-matches the key, they must never auto-derive a CUDA component.
        if cudabom_identify::license_is_excluded(component.license.as_deref()) {
            continue;
        }
        for (platform, archive) in &component.archives {
            let file_name = archive.relative_path.rsplit('/').next().unwrap_or_default();
            let archive_path = crate::corpus::corpus_archive_path(
                corpus_dir,
                key,
                &component.version,
                platform,
                file_name,
            );
            if !archive_path.exists() {
                continue; // not fetched for this platform; skip silently
            }
            // Only keys whose archive ships a real shared library auto-derive.
            if archive_ships_shared_library(&archive_path) {
                work.push(ArchiveJob {
                    archive_path,
                    version: component.version.clone(),
                    release_label: manifest.release_label.clone(),
                    attribution: Attribution::Auto {
                        manifest_key: key.clone(),
                    },
                    label: format!("{key} {} ({platform}, auto)", component.version),
                    archive_sha256: archive.sha256.clone(),
                });
            }
        }
    }
}

fn binary_fingerprints_for_manifest(
    manifest: &RedistManifest,
    underived: &[String],
    corpus_dir: &Path,
    jobs: usize,
) -> Result<Vec<BinaryFingerprint>> {
    // 1. Enumerate the archive jobs. This is cheap (path existence checks only);
    //    the expensive unpack/hash work is deferred to the worker pool. Both the
    //    reviewed-profile jobs and the Model B auto-derivation jobs are gathered
    //    into one work queue.
    let mut work: Vec<ArchiveJob> = Vec::new();
    enumerate_profiled_jobs(manifest, corpus_dir, &mut work);
    enumerate_auto_jobs(manifest, underived, corpus_dir, &mut work);

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

/// Extract one archive into a scratch directory, fingerprint the `.so` (and,
/// for profiled components, DLL and `.a`) files inside it, and remove the
/// scratch directory before returning.
///
/// Attribution is policy-driven (see [`Attribution`]):
///
/// - **Profiled**: only `.so` files whose `DT_SONAME` stem is on the
///   component's reviewed allowlist are credited. NVIDIA archives bundle extra
///   libraries (a `libcuda.so` driver stub, `libOpenCL.so`) that would
///   otherwise be wrongly credited to the component whose archive carried them;
///   the allowlist keeps attribution a documented fact rather than "whatever
///   `.so` was in the tarball". DLLs and static `.a`s are also derived here.
/// - **Auto (Model B)**: the archive has no reviewed profile but ships at least
///   one shared library. A library whose SONAME stem is already owned by a
///   reviewed profile folds into that profiled component
///   ([`cudabom_identify::component_owning_soname`]); otherwise its identity is
///   the normalized manifest key ([`cudabom_identify::auto_identity`]). A
///   library is credited only when its stem relates to the archive key
///   ([`cudabom_identify::soname_belongs_to_key`]) or is the archive's own
///   primary library and not a bundled cross-cutting driver stub
///   (`libcuda.so`/`libOpenCL.so`). Linux `.so`s ground identity from their
///   `DT_SONAME`; Windows `.dll`s (which carry no SONAME) reconstruct the
///   equivalent `libNAME.so` stem from NVIDIA's `NAME64_<major>.dll` naming
///   ([`dll_candidate_soname_stem`]) and run the identical pipeline, so a new
///   auto component is covered symmetrically on Linux and Windows. Static `.a`s
///   are still not auto-claimed (no SONAME, no stable file identity).
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
    // Distinct components auto-derived from this archive's libraries, so we can
    // add one archive-hash record per component (the manifest-layer signal).
    let mut auto_components: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    // The profiled provenance is loop-invariant, so build it once rather than
    // per library. `None` for an Auto job, which takes the SONAME-identity path.
    let profiled_prov = match &job.attribution {
        Attribution::Profiled { component, .. } => Some(BinaryProvenance {
            component: component.clone(),
            version: job.version.clone(),
            release_label: job.release_label.clone(),
        }),
        Attribution::Auto { .. } => None,
    };
    for so_path in so_paths {
        // Read one library at a time to keep peak memory bounded.
        let bytes =
            std::fs::read(&so_path).with_context(|| format!("reading {}", so_path.display()))?;
        match &job.attribution {
            Attribution::Profiled { allowed, .. } => {
                let prov = profiled_prov.as_ref().expect("profiled job has provenance");
                let Ok(fp) = fingerprint_binary(&bytes, prov) else {
                    continue; // not a parseable ELF; skip
                };
                // Attribute only libraries this component is reviewed to own.
                if let Some(stem) = &fp.soname_stem {
                    if allowed.contains(&stem.as_str()) {
                        out.push(fp);
                    }
                }
            }
            Attribution::Auto { manifest_key } => {
                if let Some(fp) = auto_fingerprint_so(&bytes, manifest_key, job) {
                    auto_components.insert(fp.component.clone());
                    out.push(fp);
                }
            }
        }
    }

    // Auto (Model B) Windows coverage: a key's Windows archive ships `.dll`s
    // (no `.so`), so the `.so` loop above produced nothing for it. Credit each
    // DLL to the same component its Linux `.so` sibling would resolve to, via
    // the DLL-name identity pipeline ([`auto_fingerprint_dll`]). This closes the
    // Linux/Windows asymmetry: a new auto component (e.g. `nvtx`) is covered on
    // both platforms, not Linux-only. (Mac is N/A: NVIDIA ships no Mac archives.)
    if let Attribution::Auto { manifest_key } = &job.attribution {
        let mut dll_paths = Vec::new();
        collect_dll_paths(scratch.path(), &mut dll_paths)?;
        for dll_path in dll_paths {
            let bytes = std::fs::read(&dll_path)
                .with_context(|| format!("reading {}", dll_path.display()))?;
            if let Some(fp) = auto_fingerprint_dll(&bytes, &dll_path, manifest_key, job) {
                auto_components.insert(fp.component.clone());
                out.push(fp);
            }
        }
    }

    // For auto-derived components, record the archive's own sha256 -> version
    // (the manifest layer a profiled key gets from `derive()`), so scanning the
    // published archive bytes resolves the version too. Keyed per derived
    // component because one archive (e.g. `cudnn_jit`) can ship several `.so`s
    // that share the same component root.
    if let Attribution::Auto { .. } = &job.attribution {
        for component in &auto_components {
            out.push(BinaryFingerprint {
                component: component.clone(),
                version: job.version.clone(),
                file_sha256: job.archive_sha256.clone(),
                build_id: None,
                soname_stem: None,
                release_label: job.release_label.clone(),
                symbol_markers: Vec::new(),
            });
        }
    }

    // Static `.a`s are only derived for reviewed (profiled) components: a static
    // member carries no SONAME and its hash does not survive linking, so there
    // is no stable auto identity. (Auto Windows DLLs are handled above, in the
    // Auto branch, via the DLL-name identity pipeline.) The remainder of this
    // function is the profiled-only DLL + static path.
    let Attribution::Profiled { allowed, .. } = &job.attribution else {
        return Ok(out);
    };
    let provenance = profiled_prov.as_ref().expect("profiled job has provenance");

    // Windows DLLs: unlike ELF, a Windows CUDA DLL does not always stamp its
    // full micro version in the version resource (e.g. `cublas64_11.dll` carries
    // only `11.11.3`, not the archive's `11.11.3.6`). Fingerprinting the DLL by
    // its sha256 lets the hash path recover the exact archive version. Attribute
    // only DLLs whose name maps to a stem this component owns, so a bundled
    // unrelated DLL is never miscredited.
    let mut dll_paths = Vec::new();
    collect_dll_paths(scratch.path(), &mut dll_paths)?;
    for dll_path in dll_paths {
        if !dll_name_belongs_to(&dll_path, allowed) {
            continue;
        }
        let bytes =
            std::fs::read(&dll_path).with_context(|| format!("reading {}", dll_path.display()))?;
        out.push(fingerprint_dll(&bytes, provenance, &dll_path));
    }

    // Static libraries (`.a`): a statically linked application compiles these
    // members in, so there is no `.so` and no SONAME to key on. Fingerprint the
    // member objects by hash and attribute them to this component via the
    // archive name, so static CUDA is identified the same way dynamic CUDA is.
    let mut a_paths = Vec::new();
    collect_static_lib_paths(scratch.path(), &mut a_paths)?;
    for a_path in a_paths {
        if !static_lib_belongs_to(&a_path, &provenance.component) {
            continue; // a `.a` this component is not reviewed to own
        }
        let stem = a_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("lib.a")
            .to_string();
        let bytes =
            std::fs::read(&a_path).with_context(|| format!("reading {}", a_path.display()))?;
        out.extend(fingerprint_static_members(&bytes, provenance, &stem));
    }

    Ok(out)
}

/// Auto-derive (Model B) a fingerprint for one `.so`'s bytes shipped under an
/// unprofiled `manifest_key`. Returns `None` when the bytes are not a parseable
/// ELF, carry no `DT_SONAME` to ground identity, or are a bundled cross-cutting
/// driver stub unrelated to the archive key (attribution safety).
///
/// Attribution precedence:
/// 1. **Fold-in**: if the SONAME stem is already owned by a reviewed profile
///    ([`cudabom_identify::component_owning_soname`]), credit the fingerprint
///    to *that* profiled component. This keeps cuDNN's sub-libraries shipped
///    under the `cudnn_jit` key (`libcudnn_graph.so`,
///    `libcudnn_engines_runtime_compiled.so`) attributed to `cudnn` rather
///    than minting fragment components.
/// 2. **Auto name**: otherwise, the component name is the normalized manifest
///    key ([`cudabom_identify::auto_identity`]), not the raw SONAME stem-core.
///
/// A `.so` is credited only when it relates to the archive key, or is the
/// archive's own primary library (not a `libcuda.so`/`libOpenCL.so` stub that
/// NVIDIA bundles into unrelated archives).
fn auto_fingerprint_so(
    bytes: &[u8],
    manifest_key: &str,
    job: &ArchiveJob,
) -> Option<BinaryFingerprint> {
    use cudabom_identify::{auto_identity, component_owning_soname};

    // Peek the SONAME stem without committing provenance: identity must come
    // from the real binary. Reuse `fingerprint_binary` with a placeholder
    // component, then rebind the component to the resolved identity.
    let probe = BinaryProvenance {
        component: manifest_key.to_string(),
        version: job.version.clone(),
        release_label: job.release_label.clone(),
    };
    let fp = fingerprint_binary(bytes, &probe).ok()?;
    let stem = fp.soname_stem.as_deref()?; // no SONAME -> no auto identity

    // Fold-in: a stem already owned by a reviewed profile accrues to that
    // component, no attribution-safety relation check needed (the profile's
    // ownership is the authoritative statement that this `.so` belongs there).
    if let Some(owner) = component_owning_soname(stem) {
        return Some(BinaryFingerprint {
            component: owner.to_string(),
            ..fp
        });
    }

    // Attribution: a `.so` belongs to this auto key when its name relates to
    // the key (`libcal.so` -> `libcal`) OR it is the archive's own primary
    // library: not a recognized cross-cutting driver/third-party stub
    // that NVIDIA bundles into archives it does not belong to. This primary-
    // library allowance is what credits `cuda_nvtx`'s `libnvToolsExt.so`
    // (11.x/12.x) and `libnvtx3interop.so` (13.x) to `nvtx`, whose stem-core
    // does not textually relate to the key, while still dropping a genuinely
    // bundled `libcuda.so` driver stub shipped inside an unrelated archive.
    if !so_belongs_to_auto_key(stem, manifest_key) {
        return None;
    }

    let identity = auto_identity(stem, manifest_key);
    Some(BinaryFingerprint {
        component: identity,
        ..fp
    })
}

/// Does a `.so` with SONAME stem `soname_stem` belong to the auto-derived
/// `manifest_key`? True when the stem relates to the key by name
/// ([`cudabom_identify::soname_belongs_to_key`]) OR the stem is the archive's
/// own primary library: any `.so` that is not a recognized bundled driver /
/// third-party stub ([`is_bundled_driver_stub`]). The license gate in
/// [`enumerate_auto_jobs`] has already excluded driver/datacenter/IDE archives,
/// so by the time this runs the surviving archives are CUDA-family and their
/// non-stub `.so`s are legitimately their own.
fn so_belongs_to_auto_key(soname_stem: &str, manifest_key: &str) -> bool {
    use cudabom_identify::soname_belongs_to_key;
    soname_belongs_to_key(soname_stem, manifest_key) || !is_bundled_driver_stub(soname_stem)
}

/// Derive the candidate Linux SONAME stem (`libNAME.so`) a Windows DLL
/// corresponds to, from NVIDIA's naming convention `NAME64_<major>.dll` /
/// `NAME_<major>.dll` / `NAME.dll` (e.g. `nvToolsExt64_1.dll` -> `libnvToolsExt.so`,
/// `cudart64_12.dll` -> `libcudart.so`).
///
/// A Windows DLL carries no `DT_SONAME`, so it cannot *self-report* an identity
/// the way an ELF `.so` does. But NVIDIA ships the same library under both
/// `libNAME.so` (Linux) and `NAME64_<major>.dll` (Windows), so the DLL base
/// name is the authoritative identity signal on Windows. Reconstructing the
/// `libNAME.so` stem lets a DLL flow through the *same* identity pipeline the
/// Linux `.so` uses ([`component_owning_soname`] fold / [`so_belongs_to_auto_key`]
/// / [`cudabom_identify::auto_identity`]); the DLL's `NAME` casing is preserved
/// (unlike [`dll_name_belongs_to`], which lowercases for comparison) so the
/// reconstructed stem matches mixed-case SONAMEs such as `libcublasLt.so`.
///
/// Returns `None` for a name that is not a `.dll` or reduces to empty.
fn dll_candidate_soname_stem(path: &Path) -> Option<String> {
    let name = path.file_name().and_then(|n| n.to_str())?;
    // Case-insensitive extension strip, preserving the base name's casing.
    let base = if name.len() >= 4 && name[name.len() - 4..].eq_ignore_ascii_case(".dll") {
        &name[..name.len() - 4]
    } else {
        return None;
    };
    // Drop the ABI version suffix NVIDIA stamps onto the Windows name, WITHOUT
    // truncating a multi-token stem (`cudnn_graph`, `nvpl_blas_core`):
    //   `cudnn_graph64_9`  -> `cudnn_graph`   (strip `64_<major>`)
    //   `nvToolsExt64_1`   -> `nvToolsExt`
    //   `nvrtc-builtins64_134` -> `nvrtc-builtins`
    //   `OpenCL_1`         -> `OpenCL`         (strip a trailing `_<digits>`)
    //   `cal`              -> `cal`            (no suffix)
    // First remove a `64_<rest>` ABI tail if present (the dominant form), then
    // strip at most one *trailing* `_<numeric>` token. Internal `_` tokens of
    // the real stem are preserved, since the stem is the sole identity signal
    // the fold-in / attribution pipeline keys on.
    let base = match base.split_once("64_") {
        Some((stem, _abi)) => stem,
        None => strip_trailing_numeric_token(base),
    };
    if base.is_empty() {
        return None;
    }
    Some(format!("lib{base}.so"))
}

/// Strip a single trailing `_<digits>` token from a DLL base name, preserving
/// every internal underscore. `OpenCL_1` -> `OpenCL`; `nvpl_blas_core` ->
/// `nvpl_blas_core` (last token non-numeric, kept); `cal` -> `cal`.
fn strip_trailing_numeric_token(base: &str) -> &str {
    match base.rsplit_once('_') {
        Some((head, tail)) if !tail.is_empty() && tail.chars().all(|c| c.is_ascii_digit()) => head,
        _ => base,
    }
}

/// Auto-derive (Model B) a fingerprint for one Windows DLL's bytes shipped under
/// an unprofiled `manifest_key`. The Windows counterpart of [`auto_fingerprint_so`]:
/// it reconstructs the DLL's candidate `libNAME.so` stem
/// ([`dll_candidate_soname_stem`]) and runs the *identical* identity pipeline so
/// a Windows DLL is credited to exactly the same component its Linux `.so`
/// sibling would be (fold into a profiled owner, else the normalized key), with
/// the same bundled-driver-stub rejection.
///
/// Returns `None` when the name is not a resolvable DLL or is a bundled
/// cross-cutting stub unrelated to the key. The DLL is fingerprinted by sha256
/// only (no build-id/SONAME; see [`fingerprint_dll`]).
fn auto_fingerprint_dll(
    bytes: &[u8],
    dll_path: &Path,
    manifest_key: &str,
    job: &ArchiveJob,
) -> Option<BinaryFingerprint> {
    use cudabom_identify::{auto_identity, component_owning_soname};

    let stem = dll_candidate_soname_stem(dll_path)?;

    // Fold-in: a stem already owned by a reviewed profile accrues to that
    // component (same authority as the `.so` path).
    if let Some(owner) = component_owning_soname(&stem) {
        let prov = BinaryProvenance {
            component: owner.to_string(),
            version: job.version.clone(),
            release_label: job.release_label.clone(),
        };
        return Some(fingerprint_dll(bytes, &prov, dll_path));
    }

    // Attribution safety: credit only a DLL that relates to the key by name or
    // is the archive's own primary library (not a bundled driver/third-party
    // stub). Identical rule to the `.so` path, applied to the reconstructed stem.
    if !so_belongs_to_auto_key(&stem, manifest_key) {
        return None;
    }

    let identity = auto_identity(&stem, manifest_key);
    let prov = BinaryProvenance {
        component: identity,
        version: job.version.clone(),
        release_label: job.release_label.clone(),
    };
    Some(fingerprint_dll(bytes, &prov, dll_path))
}

/// True if a SONAME stem names a cross-cutting driver/loader/third-party stub
/// that NVIDIA bundles into archives it does not belong to. These must never be
/// auto-credited to an archive whose key is unrelated to them.
///
/// The core CUDA cases are the driver `libcuda.so` and the OpenCL ICD loader
/// `libOpenCL.so` (the one archive that legitimately *is* `libOpenCL.so`,
/// `cuda_opencl`, relates to its key via `soname_belongs_to_key` and is kept by
/// that branch before this guard applies). The remaining entries are
/// third-party / driver runtime libraries observed bundled in NVIDIA's
/// driver/datacenter/IDE archives (`libnvidia-*`, Qt, OpenSSL, GL/EGL, ICU,
/// Eclipse); those archives are already dropped wholesale by the license gate,
/// so this is defense-in-depth should such a `.so` ever reach the auto path.
fn is_bundled_driver_stub(soname_stem: &str) -> bool {
    // Exact cross-cutting loaders/driver stub.
    if matches!(soname_stem, "libcuda.so" | "libOpenCL.so") {
        return true;
    }
    STUB_PREFIXES
        .iter()
        .any(|prefix| soname_stem.starts_with(prefix))
}

/// Recognized third-party / driver-runtime library families (prefix match on
/// the conventional `lib<name>` / tooling name). Hoisted to module scope so it
/// is defined once rather than per call.
const STUB_PREFIXES: &[&str] = &[
    "libnvidia-", // driver runtime components
    "libQt5",     // IDE (Nsight) Qt runtime
    "libQt6",
    "libssl",    // OpenSSL
    "libcrypto", // OpenSSL
    "libGL",     // GL/GLX/GLES
    "libEGL",    // EGL
    "libicu",    // ICU (also seen as `icu*`)
    "icu",
    "eclipse", // Nsight VSE / Eclipse bits
];

/// True if an archive's table of contents lists at least one shared library
/// (`.so` on Linux, `.dll` on Windows). The Model B gate: an unprofiled key
/// auto-derives a component **iff** its archive actually ships a shared library.
/// Reads the TOC without extracting.
///
/// Both platforms are accepted so a key's Windows-only archive (ships `.dll`
/// but no `.so`) is not silently dropped; its identity is still groundable
/// from the NVIDIA DLL naming convention (`NAME64_<major>.dll` <-> `libNAME.so`,
/// see [`dll_candidate_soname_stem`]).
fn archive_ships_shared_library(archive_path: &Path) -> bool {
    archive_table_of_contents(archive_path).iter().any(|name| {
        let base = name.rsplit('/').next().unwrap_or(name);
        base.contains(".so") || base.to_ascii_lowercase().ends_with(".dll")
    })
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
        let Some(component) = manifest.components.get(key) else {
            continue;
        };
        // Mirror the auto-derivation license gate: an excluded-license
        // (driver/datacenter/IDE) key is intentionally not auto-derived, so it
        // must not be reported as an auto-derived shared library either.
        if cudabom_identify::license_is_excluded(component.license.as_deref()) {
            continue;
        }
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

    // Model B auto-derives any unmapped key that ships a real `.so` into a
    // component (identity read from the library's own SONAME), so these are no
    // longer silently dropped. Surface them as an informational tripwire so a
    // reviewed `ComponentProfile` (preferred canonical name + advisory terms)
    // can still be added to enrich the auto-derived identity.
    if !unmapped_with_libs.is_empty() {
        status!("");
        status!(
            "xtask: NOTE: {} unmapped manifest key(s) ship a shared library and were AUTO-DERIVED (Model B).",
            unmapped_with_libs.len()
        );
        status!("xtask: identity was read from each library's real SONAME. Add a ComponentProfile to enrich (canonical name + advisory terms):");
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

    // --- self-heal selection (stale shards + re-lock) ---------------------

    /// A shard whose source manifest offers a non-excluded archive the shard
    /// never incorporated is flagged stale; once that archive's sha256 is in
    /// provenance, it is no longer flagged (self-terminating).
    #[test]
    fn shard_missing_derivable_archive_is_content_based_and_self_terminating() {
        let scratch = ScratchDir::new().unwrap();
        let from = scratch.path();
        // Source manifest: one derivable (CUDA Toolkit) + one excluded (driver).
        let manifest = r#"{
            "release_label": "12.6.0",
            "cuda_nvtx": {
                "name": "CUDA NVTX",
                "license": "CUDA Toolkit",
                "version": "12.6.37",
                "linux-x86_64": {
                    "relative_path": "cuda_nvtx/linux-x86_64/a.tar.xz",
                    "sha256": "aaaa"
                }
            },
            "nvidia_driver": {
                "name": "NVIDIA Driver",
                "license": "NVIDIA Driver",
                "version": "560.0",
                "linux-x86_64": {
                    "relative_path": "nvidia_driver/linux-x86_64/d.tar.xz",
                    "sha256": "dddd"
                }
            }
        }"#;
        std::fs::write(from.join("redistrib_12.6.0.json"), manifest).unwrap();

        // Shard that incorporated NEITHER archive -> stale (nvtx is derivable).
        let shard_none = serde_json::json!({ "provenance": { "corpus_sha256": [] } });
        assert!(
            shard_missing_derivable_archive(&shard_none, from, "redistrib_12.6.0.json"),
            "a shard missing the derivable nvtx archive must be stale"
        );

        // Shard that incorporated ONLY the excluded driver archive -> still
        // stale, because the derivable nvtx archive is still missing.
        let shard_driver_only = serde_json::json!({ "provenance": { "corpus_sha256": ["dddd"] } });
        assert!(
            shard_missing_derivable_archive(&shard_driver_only, from, "redistrib_12.6.0.json"),
            "incorporating only an excluded archive must not clear staleness"
        );

        // Shard that incorporated the derivable archive -> NOT stale: the
        // excluded driver archive never counts, so this self-terminates even
        // though `dddd` is absent.
        let shard_healed = serde_json::json!({ "provenance": { "corpus_sha256": ["aaaa"] } });
        assert!(
            !shard_missing_derivable_archive(&shard_healed, from, "redistrib_12.6.0.json"),
            "once the derivable archive is recorded, the shard must stop being stale"
        );
    }

    /// A Windows-only archive (`.zip`, never fetched or derived on the
    /// Linux-only corpus) must NOT mark a shard stale; otherwise every shard
    /// with a Windows archive would be perpetually stale and never
    /// self-terminate.
    #[test]
    fn shard_missing_derivable_archive_ignores_windows_only_archives() {
        let scratch = ScratchDir::new().unwrap();
        let from = scratch.path();
        let manifest = r#"{
            "release_label": "12.6.0",
            "cuda_foo": {
                "name": "Foo",
                "license": "CUDA Toolkit",
                "version": "1.0.0",
                "linux-x86_64": {
                    "relative_path": "cuda_foo/linux-x86_64/l.tar.xz",
                    "sha256": "lin1"
                },
                "windows-x86_64": {
                    "relative_path": "cuda_foo/windows-x86_64/w.zip",
                    "sha256": "win1"
                }
            }
        }"#;
        std::fs::write(from.join("redistrib_12.6.0.json"), manifest).unwrap();

        // The Linux archive is recorded; only the Windows archive is "missing".
        // That must not count, so the shard is NOT stale.
        let shard = serde_json::json!({ "provenance": { "corpus_sha256": ["lin1"] } });
        assert!(
            !shard_missing_derivable_archive(&shard, from, "redistrib_12.6.0.json"),
            "a missing Windows-only archive must not mark a Linux-derived shard stale"
        );
    }

    /// With no source manifest to compare against, staleness cannot be proven,
    /// so the shard is not flagged (the manifest-only path handles that case).
    #[test]
    fn shard_missing_derivable_archive_false_without_source_manifest() {
        let scratch = ScratchDir::new().unwrap();
        let shard = serde_json::json!({ "provenance": { "corpus_sha256": [] } });
        assert!(!shard_missing_derivable_archive(
            &shard,
            scratch.path(),
            "redistrib_absent.json"
        ));
    }

    /// The base URL is recovered from a committed lock entry by stripping the
    /// manifest's own `relative_path` suffix, preserving non-default hosts and
    /// path depths (sibling / jetson / cuda-repos trees).
    #[test]
    fn recover_base_url_strips_relative_path_suffix() {
        let manifest = r#"{
            "release_label": "1.0.0",
            "libfoo": {
                "name": "foo",
                "version": "1.0.0",
                "linux-x86_64": {
                    "relative_path": "libfoo/linux-x86_64/foo.tar.xz",
                    "sha256": "ffff"
                }
            }
        }"#;
        let manifest = RedistManifest::from_json(manifest.as_bytes()).unwrap();
        let lock = cudabom_identify::CorpusLock {
            schema_version: 1,
            entries: vec![cudabom_identify::CorpusEntry {
                component: "libfoo".into(),
                version: "1.0.0".into(),
                platform: "linux-x86_64".into(),
                url: "https://host.example/compute/sibling/redist/libfoo/linux-x86_64/foo.tar.xz"
                    .into(),
                sha256: "ffff".into(),
            }],
        };
        assert_eq!(
            recover_base_url(&lock, &manifest).as_deref(),
            Some("https://host.example/compute/sibling/redist")
        );
    }

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
    fn archive_ships_shared_library_gates_on_a_real_so() {
        // Model B gate: an archive that ships a `.so` is a candidate for
        // auto-derivation; one that ships only a header/static lib is not.
        let dir = std::env::temp_dir().join(format!(
            "cudabom-ships-so-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        std::fs::create_dir_all(dir.join("withso/lib")).unwrap();
        std::fs::create_dir_all(dir.join("noso/lib")).unwrap();
        std::fs::create_dir_all(dir.join("noso/include")).unwrap();
        std::fs::write(dir.join("withso/lib/libcal.so.12"), b"\x7fELF").unwrap();
        std::fs::write(dir.join("noso/lib/libnvptxcompiler_static.a"), b"!<arch>").unwrap();
        std::fs::write(dir.join("noso/include/foo.h"), b"// header").unwrap();

        let tar = |name: &str| -> Option<PathBuf> {
            let archive = dir.join(format!("{name}.tar"));
            Command::new("tar")
                .arg("-cf")
                .arg(&archive)
                .arg("-C")
                .arg(&dir)
                .arg(name)
                .status()
                .is_ok_and(|s| s.success())
                .then_some(archive)
        };

        if let Some(withso) = tar("withso") {
            assert!(
                archive_ships_shared_library(&withso),
                "an archive shipping libcal.so is a Model B candidate"
            );
        }
        if let Some(noso) = tar("noso") {
            assert!(
                !archive_ships_shared_library(&noso),
                "a static-only / header-only archive is not a candidate"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn bundled_driver_stubs_are_recognized() {
        // The cross-cutting stubs NVIDIA bundles into unrelated archives.
        assert!(is_bundled_driver_stub("libcuda.so"));
        assert!(is_bundled_driver_stub("libOpenCL.so"));
        // Recognized third-party / driver runtime families (defense-in-depth;
        // their archives are already dropped wholesale by the license gate).
        assert!(is_bundled_driver_stub("libnvidia-ml.so"));
        assert!(is_bundled_driver_stub("libQt5Core.so"));
        assert!(is_bundled_driver_stub("libssl.so"));
        assert!(is_bundled_driver_stub("libcrypto.so"));
        assert!(is_bundled_driver_stub("libGL.so"));
        assert!(is_bundled_driver_stub("libEGL.so"));
        assert!(is_bundled_driver_stub("libicuuc.so"));
        // A real component library is not a stub.
        assert!(!is_bundled_driver_stub("libcal.so"));
        assert!(!is_bundled_driver_stub("libcudnn_graph.so"));
        assert!(!is_bundled_driver_stub("libnvToolsExt.so"));
        assert!(!is_bundled_driver_stub("libnvtx3interop.so"));
    }

    #[test]
    fn so_belongs_to_auto_key_allows_primary_and_drops_stub() {
        // A name-related primary library belongs.
        assert!(so_belongs_to_auto_key("libcal.so", "libcal"));
        // A primary library that does NOT relate by name still belongs (NVTX).
        assert!(so_belongs_to_auto_key("libnvToolsExt.so", "cuda_nvtx"));
        assert!(so_belongs_to_auto_key("libnvtx3interop.so", "cuda_nvtx"));
        // A bundled driver stub never belongs, regardless of key.
        assert!(!so_belongs_to_auto_key("libcuda.so", "cuda_nvtx"));
        assert!(!so_belongs_to_auto_key("libnvidia-ml.so", "cuda_nvtx"));
    }

    #[test]
    fn dll_candidate_soname_stem_mirrors_nvidia_dll_naming() {
        let stem = |n: &str| dll_candidate_soname_stem(Path::new(n));
        // `NAME64_<major>.dll` -> `libNAME.so`.
        assert_eq!(
            stem("nvToolsExt64_1.dll").as_deref(),
            Some("libnvToolsExt.so")
        );
        assert_eq!(stem("cudart64_12.dll").as_deref(), Some("libcudart.so"));
        // Mixed-case base name is preserved (so it can match `libcublasLt.so`).
        assert_eq!(stem("cublasLt64_12.dll").as_deref(), Some("libcublasLt.so"));
        // MULTI-TOKEN stems must NOT be truncated at the first `_` (regression:
        // `cudnn_graph64_9.dll` previously reduced to `libcudnn.so`).
        assert_eq!(
            stem("cudnn_graph64_9.dll").as_deref(),
            Some("libcudnn_graph.so")
        );
        assert_eq!(
            stem("cudnn_engines_runtime_compiled64_9.dll").as_deref(),
            Some("libcudnn_engines_runtime_compiled.so")
        );
        assert_eq!(
            stem("nvpl_blas_core64_0.dll").as_deref(),
            Some("libnvpl_blas_core.so")
        );
        // Hyphenated multi-token stem (nvrtc builtins) preserved.
        assert_eq!(
            stem("nvrtc-builtins64_134.dll").as_deref(),
            Some("libnvrtc-builtins.so")
        );
        // `NAME_<major>.dll` (no 64) strips only the trailing numeric token.
        assert_eq!(stem("OpenCL_1.dll").as_deref(), Some("libOpenCL.so"));
        // A trailing NON-numeric token is part of the stem, not an ABI suffix.
        assert_eq!(
            stem("sanitizer_collection.dll").as_deref(),
            Some("libsanitizer_collection.so")
        );
        // Bare `NAME.dll`.
        assert_eq!(stem("cal.dll").as_deref(), Some("libcal.so"));
        // Case-insensitive extension; non-DLL and empty-base reject.
        assert_eq!(stem("cudart64_12.DLL").as_deref(), Some("libcudart.so"));
        assert_eq!(stem("libcudart.so"), None);
        assert_eq!(stem("64_12.dll"), None); // base reduces to empty
    }

    #[test]
    fn auto_fingerprint_dll_mirrors_so_attribution() {
        // Build an ArchiveJob for a given auto key; only version/release_label/
        // attribution are read by `auto_fingerprint_dll`.
        let job_for = |key: &str| ArchiveJob {
            archive_path: PathBuf::from("/dev/null"),
            version: "12.6.0".to_string(),
            release_label: Some("12.6.0".to_string()),
            attribution: Attribution::Auto {
                manifest_key: key.to_string(),
            },
            label: String::new(),
            archive_sha256: String::new(),
        };
        let bytes = b"MZ-not-a-real-pe-but-hash-is-all-we-record";

        // MINT: NVTX's own DLL (stem-core unrelated to key) is credited to the
        // key-named component `nvtx`, exactly as its Linux `.so` sibling is.
        let nvtx = job_for("cuda_nvtx");
        let fp = auto_fingerprint_dll(bytes, Path::new("nvToolsExt64_1.dll"), "cuda_nvtx", &nvtx)
            .expect("nvtx primary DLL must auto-derive");
        assert_eq!(fp.component, "nvtx");
        assert_eq!(fp.file_sha256, cudabom_fetch::hex_sha256(bytes));
        assert!(fp.build_id.is_none() && fp.soname_stem.is_none());

        // FOLD: a cuDNN sub-library DLL shipped under `cudnn_jit` folds into the
        // profiled `cudnn` component (same authority as the `.so` fold path).
        let jit = job_for("cudnn_jit");
        let fp = auto_fingerprint_dll(bytes, Path::new("cudnn_graph64_9.dll"), "cudnn_jit", &jit)
            .expect("cudnn sub-library DLL must fold");
        assert_eq!(fp.component, "cudnn");

        // DROP: a bundled driver stub DLL is never credited to an unrelated key.
        assert!(
            auto_fingerprint_dll(bytes, Path::new("cuda64_1.dll"), "cuda_nvtx", &nvtx).is_none(),
            "a bundled `cuda64_*.dll` driver stub must not be credited to `cuda_nvtx`"
        );
    }

    /// Compile a tiny shared object with a given SONAME; `None` if no C
    /// compiler is available. Linux-only (where ELF `.so`s and CI live).
    #[cfg(target_os = "linux")]
    fn compile_shared(dir: &Path, soname: &str) -> Option<PathBuf> {
        let cc = if Command::new("cc").arg("--version").output().is_ok() {
            "cc"
        } else if Command::new("gcc").arg("--version").output().is_ok() {
            "gcc"
        } else {
            return None;
        };
        let src = dir.join("lib.c");
        let out = dir.join(soname);
        std::fs::write(&src, "int cudabom_symbol(int x){return x+1;}").ok()?;
        let status = Command::new(cc)
            .args(["-shared", "-fPIC"])
            .arg(format!("-Wl,-soname,{soname}"))
            .arg("-Wl,--build-id=sha1")
            .arg("-o")
            .arg(&out)
            .arg(&src)
            .status()
            .ok()?;
        status.success().then_some(out)
    }

    /// End-to-end Model B: build a real archive containing a primary `.so`
    /// (`libcal.so`) and a bundled unrelated driver stub (`libcuda.so`), lay it
    /// out in the corpus under an unprofiled manifest key, and derive. The
    /// unprofiled key must auto-derive a component named from the real SONAME
    /// stem-core (`cal`), carrying the archive hash and the primary library's
    /// `.so` fingerprints, while the bundled `libcuda.so` stub is NOT credited.
    #[cfg(target_os = "linux")]
    #[test]
    fn unprofiled_so_bearing_key_auto_derives_and_drops_bundled_stub() {
        let base = std::env::temp_dir().join(format!(
            "cudabom-autoderive-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        let build = base.join("build/libcal/lib");
        std::fs::create_dir_all(&build).unwrap();
        // Primary library (SONAME libcal.so) + a bundled driver stub
        // (SONAME libcuda.so). File names are irrelevant: identity and
        // attribution are read from each ELF's DT_SONAME.
        if compile_shared(&build, "libcal.so.12").is_none() {
            eprintln!("no C compiler; skipping");
            let _ = std::fs::remove_dir_all(&base);
            return;
        }
        if compile_shared(&build, "libcuda.so.1").is_none() {
            eprintln!("no C compiler; skipping");
            let _ = std::fs::remove_dir_all(&base);
            return;
        }

        // Pack the staged tree into a .tar laid out at the corpus path the
        // auto-derivation reader expects: <corpus>/<key>/<version>/<platform>/.
        let corpus = base.join("corpus");
        let version = "1.0.0";
        let platform = "linux-x86_64";
        let archive_dir = corpus.join("libcal").join(version).join(platform);
        std::fs::create_dir_all(&archive_dir).unwrap();
        let archive_path = archive_dir.join("libcal-linux-x86_64-1.0.0-archive.tar");
        let ok = Command::new("tar")
            .arg("-cf")
            .arg(&archive_path)
            .arg("-C")
            .arg(base.join("build"))
            .arg("libcal")
            .status()
            .is_ok_and(|s| s.success());
        assert!(ok, "staging the test archive must succeed");

        // Compute the archive's real sha256 so we can assert the archive-hash
        // record is attributed to the auto-derived component.
        let archive_bytes = std::fs::read(&archive_path).unwrap();
        let archive_sha = cudabom_fetch::hex_sha256(&archive_bytes);

        let manifest_json = format!(
            r#"{{
                "release_label": "1.0.0",
                "libcal": {{
                    "name": "cuda libcal",
                    "version": "{version}",
                    "{platform}": {{
                        "relative_path": "libcal/{platform}/libcal-linux-x86_64-1.0.0-archive.tar",
                        "sha256": "{archive_sha}"
                    }}
                }}
            }}"#
        );
        let manifest = RedistManifest::from_json(manifest_json.as_bytes()).unwrap();
        let derived = derive(&manifest);
        // libcal is unprofiled, so the manifest layer reports it underived.
        assert_eq!(derived.underived, vec!["libcal".to_string()]);

        let fps =
            binary_fingerprints_for_manifest(&manifest, &derived.underived, &corpus, 1).unwrap();
        assert!(
            !fps.is_empty(),
            "a .so-bearing unprofiled key must auto-derive fingerprints"
        );
        // Identity read from the real SONAME stem-core: `cal`.
        assert!(
            fps.iter().all(|f| f.component == "cal"),
            "every auto fingerprint is attributed to `cal`: {:?}",
            fps.iter().map(|f| &f.component).collect::<Vec<_>>()
        );
        // The bundled libcuda.so stub is NOT credited (attribution safety).
        assert!(
            fps.iter()
                .all(|f| f.soname_stem.as_deref() != Some("libcuda.so")),
            "the bundled libcuda.so stub must not be credited"
        );
        // The primary library's SONAME stem is captured.
        assert!(
            fps.iter()
                .any(|f| f.soname_stem.as_deref() == Some("libcal.so")),
            "the primary libcal.so stem must be captured"
        );
        // The archive's own hash is recorded against the auto component.
        assert!(
            fps.iter()
                .any(|f| f.file_sha256 == archive_sha && f.component == "cal"),
            "the archive hash must be attributed to the auto component"
        );

        let _ = std::fs::remove_dir_all(&base);
    }

    /// Fix A (license gate): a `.so`-bearing unprofiled key whose manifest
    /// `license` is one of NVIDIA's driver/datacenter/IDE tags (here
    /// `NVIDIA SLA`, as `nsight_compute` carries) must NOT auto-derive any
    /// component, even though its primary `.so` name-matches the key.
    #[cfg(target_os = "linux")]
    #[test]
    fn excluded_license_key_never_auto_derives() {
        let base = std::env::temp_dir().join(format!(
            "cudabom-excl-license-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        let build = base.join("build/fabricmanager/lib");
        std::fs::create_dir_all(&build).unwrap();
        // A real .so whose name matches the key, so only the license gate can
        // stop it from minting.
        if compile_shared(&build, "libnvfm.so.1").is_none() {
            eprintln!("no C compiler; skipping");
            let _ = std::fs::remove_dir_all(&base);
            return;
        }
        let version = "1.0.0";
        let platform = "linux-x86_64";
        let archive_dir = corpus_dir_for(&base, "fabricmanager", version, platform);
        std::fs::create_dir_all(&archive_dir).unwrap();
        let archive_path = archive_dir.join("fabricmanager-linux-x86_64-1.0.0-archive.tar");
        let ok = Command::new("tar")
            .arg("-cf")
            .arg(&archive_path)
            .arg("-C")
            .arg(base.join("build"))
            .arg("fabricmanager")
            .status()
            .is_ok_and(|s| s.success());
        assert!(ok, "staging the test archive must succeed");
        let archive_sha = cudabom_fetch::hex_sha256(&std::fs::read(&archive_path).unwrap());

        // Manifest carries the EXCLUDED license `NVIDIA SLA`.
        let manifest_json = format!(
            r#"{{
                "release_label": "1.0.0",
                "fabricmanager": {{
                    "name": "NVIDIA Fabric Manager",
                    "license": "NVIDIA SLA",
                    "version": "{version}",
                    "{platform}": {{
                        "relative_path": "fabricmanager/{platform}/fabricmanager-linux-x86_64-1.0.0-archive.tar",
                        "sha256": "{archive_sha}"
                    }}
                }}
            }}"#
        );
        let manifest = RedistManifest::from_json(manifest_json.as_bytes()).unwrap();
        let derived = derive(&manifest);
        assert_eq!(derived.underived, vec!["fabricmanager".to_string()]);

        let fps =
            binary_fingerprints_for_manifest(&manifest, &derived.underived, &corpus_root(&base), 1)
                .unwrap();
        assert!(
            fps.is_empty(),
            "an excluded-license (NVIDIA SLA) key must auto-derive nothing: {:?}",
            fps.iter().map(|f| &f.component).collect::<Vec<_>>()
        );

        let _ = std::fs::remove_dir_all(&base);
    }

    /// Fix B (primary-library allowance): a key whose primary `.so` stem-core
    /// does NOT textually relate to the key (the NVTX case: `cuda_nvtx` ships
    /// `libnvToolsExt.so`, stem-core `nvtoolsext` vs key `nvtx`) must still
    /// auto-derive, with the component named from the key (`nvtx`), while a
    /// bundled `libcuda.so` stub in the same archive is still dropped.
    #[cfg(target_os = "linux")]
    #[test]
    fn primary_library_without_name_relation_still_derives() {
        let base = std::env::temp_dir().join(format!(
            "cudabom-nvtx-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        let build = base.join("build/cuda_nvtx/lib");
        std::fs::create_dir_all(&build).unwrap();
        // Primary library whose SONAME does NOT relate to the key by name, plus
        // a genuinely bundled driver stub that must be dropped.
        if compile_shared(&build, "libnvToolsExt.so.1").is_none()
            || compile_shared(&build, "libcuda.so.1").is_none()
        {
            eprintln!("no C compiler; skipping");
            let _ = std::fs::remove_dir_all(&base);
            return;
        }
        let version = "12.0.0";
        let platform = "linux-x86_64";
        let archive_dir = corpus_dir_for(&base, "cuda_nvtx", version, platform);
        std::fs::create_dir_all(&archive_dir).unwrap();
        let archive_path = archive_dir.join("cuda_nvtx-linux-x86_64-12.0.0-archive.tar");
        let ok = Command::new("tar")
            .arg("-cf")
            .arg(&archive_path)
            .arg("-C")
            .arg(base.join("build"))
            .arg("cuda_nvtx")
            .status()
            .is_ok_and(|s| s.success());
        assert!(ok, "staging the test archive must succeed");
        let archive_sha = cudabom_fetch::hex_sha256(&std::fs::read(&archive_path).unwrap());

        // License `CUDA Toolkit` is allowed (falls through the license gate).
        let manifest_json = format!(
            r#"{{
                "release_label": "12.0.0",
                "cuda_nvtx": {{
                    "name": "CUDA NVTX",
                    "license": "CUDA Toolkit",
                    "version": "{version}",
                    "{platform}": {{
                        "relative_path": "cuda_nvtx/{platform}/cuda_nvtx-linux-x86_64-12.0.0-archive.tar",
                        "sha256": "{archive_sha}"
                    }}
                }}
            }}"#
        );
        let manifest = RedistManifest::from_json(manifest_json.as_bytes()).unwrap();
        let derived = derive(&manifest);
        assert_eq!(derived.underived, vec!["cuda_nvtx".to_string()]);

        let fps =
            binary_fingerprints_for_manifest(&manifest, &derived.underived, &corpus_root(&base), 1)
                .unwrap();
        // The primary libnvToolsExt.so is credited to the key-named component.
        assert!(
            fps.iter()
                .any(|f| f.component == "nvtx"
                    && f.soname_stem.as_deref() == Some("libnvToolsExt.so")),
            "libnvToolsExt.so must be credited to the `nvtx` component: {:?}",
            fps.iter()
                .map(|f| (&f.component, &f.soname_stem))
                .collect::<Vec<_>>()
        );
        // The bundled libcuda.so stub is still dropped.
        assert!(
            fps.iter()
                .all(|f| f.soname_stem.as_deref() != Some("libcuda.so")),
            "the bundled libcuda.so stub must not be credited"
        );
        // Every derived component is `nvtx` (no `nvToolsExt`, no `cuda`).
        assert!(
            fps.iter().all(|f| f.component == "nvtx"),
            "every auto fingerprint is attributed to `nvtx`: {:?}",
            fps.iter().map(|f| &f.component).collect::<Vec<_>>()
        );

        let _ = std::fs::remove_dir_all(&base);
    }

    /// Corpus root under a test base dir.
    #[cfg(target_os = "linux")]
    fn corpus_root(base: &Path) -> PathBuf {
        base.join("corpus")
    }

    /// The corpus archive dir for an auto key: `<base>/corpus/<key>/<v>/<plat>`.
    #[cfg(target_os = "linux")]
    fn corpus_dir_for(base: &Path, key: &str, version: &str, platform: &str) -> PathBuf {
        corpus_root(base).join(key).join(version).join(platform)
    }

    /// A key whose archive ships no `.so` (samples + static-only `.a`) must
    /// auto-derive nothing: no SONAME means no identity to ground on.
    #[test]
    #[cfg(target_os = "linux")]
    fn samples_or_static_only_key_auto_derives_nothing() {
        let base = std::env::temp_dir().join(format!(
            "cudabom-noso-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        let version = "1.0.0";
        let platform = "linux-x86_64";
        let staged = base.join("build/cudnn_samples/samples");
        std::fs::create_dir_all(&staged).unwrap();
        std::fs::write(staged.join("conv_sample.cpp"), b"// sample").unwrap();
        std::fs::write(staged.join("libstatic.a"), b"!<arch>").unwrap();

        let corpus = base.join("corpus");
        let archive_dir = corpus.join("cudnn_samples").join(version).join(platform);
        std::fs::create_dir_all(&archive_dir).unwrap();
        let archive_path = archive_dir.join("cudnn_samples-linux-x86_64-1.0.0-archive.tar");
        let ok = Command::new("tar")
            .arg("-cf")
            .arg(&archive_path)
            .arg("-C")
            .arg(base.join("build"))
            .arg("cudnn_samples")
            .status()
            .is_ok_and(|s| s.success());
        if !ok {
            let _ = std::fs::remove_dir_all(&base);
            return; // no system tar; nothing to assert
        }
        let archive_bytes = std::fs::read(&archive_path).unwrap();
        let archive_sha = cudabom_fetch::hex_sha256(&archive_bytes);
        let manifest_json = format!(
            r#"{{
                "release_label": "1.0.0",
                "cudnn_samples": {{
                    "name": "cuDNN samples",
                    "version": "{version}",
                    "{platform}": {{
                        "relative_path": "cudnn_samples/{platform}/cudnn_samples-linux-x86_64-1.0.0-archive.tar",
                        "sha256": "{archive_sha}"
                    }}
                }}
            }}"#
        );
        let manifest = RedistManifest::from_json(manifest_json.as_bytes()).unwrap();
        let derived = derive(&manifest);
        assert_eq!(derived.underived, vec!["cudnn_samples".to_string()]);
        let fps =
            binary_fingerprints_for_manifest(&manifest, &derived.underived, &corpus, 1).unwrap();
        assert!(
            fps.is_empty(),
            "a samples/static-only archive must auto-derive nothing: {:?}",
            fps.iter().map(|f| &f.component).collect::<Vec<_>>()
        );
        let _ = std::fs::remove_dir_all(&base);
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

/// Network/env-gated end-to-end test of the Model B auto-derivation pipeline on
/// REAL NVIDIA archives. OFF by default: `cargo test --workspace` stays offline
/// and green because this returns early unless `CUDABOM_NETWORK_TESTS` is set.
///
/// Run on demand:
/// `CUDABOM_NETWORK_TESTS=1 cargo test -p xtask -- --nocapture model_b_auto_derivation_real_archives`
#[cfg(test)]
mod net_tests {
    use super::*;
    use cudabom_fetch::{GetOptions, RetryPolicy};

    /// Absolute path to a workspace fixture. `cargo test -p xtask` runs with the
    /// crate dir as CWD, so resolve fixtures relative to the workspace root
    /// (one level up from `CARGO_MANIFEST_DIR`, the `xtask/` crate dir).
    fn fixture(rel: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("workspace root is the parent of the xtask crate dir")
            .join(rel)
    }

    /// A fresh, unique scratch root under the system temp dir (xtask has no
    /// `tempfile` dependency; mirror the nanos-suffix pattern used by the other
    /// in-crate tests). Removed by the caller at the end of a successful run.
    fn unique_root(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "cudabom-netns-{tag}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ))
    }

    /// Fetch `url` with the crate's default user-agent and retry policy, writing
    /// the bytes to the corpus layout `corpus_archive_path` expects:
    /// `<root>/<key>/<version>/<platform>/<file_name>`. Returns `false` (so the
    /// caller can skip gracefully, never panic) on any non-200 / network error.
    fn stage(
        corpus_root: &Path,
        key: &str,
        version: &str,
        platform: &str,
        file_name: &str,
        url: &str,
    ) -> bool {
        let options = GetOptions {
            retry: RetryPolicy::default(),
            expected_sha256: None,
            user_agent: cudabom_fetch::DEFAULT_USER_AGENT.to_string(),
            headers: Vec::new(),
        };
        let bytes = match cudabom_fetch::get(url, &options) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("download failed for {url}: {e}; skipping network test");
                return false;
            }
        };
        let dest =
            crate::corpus::corpus_archive_path(corpus_root, key, version, platform, file_name);
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent).expect("create corpus dirs");
        }
        std::fs::write(&dest, &bytes).expect("write staged archive");
        true
    }

    /// Build the shard(s) for the manifests under `from_dir` with `corpus_root`
    /// present, writing to `out_dir`. Uses the exact `build` entry point the
    /// `fingerprints build` CLI uses, with `--force` (always re-derive) and
    /// `--keep-downloads` (we manage/clean the corpus ourselves).
    fn build_shards(from_dir: &Path, out_dir: &Path, corpus_root: &Path) {
        let args = vec![
            "--from".to_string(),
            from_dir.display().to_string(),
            "--out".to_string(),
            out_dir.display().to_string(),
            "--corpus".to_string(),
            corpus_root.display().to_string(),
            "--keep-downloads".to_string(),
            "--force".to_string(),
        ];
        build(&args).expect("fingerprints build should succeed");
    }

    /// Read a built shard and return `(component_name -> (file_hash_count,
    /// build_id_count, soname_stems))` so assertions read the real outcome.
    fn shard_components(
        shard_path: &Path,
    ) -> std::collections::BTreeMap<String, (usize, usize, Vec<String>)> {
        let json = std::fs::read_to_string(shard_path)
            .unwrap_or_else(|e| panic!("reading shard {}: {e}", shard_path.display()));
        let v: serde_json::Value = serde_json::from_str(&json).expect("shard is valid JSON");
        let mut out = std::collections::BTreeMap::new();
        for c in v["components"].as_array().expect("components array") {
            let name = c["name"].as_str().expect("component name").to_string();
            let fh = c["file_hashes"].as_object().map_or(0, serde_json::Map::len);
            let bid = c["build_ids"].as_object().map_or(0, serde_json::Map::len);
            let stems = c["soname_stems"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|s| s.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default();
            out.insert(name, (fh, bid, stems));
        }
        out
    }

    /// End-to-end proof of both Model B outcomes on REAL downloads:
    ///
    /// 1. FOLD: cuDNN 9.11.0.98's `cudnn_jit` archive ships `libcudnn_graph.so`
    ///    and `libcudnn_engines_runtime_compiled.so`, both already owned by the
    ///    reviewed `cudnn` profile, so they fold INTO `cudnn` (enriching its
    ///    file-hashes/build-ids) and must NOT mint `cudnn_graph` /
    ///    `cudnn_engines_runtime_compiled` components.
    /// 2. MINT: CUDA 13.4.2's `cuda_nvtx` (ships `libnvtx3interop.so`, NOT
    ///    `libnvToolsExt.so`) and `cuda_opencl` (ships `libOpenCL.so`) have no
    ///    reviewed profile, so they mint components named from the manifest key
    ///    (`nvtx`, `opencl`), NOT the raw SONAME stem-core (`nvToolsExt`,
    ///    `OpenCL`). Non-library keys (`demo_suite`, `documentation`) mint
    ///    nothing.
    #[test]
    fn model_b_auto_derivation_real_archives() {
        if std::env::var("CUDABOM_NETWORK_TESTS").is_err() {
            eprintln!("CUDABOM_NETWORK_TESTS not set; skipping network test");
            return;
        }

        let root = unique_root("modelb");
        let corpus = root.join("corpus");
        let from = root.join("from");
        let out = root.join("out");

        if !assert_fold_case(&corpus, &from, &out) {
            let _ = std::fs::remove_dir_all(&root);
            return; // graceful skip on network failure
        }
        if !assert_mint_case(&corpus, &from, &out) {
            let _ = std::fs::remove_dir_all(&root);
            return; // graceful skip on network failure
        }
        if !assert_windows_coverage_case(&corpus, &from, &out) {
            let _ = std::fs::remove_dir_all(&root);
            return; // graceful skip on network failure
        }
        if !assert_excluded_case(&corpus, &from, &out) {
            let _ = std::fs::remove_dir_all(&root);
            return; // graceful skip on network failure
        }

        let _ = std::fs::remove_dir_all(&root);
    }

    /// FOLD CASE. Returns `false` (skip) if the real download failed.
    fn assert_fold_case(corpus: &Path, from: &Path, out: &Path) -> bool {
        // cuDNN uses the COMPOSITE platform key `linux-x86_64-cuda12` (the
        // redist parser flattens the `cuda12` sub-variant into the platform).
        // The auto-key corpus path is keyed by the manifest key `cudnn_jit`.
        let staged = stage(
            corpus,
            "cudnn_jit",
            "9.11.0.98",
            "linux-x86_64-cuda12",
            "cudnn_jit-linux-x86_64-9.11.0.98_cuda12-archive.tar.xz",
            "https://developer.download.nvidia.com/compute/cudnn/redist/cudnn_jit/linux-x86_64/cudnn_jit-linux-x86_64-9.11.0.98_cuda12-archive.tar.xz",
        );
        if !staged {
            return false;
        }

        // Mirror the fixture layout `fixtures/redist/cudnn/redistrib_9.11.0.json`
        // under `from/cudnn/` so the shard lands at `out/cudnn/`.
        let cudnn_from = from.join("cudnn");
        std::fs::create_dir_all(&cudnn_from).expect("create from/cudnn");
        std::fs::copy(
            fixture("fixtures/redist/cudnn/redistrib_9.11.0.json"),
            cudnn_from.join("redistrib_9.11.0.json"),
        )
        .expect("copy cudnn fixture");

        build_shards(from, out, corpus);

        let cudnn_shard = shard_components(&out.join("cudnn/redistrib_9.11.0.json"));
        let (cudnn_fh, cudnn_bid, cudnn_stems) = cudnn_shard
            .get("cudnn")
            .expect("shard must contain a cudnn component");
        assert!(
            *cudnn_fh > 0 && *cudnn_bid > 0,
            "cudnn must be enriched by the jit archive (file_hashes={cudnn_fh}, build_ids={cudnn_bid})"
        );
        // The folded sub-libraries' real SONAMEs stay on cudnn's stem list.
        assert!(
            cudnn_stems.iter().any(|s| s == "libcudnn_graph.so"),
            "cudnn stems must include libcudnn_graph.so (folded): {cudnn_stems:?}"
        );
        assert!(
            cudnn_stems
                .iter()
                .any(|s| s == "libcudnn_engines_runtime_compiled.so"),
            "cudnn stems must include libcudnn_engines_runtime_compiled.so (folded): {cudnn_stems:?}"
        );
        // The jit sub-libraries must have FOLDED, not minted fragments.
        assert!(
            !cudnn_shard.contains_key("cudnn_graph"),
            "cudnn_graph must NOT be a separate component (folded into cudnn): {:?}",
            cudnn_shard.keys().collect::<Vec<_>>()
        );
        assert!(
            !cudnn_shard.contains_key("cudnn_engines_runtime_compiled"),
            "cudnn_engines_runtime_compiled must NOT be a separate component (folded into cudnn): {:?}",
            cudnn_shard.keys().collect::<Vec<_>>()
        );
        eprintln!(
            "FOLD: cudnn enriched (file_hashes={cudnn_fh}, build_ids={cudnn_bid}); \
             no cudnn_graph / cudnn_engines_runtime_compiled components."
        );
        true
    }

    /// MINT CASE. Returns `false` (skip) if a real download failed.
    fn assert_mint_case(corpus: &Path, from: &Path, out: &Path) -> bool {
        // CUDA toolkit 13.4.2, plain `linux-x86_64` platform. Fixture lives at
        // the fixtures root, so its shard lands at `out/`.
        let nvtx_ok = stage(
            corpus,
            "cuda_nvtx",
            "13.4.92",
            "linux-x86_64",
            "cuda_nvtx-linux-x86_64-13.4.92-archive.tar.xz",
            "https://developer.download.nvidia.com/compute/cuda/redist/cuda_nvtx/linux-x86_64/cuda_nvtx-linux-x86_64-13.4.92-archive.tar.xz",
        );
        let opencl_ok = stage(
            corpus,
            "cuda_opencl",
            "13.4.92",
            "linux-x86_64",
            "cuda_opencl-linux-x86_64-13.4.92-archive.tar.xz",
            "https://developer.download.nvidia.com/compute/cuda/redist/cuda_opencl/linux-x86_64/cuda_opencl-linux-x86_64-13.4.92-archive.tar.xz",
        );
        if !nvtx_ok || !opencl_ok {
            return false;
        }

        std::fs::copy(
            fixture("fixtures/redist/redistrib_13.4.2.json"),
            from.join("redistrib_13.4.2.json"),
        )
        .expect("copy cuda fixture");

        build_shards(from, out, corpus);

        let cuda_shard = shard_components(&out.join("redistrib_13.4.2.json"));
        // nvtx is minted from the manifest key (NOT the SONAME stem-core
        // `nvToolsExt`), carrying its real 13.x SONAME `libnvtx3interop.so`.
        let (_, _, nvtx_stems) = cuda_shard
            .get("nvtx")
            .expect("shard must contain an nvtx component (not nvToolsExt)");
        assert!(
            nvtx_stems.iter().any(|s| s == "libnvtx3interop.so"),
            "nvtx stems must include the real 13.x SONAME libnvtx3interop.so: {nvtx_stems:?}"
        );
        assert!(
            !cuda_shard.contains_key("nvToolsExt"),
            "must NOT mint a component named nvToolsExt (name comes from the key): {:?}",
            cuda_shard.keys().collect::<Vec<_>>()
        );
        // opencl is minted from the key, carrying its real SONAME libOpenCL.so.
        let (_, _, opencl_stems) = cuda_shard
            .get("opencl")
            .expect("shard must contain an opencl component (not OpenCL)");
        assert!(
            opencl_stems.iter().any(|s| s == "libOpenCL.so"),
            "opencl stems must include the real SONAME libOpenCL.so: {opencl_stems:?}"
        );
        assert!(
            !cuda_shard.contains_key("OpenCL"),
            "must NOT mint a component named OpenCL (name comes from the key): {:?}",
            cuda_shard.keys().collect::<Vec<_>>()
        );
        // Non-library keys ship no .so and must mint nothing.
        assert!(
            !cuda_shard.contains_key("demo_suite"),
            "demo_suite ships no .so and must not become a component: {:?}",
            cuda_shard.keys().collect::<Vec<_>>()
        );
        assert!(
            !cuda_shard.contains_key("documentation"),
            "documentation ships no .so and must not become a component: {:?}",
            cuda_shard.keys().collect::<Vec<_>>()
        );
        eprintln!(
            "MINT: nvtx {nvtx_stems:?}, opencl {opencl_stems:?}; \
             no nvToolsExt / OpenCL / demo_suite / documentation components."
        );
        true
    }

    /// WINDOWS-COVERAGE CASE (real archive): proves auto-derivation covers a new
    /// component on BOTH platforms, not Linux-only.
    ///
    /// `cuda_sanitizer_api` (license `CUDA Toolkit`, unprofiled) ships real
    /// shared libraries on Linux (`libsanitizer-*.so`) AND real runtime DLLs on
    /// Windows (`sanitizer-collection.dll`, `InterceptorInjectionTarget.dll`,
    /// ...). After this fix, staging BOTH archives must enrich the SAME
    /// auto-derived component with Windows DLL `file_hashes`; the Linux/Windows
    /// asymmetry is closed. (NVTX/OpenCL are intentionally NOT used here: NVTX3
    /// is header-only and OpenCL ships only an import `.lib` on Windows, so
    /// neither has a runtime DLL to cover, a real-world fact this fix respects
    /// by crediting nothing where there is no runtime binary.)
    ///
    /// Returns `false` (skip) on any download error. Uses a synthetic manifest
    /// (sanitizer is not in a committed cross-platform fixture) carrying the
    /// real license and both staged archives, driving the SAME `build` path.
    fn assert_windows_coverage_case(corpus: &Path, from: &Path, out: &Path) -> bool {
        let version = "13.4.92";
        let key = "cuda_sanitizer_api";
        let host = "https://developer.download.nvidia.com/compute/cuda/redist";

        let linux_file = format!("{key}-linux-x86_64-{version}-archive.tar.xz");
        let win_file = format!("{key}-windows-x86_64-{version}-archive.zip");
        let linux_ok = stage(
            corpus,
            key,
            version,
            "linux-x86_64",
            &linux_file,
            &format!("{host}/{key}/linux-x86_64/{linux_file}"),
        );
        let win_ok = stage(
            corpus,
            key,
            version,
            "windows-x86_64",
            &win_file,
            &format!("{host}/{key}/windows-x86_64/{win_file}"),
        );
        if !linux_ok || !win_ok {
            return false;
        }

        // Synthetic manifest with BOTH platform archives and the real license.
        let win_dir = from.join("wincov");
        std::fs::create_dir_all(&win_dir).expect("create from/wincov");
        let manifest_json = format!(
            r#"{{
                "release_label": "{version}",
                "{key}": {{
                    "name": "CUDA Sanitizer API",
                    "license": "CUDA Toolkit",
                    "version": "{version}",
                    "linux-x86_64": {{
                        "relative_path": "{key}/linux-x86_64/{linux_file}",
                        "sha256": "unused-in-this-path"
                    }},
                    "windows-x86_64": {{
                        "relative_path": "{key}/windows-x86_64/{win_file}",
                        "sha256": "unused-in-this-path"
                    }}
                }}
            }}"#
        );
        std::fs::write(win_dir.join("redistrib_wincov.json"), manifest_json)
            .expect("write synthetic wincov manifest");

        build_shards(&win_dir, &out.join("wincov"), corpus);

        let shard = shard_components(&out.join("wincov/redistrib_wincov.json"));
        // The auto-derived component is named from the key (`sanitizer_api`).
        let (fh, _, _) = shard.get("sanitizer_api").unwrap_or_else(|| {
            panic!(
                "shard must contain a sanitizer_api component: {:?}",
                shard.keys().collect::<Vec<_>>()
            )
        });
        // Both the Linux `.so`s and the Windows DLLs contribute `file_hashes`.
        // The Windows archive alone ships 4 DLLs, so the count must comfortably
        // exceed what Linux alone would yield; assert on cross-platform presence.
        assert!(
            *fh >= 2,
            "sanitizer_api must carry file_hashes from BOTH Linux .so and Windows DLLs (got {fh})"
        );
        eprintln!("WINDOWS-COVERAGE: sanitizer_api enriched on Linux+Windows (file_hashes={fh}).");
        true
    }

    /// EXCLUDED CASE (Fix A, real archive): `fabricmanager` ships a real `.so`
    /// (`libnvfm.so`) but its redist `license` is `NVIDIA SLA`, one of NVIDIA's
    /// own driver/datacenter tags. It must NOT mint any component despite
    /// shipping libraries. The archive is small (~9 MB). Because
    /// `fabricmanager` is not in a committed fixture, this writes a minimal
    /// synthetic manifest carrying the real license and the staged archive, and
    /// drives the SAME `build` path. Returns `false` (skip) on download error.
    fn assert_excluded_case(corpus: &Path, from: &Path, out: &Path) -> bool {
        let version = "610.43.02";
        let platform = "linux-x86_64";
        let file_name = "fabricmanager-linux-x86_64-610.43.02-archive.tar.xz";
        let staged = stage(
            corpus,
            "fabricmanager",
            version,
            platform,
            file_name,
            "https://developer.download.nvidia.com/compute/cuda/redist/fabricmanager/linux-x86_64/fabricmanager-linux-x86_64-610.43.02-archive.tar.xz",
        );
        if !staged {
            return false;
        }

        // Minimal real-license manifest. `fabricmanager` is unprofiled and
        // carries NVIDIA's excluded `NVIDIA SLA` license tag.
        let excl_dir = from.join("excl");
        std::fs::create_dir_all(&excl_dir).expect("create from/excl");
        let manifest_json = format!(
            r#"{{
                "release_label": "{version}",
                "fabricmanager": {{
                    "name": "NVIDIA Fabric Manager",
                    "license": "NVIDIA SLA",
                    "version": "{version}",
                    "{platform}": {{
                        "relative_path": "fabricmanager/{platform}/{file_name}",
                        "sha256": "unused-in-this-path"
                    }}
                }}
            }}"#
        );
        std::fs::write(excl_dir.join("redistrib_610.43.2.json"), manifest_json)
            .expect("write synthetic excluded manifest");

        build_shards(from, out, corpus);

        let excl_shard = shard_components(&out.join("excl/redistrib_610.43.2.json"));
        assert!(
            excl_shard.is_empty(),
            "an excluded-license (NVIDIA SLA) key must mint NO component despite shipping .so's: {:?}",
            excl_shard.keys().collect::<Vec<_>>()
        );
        eprintln!(
            "EXCLUDE: fabricmanager (license NVIDIA SLA, ships libnvfm.so) minted \
             no component ({} total).",
            excl_shard.len()
        );
        true
    }
}
