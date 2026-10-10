//! `cargo xtask corpus`: manage the fingerprint corpus.
//!
//! - `corpus lock` derives a committed `corpus.<version>.lock.json` from a
//!   redist manifest (URLs + NVIDIA's own sha256 digests; nothing invented).
//! - `corpus fetch` downloads and verifies each locked archive into the
//!   gitignored `./corpus` directory, using the shared `cudabom-fetch`
//!   primitive so it inherits retry/backoff/rate-limit handling.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use cudabom_fetch::{GetOptions, RetryPolicy};
use cudabom_identify::{lock_from_manifest, resolve_component, CorpusLock, RedistManifest};

use crate::verbosity::{detail, status};

use crate::{flag, has_flag};

/// Default corpus lockfile directory (holds `corpus.<release>.lock.json` shards).
const DEFAULT_LOCK_DIR: &str = cudabom_core::paths::FINGERPRINTS_DIR;
/// Default single lockfile path for `corpus lock` output (subset/smoke runs).
const DEFAULT_LOCK: &str = "fingerprints/corpus.lock.json";
/// HTTP User-Agent for every corpus download. Single-sourced from the shared
/// network layer so it matches every other fetch site.
const USER_AGENT: &str = cudabom_fetch::DEFAULT_USER_AGENT;
/// Canonical CUDA Linux target set, used when `--platform` is not given. Also
/// the set referenced in `--platform` help and the docs.
const DEFAULT_PLATFORMS: &[&str] = &[
    "linux-x86_64",
    "linux-sbsa",
    "linux-ppc64le",
    "linux-aarch64",
];
/// Default corpus download directory (gitignored).
const DEFAULT_CORPUS_DIR: &str = "corpus";
/// Default directory for saved redist manifests (fixtures).
const DEFAULT_FIXTURES_DIR: &str = "fixtures/redist";
/// Default directory of derived fingerprint shards (used to detect which
/// releases are already committed).
const DEFAULT_SHARD_DIR: &str = cudabom_core::paths::CUDA_SHARD_DIR;

/// A redistributable product tree cudabom discovers.
///
/// The set of products is itself first-party: it is NVIDIA's documented list of
/// redistributable archives (CUDA Installation Guide, "Available Tarball and
/// Zip Archives"). Each entry pairs the product's `compute/<product>/redist/`
/// base URL with the on-disk subdirectory its fixtures and shards live under,
/// so trees do not collide. Only the *product set* is enumerated here; every
/// product's *versions* and *components* stay fully dynamic (scraped from the
/// index, resolved via the reviewed component profiles).
///
/// The CUDA toolkit keeps the historical root paths (`fixtures/redist/`,
/// `fingerprints/cuda/`) for backward compatibility; siblings get a per-product
/// subdirectory (`fixtures/redist/<product>/`, `fingerprints/<product>/`).
#[derive(Debug, Clone, Copy)]
struct RedistProduct {
    /// Product name (matches NVIDIA's `--product` and the URL path segment).
    name: &'static str,
    /// Fixtures subdirectory under the fixtures root (empty = root, for cuda).
    fixtures_subdir: &'static str,
    /// Shard directory for this product's derived fingerprints.
    shard_dir: &'static str,
    /// Ad-hoc base URL override (set only by `--base-url`); when `None` the URL
    /// is composed from the configured download host.
    base_url_override: Option<&'static str>,
}

impl RedistProduct {
    /// The `compute/<product>/redist/` base URL, composed from the configured
    /// download host (see [`crate::sources`]), or the `--base-url` override
    /// returned verbatim when one is set.
    fn base_url(&self) -> String {
        match self.base_url_override {
            Some(url) => url.to_string(),
            None => crate::sources::redist_base(self.name),
        }
    }
}

/// NVIDIA's published redistributable product trees (CUDA Installation Guide,
/// "Available Tarball and Zip Archives"). Discovery iterates these; adding a
/// product is a one-line, reviewable change here (plus the component profiles
/// in `cudabom-identify` that let its archives be attributed).
const REDIST_PRODUCTS: &[RedistProduct] = &[
    RedistProduct {
        name: "cuda",
        fixtures_subdir: "",
        shard_dir: cudabom_core::paths::CUDA_SHARD_DIR,
        base_url_override: None,
    },
    RedistProduct {
        name: "cudnn",
        fixtures_subdir: "cudnn",
        shard_dir: "fingerprints/cudnn",
        base_url_override: None,
    },
    RedistProduct {
        name: "nccl",
        fixtures_subdir: "nccl",
        shard_dir: "fingerprints/nccl",
        base_url_override: None,
    },
    RedistProduct {
        name: "cutensor",
        fixtures_subdir: "cutensor",
        shard_dir: "fingerprints/cutensor",
        base_url_override: None,
    },
    RedistProduct {
        name: "cudss",
        fixtures_subdir: "cudss",
        shard_dir: "fingerprints/cudss",
        base_url_override: None,
    },
    RedistProduct {
        name: "cusparselt",
        fixtures_subdir: "cusparselt",
        shard_dir: "fingerprints/cusparselt",
        base_url_override: None,
    },
    RedistProduct {
        name: "cuquantum",
        fixtures_subdir: "cuquantum",
        shard_dir: "fingerprints/cuquantum",
        base_url_override: None,
    },
    RedistProduct {
        name: "nvjpeg2000",
        fixtures_subdir: "nvjpeg2000",
        shard_dir: "fingerprints/nvjpeg2000",
        base_url_override: None,
    },
    RedistProduct {
        name: "nvtiff",
        fixtures_subdir: "nvtiff",
        shard_dir: "fingerprints/nvtiff",
        base_url_override: None,
    },
    RedistProduct {
        name: "cublasmp",
        fixtures_subdir: "cublasmp",
        shard_dir: "fingerprints/cublasmp",
        base_url_override: None,
    },
    RedistProduct {
        name: "nvpl",
        fixtures_subdir: "nvpl",
        shard_dir: "fingerprints/nvpl",
        base_url_override: None,
    },
    RedistProduct {
        name: "nvshmem",
        fixtures_subdir: "nvshmem",
        shard_dir: "fingerprints/nvshmem",
        base_url_override: None,
    },
    RedistProduct {
        name: "nvcomp",
        fixtures_subdir: "nvcomp",
        shard_dir: "fingerprints/nvcomp",
        base_url_override: None,
    },
];

/// `corpus lock --manifest <file> [--out <file>] [--base-url <url>]
/// [--platform <p> ...]`
pub(crate) fn lock(args: &[String]) -> Result<()> {
    let manifest_path =
        flag(args, "--manifest").context("corpus lock requires --manifest <redistrib_*.json>")?;
    let out = flag(args, "--out").unwrap_or_else(|| DEFAULT_LOCK.to_string());
    let base_url = flag(args, "--base-url").unwrap_or_else(|| crate::sources::redist_base("cuda"));
    let platforms = collect_platforms(args);
    let platform_refs: Vec<&str> = platforms.iter().map(String::as_str).collect();

    let bytes = std::fs::read(&manifest_path)
        .with_context(|| format!("reading manifest {manifest_path}"))?;
    let manifest =
        RedistManifest::from_json(&bytes).map_err(|e| anyhow::anyhow!("{manifest_path}: {e}"))?;

    let lock = lock_from_manifest(&manifest, &base_url, &platform_refs, resolve_component);
    let limit = flag(args, "--limit")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(0);
    let lock = lock.limited(limit);
    if lock.entries.is_empty() {
        bail!("no lockable entries: no profiled components for platforms {platforms:?}");
    }
    let json = lock.to_json().map_err(|e| anyhow::anyhow!(e))?;
    if let Some(parent) = Path::new(&out).parent() {
        std::fs::create_dir_all(parent).ok();
    }
    std::fs::write(&out, json).with_context(|| format!("writing {out}"))?;
    let suffix = if limit > 0 {
        format!(" (limited to {limit} for a subset-first run)")
    } else {
        String::new()
    };
    status!(
        "xtask: wrote {} entr(ies) to {out}{suffix}",
        lock.entries.len()
    );
    Ok(())
}

/// `corpus fetch [--lock <file>] [--out <dir>] [--dry-run] [retry flags]`
pub(crate) fn fetch(args: &[String]) -> Result<()> {
    let lock_path = flag(args, "--lock").unwrap_or_else(|| DEFAULT_LOCK_DIR.to_string());
    let out_dir =
        PathBuf::from(flag(args, "--out").unwrap_or_else(|| DEFAULT_CORPUS_DIR.to_string()));
    let retry = build_retry(args);
    let dry_run = has_flag(args, "--dry-run");

    // `--lock` may be a single shard file or a directory of
    // `corpus.<release>.lock.json` shards (the full-corpus case), which are
    // merged and de-duplicated.
    let path = Path::new(&lock_path);
    let lock = if path.is_dir() {
        CorpusLock::from_dir(path).map_err(|e| anyhow::anyhow!(e))?
    } else {
        let bytes = std::fs::read(path).with_context(|| format!("reading {lock_path}"))?;
        CorpusLock::from_json(&bytes).map_err(|e| anyhow::anyhow!("{lock_path}: {e}"))?
    };
    if lock.entries.is_empty() {
        bail!("no corpus entries found at {lock_path}");
    }

    // Optional targeted scope: `--component <a,b>` (repeatable) and
    // `--platform <p>` (repeatable) restrict the fetch to the archives actually
    // needed, so enriching one library does not pull a whole toolkit. Both the
    // nightly refresh and local re-enrichment rely on this to stay cheap.
    let want_components = collect_filter(args, "--component");
    let want_platforms = collect_filter(args, "--platform");
    let entries: Vec<&cudabom_identify::CorpusEntry> = lock
        .entries
        .iter()
        .filter(|e| want_components.is_empty() || want_components.contains(&e.component))
        .filter(|e| want_platforms.is_empty() || want_platforms.contains(&e.platform))
        .collect();
    if entries.is_empty() {
        bail!("no corpus entries at {lock_path} match the requested --component/--platform filter");
    }

    if dry_run {
        // Plan without touching the network or disk: show exactly what a real
        // run would fetch. This is the subset-first verification step.
        status!(
            "xtask: corpus fetch --dry-run: {} entr(ies) planned into {}",
            entries.len(),
            out_dir.display()
        );
        for entry in &entries {
            let dest = dest_path(&out_dir, entry);
            let state = if dest.exists() {
                "present"
            } else {
                "would fetch"
            };
            status!(
                "  [{state}] {} {} ({}) <- {}",
                entry.component,
                entry.version,
                entry.platform,
                entry.url
            );
        }
        return Ok(());
    }

    std::fs::create_dir_all(&out_dir).with_context(|| format!("creating {}", out_dir.display()))?;

    let total = entries.len();
    let mut fetched = 0usize;
    let mut skipped = 0usize;
    for (index, entry) in entries.iter().enumerate() {
        let position = index + 1;
        let dest = dest_path(&out_dir, entry);
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent).ok();
        }

        // Skip if already present and its digest matches (idempotent, resumable).
        if dest.exists() {
            let existing = std::fs::read(&dest).unwrap_or_default();
            if cudabom_fetch::verify_sha256(&existing, &entry.sha256).is_ok() {
                skipped += 1;
                detail!(
                    "xtask: [{position}/{total}] present {} {} ({})",
                    entry.component,
                    entry.version,
                    entry.platform
                );
                continue;
            }
        }

        let options = get_options(retry, Some(entry.sha256.clone()));
        status!(
            "xtask: [{position}/{total}] fetching {} {} ({})",
            entry.component,
            entry.version,
            entry.platform
        );
        detail!("xtask:            <- {}", entry.url);
        let body = cudabom_fetch::get(&entry.url, &options)
            .with_context(|| format!("fetching {}", entry.url))?;
        std::fs::write(&dest, &body).with_context(|| format!("writing {}", dest.display()))?;
        fetched += 1;
    }

    status!(
        "xtask: corpus fetch complete: {fetched} downloaded, {skipped} already present in {}",
        out_dir.display()
    );
    Ok(())
}

/// The on-disk destination for a corpus entry:
/// `<out>/<component>/<version>/<platform>/<archive-file-name>`.
fn dest_path(out_dir: &Path, entry: &cudabom_identify::CorpusEntry) -> PathBuf {
    corpus_archive_path(
        out_dir,
        &entry.component,
        &entry.version,
        &entry.platform,
        &archive_file_name(&entry.url),
    )
}

/// The single corpus layout both `corpus fetch` (write) and `fingerprints
/// build` (read) use: `<root>/<component>/<version>/<platform>/<file-name>`.
/// Defined once so the writer and reader cannot drift and silently miss every
/// archive.
pub(crate) fn corpus_archive_path(
    root: &Path,
    component: &str,
    version: &str,
    platform: &str,
    file_name: &str,
) -> PathBuf {
    root.join(component)
        .join(version)
        .join(platform)
        .join(file_name)
}

/// Build the retry policy from `--no-retry` / `--max-retries` / `--retry-base-ms`.
pub(crate) fn build_retry(args: &[String]) -> RetryPolicy {
    if has_flag(args, "--no-retry") {
        return RetryPolicy::none();
    }
    let mut policy = RetryPolicy::default();
    if let Some(n) = flag(args, "--max-retries").and_then(|s| s.parse::<u32>().ok()) {
        policy.max_attempts = n.max(1);
    }
    if let Some(ms) = flag(args, "--retry-base-ms").and_then(|s| s.parse::<u64>().ok()) {
        policy.base = Duration::from_millis(ms);
    }
    policy
}

/// Download options for a corpus request. Centralizes the fixed `USER_AGENT`
/// and empty header set so every call site differs only in retry policy and the
/// optional expected digest.
pub(crate) fn get_options(retry: RetryPolicy, expected_sha256: Option<String>) -> GetOptions {
    GetOptions {
        retry,
        expected_sha256,
        user_agent: USER_AGENT.to_string(),
        headers: Vec::new(),
    }
}

/// Collect repeated/comma-separated values for a flag (e.g. `--component a,b`
/// `--component c`), returning an empty set when the flag is absent; the
/// caller treats empty as "no filter" (fetch everything). Values are trimmed
/// for stable matching against lock entry fields.
fn collect_filter(args: &[String], flag_name: &str) -> std::collections::BTreeSet<String> {
    let mut out = std::collections::BTreeSet::new();
    let mut i = 0;
    while i < args.len() {
        if args[i] == flag_name {
            if let Some(v) = args.get(i + 1) {
                for part in v.split(',') {
                    let p = part.trim();
                    if !p.is_empty() {
                        out.insert(p.to_string());
                    }
                }
                i += 2;
                continue;
            }
        }
        i += 1;
    }
    out
}

/// Collect all `--platform <p>` values; default to the full set of CUDA Linux
/// platforms NVIDIA publishes redistributables for. Covering non-x86_64 here
/// means the derived fingerprint DB carries exact inner-`.so` hashes for
/// aarch64 (sbsa) and ppc64le too, so scans of those binaries match `Exact`
/// instead of degrading to a structural `Likely`. `lock_from_manifest` filters
/// to the platforms a given release actually ships, so requesting a platform a
/// release lacks is harmless.
fn collect_platforms(args: &[String]) -> Vec<String> {
    let platforms = crate::repeated_flag(args, "--platform");
    if platforms.is_empty() {
        DEFAULT_PLATFORMS.iter().map(|p| (*p).to_string()).collect()
    } else {
        platforms
    }
}

/// The archive file name (last path segment) of a URL.
pub(crate) fn archive_file_name(url: &str) -> String {
    url.rsplit('/')
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or("archive")
        .to_string()
}

/// `corpus discover [--product <name>|all] [--base-url <url>] [--fixtures <dir>]
/// [--out <dir>] [--fingerprints <dir>] [--platform <p> ...] [--limit N]
/// [--json] [--dry-run] [retry flags]`
///
/// Enumerate the redist manifests NVIDIA actually publishes, diff them against
/// what is already committed, and (unless `--dry-run`) fetch the manifest and
/// write a lockfile for each *new* release. This is the first-party,
/// no-hardcoded-versions discovery step: NVIDIA serves an auto-generated
/// directory index at each redist root, so the set of releases is read straight
/// from the source rather than maintained by hand.
///
/// Scope:
///   - default / `--product all`: iterate every tree in [`REDIST_PRODUCTS`]
///     (CUDA toolkit + cuDNN, NCCL, cuTENSOR, cuDSS, cuSPARSELt, cuQuantum,
///     nvJPEG2000, nvTIFF, cuBLASMp, NVPL, NVSHMEM, nvCOMP).
///   - `--product <name>`: just that tree.
///   - `--base-url <url>`: a single explicit tree (overrides product selection;
///     uses the root fixtures/shard paths unless `--fixtures`/`--fingerprints`
///     are given). Kept for ad-hoc/smoke runs.
pub(crate) fn discover(args: &[String]) -> Result<()> {
    let platforms = collect_platforms(args);
    let platform_refs: Vec<&str> = platforms.iter().map(String::as_str).collect();
    let retry = build_retry(args);
    let dry_run = has_flag(args, "--dry-run");
    let emit_json = has_flag(args, "--json");
    let limit = flag(args, "--limit")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(0);

    let fixtures_root =
        PathBuf::from(flag(args, "--fixtures").unwrap_or_else(|| DEFAULT_FIXTURES_DIR.to_string()));
    let lock_out =
        PathBuf::from(flag(args, "--out").unwrap_or_else(|| DEFAULT_LOCK_DIR.to_string()));

    // Resolve the set of trees to discover.
    let targets = resolve_targets(args)?;

    // Accumulate per-product JSON summaries so `--json` emits one object keyed
    // by product (the refresh workflow sums across them).
    let mut per_product_json: Vec<(String, String)> = Vec::new();
    let mut total_new = 0usize;

    for product in &targets {
        let fixtures_dir = if product.fixtures_subdir.is_empty() {
            fixtures_root.clone()
        } else {
            fixtures_root.join(product.fixtures_subdir)
        };
        let shards_dir = PathBuf::from(product.shard_dir);
        // Per-product lockfiles live in a subdir so `corpus.<label>.lock.json`
        // files from different products never collide (NCCL and cuDNN can share
        // a numeric label space). The cuda tree keeps the lock root for
        // backward compatibility.
        let product_lock_out = if product.name == "cuda" {
            lock_out.clone()
        } else {
            lock_out.join(product.name)
        };

        let summary = discover_one(
            product,
            &fixtures_dir,
            &product_lock_out,
            &shards_dir,
            &platform_refs,
            &platforms,
            retry,
            limit,
            dry_run,
            emit_json,
        )?;
        total_new += summary.new_count;
        if emit_json {
            per_product_json.push((product.name.to_string(), summary.json));
        }
    }

    if emit_json {
        let objs: Vec<String> = per_product_json
            .iter()
            .map(|(name, json)| format!("{name:?}:{json}"))
            .collect();
        println!("{{{}}}", objs.join(","));
    } else if total_new == 0 {
        status!("xtask: all redist trees are up to date with NVIDIA's indexes");
    } else if !dry_run {
        status!(
            "xtask: discover complete: {total_new} new release(s) across {} tree(s). Next: \
             `cargo xtask corpus fetch` then `cargo xtask fingerprints build`.",
            targets.len()
        );
    }
    Ok(())
}

/// Resolve which product trees to discover from the arguments.
///
/// `--base-url <url>` yields a single ad-hoc product (root paths, overridable).
/// `--product <name>` selects one named tree; `all` (or omitted) selects every
/// tree in [`REDIST_PRODUCTS`].
fn resolve_targets(args: &[String]) -> Result<Vec<RedistProduct>> {
    if let Some(url) = flag(args, "--base-url") {
        // Ad-hoc single tree. Leak the URL to obtain a 'static str so it fits
        // the RedistProduct shape; this runs once per invocation in a
        // short-lived CLI, so the leak is immaterial.
        let base_url: &'static str = Box::leak(url.into_boxed_str());
        return Ok(vec![RedistProduct {
            name: "cuda",
            fixtures_subdir: "",
            shard_dir: DEFAULT_SHARD_DIR,
            base_url_override: Some(base_url),
        }]);
    }
    match flag(args, "--product").as_deref() {
        None | Some("all") => Ok(REDIST_PRODUCTS.to_vec()),
        Some(name) => {
            let found = REDIST_PRODUCTS.iter().find(|p| p.name == name).copied();
            found.map(|p| vec![p]).ok_or_else(|| {
                let names: Vec<&str> = REDIST_PRODUCTS.iter().map(|p| p.name).collect();
                anyhow::anyhow!("unknown --product {name:?}; known: {}", names.join(", "))
            })
        }
    }
}

/// The outcome of discovering one product tree.
struct DiscoverSummary {
    new_count: usize,
    /// Machine-readable summary (the `{published,committed,new}` object).
    json: String,
}

/// Discover one product tree: fetch its index, diff against committed releases,
/// and (unless dry-run) fetch+lock the new releases.
#[allow(clippy::too_many_arguments)]
fn discover_one(
    product: &RedistProduct,
    fixtures_dir: &Path,
    lock_out: &Path,
    shards_dir: &Path,
    platform_refs: &[&str],
    platforms: &[String],
    retry: RetryPolicy,
    limit: usize,
    dry_run: bool,
    emit_json: bool,
) -> Result<DiscoverSummary> {
    let base_url = product.base_url();

    // 1. Read NVIDIA's directory index and extract every published manifest.
    if !emit_json {
        status!(
            "xtask: [{}] discovering redist manifests from {base_url}",
            product.name
        );
    }
    let index_body = cudabom_fetch::get(&base_url, &get_options(retry, None))
        .with_context(|| format!("fetching redist index {base_url}"))?;
    let index_text = String::from_utf8_lossy(&index_body);
    let published = parse_manifest_names(&index_text);
    if published.is_empty() {
        bail!("no redistrib_*.json entries found at {base_url} (index format changed?)");
    }

    // 2. Diff against the releases we have already evaluated. A release counts
    //    as known if a derived shard exists (rich release) or its manifest is
    //    saved (thin release with no profiled components); so thin early
    //    releases are not rediscovered on every run.
    let known = evaluated_releases(shards_dir, fixtures_dir);
    let mut new_releases: Vec<String> = published
        .iter()
        .filter(|v| !known.contains(*v))
        .cloned()
        .collect();
    new_releases.sort_by(|a, b| compare_versions(a, b));
    if limit > 0 && new_releases.len() > limit {
        new_releases.truncate(limit);
    }

    let json = discover_json(&published, &known, &new_releases);
    if !emit_json {
        status!(
            "xtask: [{}] {} published, {} already committed, {} new",
            product.name,
            published.len(),
            known.len(),
            new_releases.len()
        );
        for v in &new_releases {
            status!("  new: {v}");
        }
    }

    let new_count = new_releases.len();
    if new_count == 0 || dry_run {
        return Ok(DiscoverSummary { new_count, json });
    }

    // 3. For each new release, fetch its manifest, save it as a fixture, and
    //    write a per-release lockfile so `corpus fetch` can retrieve archives.
    std::fs::create_dir_all(fixtures_dir)
        .with_context(|| format!("creating {}", fixtures_dir.display()))?;
    std::fs::create_dir_all(lock_out)
        .with_context(|| format!("creating {}", lock_out.display()))?;

    fetch_and_lock_new(
        &new_releases,
        &base_url,
        fixtures_dir,
        lock_out,
        platform_refs,
        platforms,
        retry,
    )?;

    Ok(DiscoverSummary { new_count, json })
}

/// Fetch each new release's manifest, save it as a fixture, and write a
/// per-release lockfile so `corpus fetch` can retrieve its archives. Extracted
/// from `discover` to keep that function focused on the discover/diff decision.
#[allow(clippy::too_many_arguments)]
fn fetch_and_lock_new(
    new_releases: &[String],
    base_url: &str,
    fixtures_dir: &Path,
    lock_out: &Path,
    platform_refs: &[&str],
    platforms: &[String],
    retry: RetryPolicy,
) -> Result<()> {
    let total = new_releases.len();
    for (index, version) in new_releases.iter().enumerate() {
        let position = index + 1;
        let manifest_url = format!(
            "{}/redistrib_{version}.json",
            base_url.trim_end_matches('/')
        );
        status!("xtask: [{position}/{total}] fetching manifest {version}");
        detail!("xtask:            <- {manifest_url}");
        let bytes = cudabom_fetch::get(&manifest_url, &get_options(retry, None))
            .with_context(|| format!("fetching manifest {manifest_url}"))?;

        // Validate it parses as a manifest before writing anything.
        let manifest = RedistManifest::from_json(&bytes)
            .map_err(|e| anyhow::anyhow!("{manifest_url}: {e}"))?;

        let fixture_path = fixtures_dir.join(format!("redistrib_{version}.json"));
        std::fs::write(&fixture_path, &bytes)
            .with_context(|| format!("writing {}", fixture_path.display()))?;

        let lock = lock_from_manifest(&manifest, base_url, platform_refs, resolve_component);
        if lock.entries.is_empty() {
            detail!("xtask:   {version}: no profiled components for {platforms:?}; manifest saved");
            continue;
        }
        let lock_path = lock_out.join(format!("corpus.{version}.lock.json"));
        let json = lock.to_json().map_err(|e| anyhow::anyhow!(e))?;
        std::fs::write(&lock_path, json)
            .with_context(|| format!("writing {}", lock_path.display()))?;
        detail!(
            "xtask:   {version}: {} lock entr(ies) -> {}",
            lock.entries.len(),
            lock_path.display()
        );
    }
    Ok(())
}

/// Extract every `redistrib_<label>.json` file name from NVIDIA's directory
/// index, returning the sorted, de-duplicated set of label strings.
///
/// The index is an auto-generated HTML listing; rather than parse HTML, this
/// scans for the well-known manifest file-name pattern, which is stable and
/// unambiguous. Nothing about the label is inferred: only names that literally
/// appear are taken.
///
/// Two label shapes occur across the redist trees:
///   - Plain dotted version: `redistrib_12.6.3.json` (CUDA toolkit, cuDNN,
///     cuTENSOR, and most products) → label `12.6.3`.
///   - CUDA-qualified: `redistrib_2.30.7-cuda12.9.json` (NCCL, which publishes
///     one manifest per NCCL×CUDA pairing) → label `2.30.7-cuda12.9`. The full
///     stem is kept as the label because it is what the manifest URL, fixture
///     name, and lockfile key use; the `-cuda<X.Y>` part is not stripped.
fn parse_manifest_names(index_text: &str) -> Vec<String> {
    const PREFIX: &str = "redistrib_";
    const SUFFIX: &str = ".json";
    let mut versions = std::collections::BTreeSet::new();
    let bytes = index_text.as_bytes();
    let mut search_from = 0;
    while let Some(rel) = index_text[search_from..].find(PREFIX) {
        let start = search_from + rel + PREFIX.len();
        // A label is dot-separated digits, optionally followed by a single
        // `-cuda<dotted-digits>` qualifier (NCCL). Read the leading dotted
        // version, then, if a `-cuda` qualifier follows, consume it and its
        // trailing dotted digits as one unit. Nothing else extends the label,
        // so unrelated hyphens or letters never leak in.
        let mut end = start;
        // 1. Leading dotted-digit version.
        while end < bytes.len() {
            let is_digit = bytes[end].is_ascii_digit();
            let is_inner_dot =
                bytes[end] == b'.' && end + 1 < bytes.len() && bytes[end + 1].is_ascii_digit();
            if is_digit || is_inner_dot {
                end += 1;
            } else {
                break;
            }
        }
        // 2. Optional `-cuda<dotted-digits>` qualifier.
        if index_text[end..].starts_with("-cuda") {
            let after = end + "-cuda".len();
            // Require at least one digit after `-cuda` to accept the qualifier.
            if after < bytes.len() && bytes[after].is_ascii_digit() {
                end = after;
                while end < bytes.len() {
                    let is_digit = bytes[end].is_ascii_digit();
                    let is_inner_dot = bytes[end] == b'.'
                        && end + 1 < bytes.len()
                        && bytes[end + 1].is_ascii_digit();
                    if is_digit || is_inner_dot {
                        end += 1;
                    } else {
                        break;
                    }
                }
            }
        }
        let version = &index_text[start..end];
        // Require the exact `.json` suffix immediately after the label so we do
        // not pick up unrelated occurrences, and require it to start with a
        // digit so a stray `redistrib_cuda...` cannot match.
        if !version.is_empty()
            && version.as_bytes()[0].is_ascii_digit()
            && index_text[end..].starts_with(SUFFIX)
        {
            versions.insert(version.to_string());
        }
        search_from = start;
    }
    versions.into_iter().collect()
}

/// The set of releases we have already evaluated, so discover does not keep
/// re-fetching them forever. A release counts as evaluated if either a derived
/// shard exists (`shards_dir/redistrib_<ver>.json`, the rich case) **or** its
/// manifest fixture is saved (`fixtures_dir/redistrib_<ver>.json`). The latter
/// is essential for early redist releases (11.0-11.3) that ship only datacenter
/// management pieces and no profiled CUDA libraries: they produce no shard, so
/// without counting the saved manifest they would appear "new" on every run.
fn evaluated_releases(
    shards_dir: &Path,
    fixtures_dir: &Path,
) -> std::collections::BTreeSet<String> {
    let mut out = std::collections::BTreeSet::new();
    for dir in [shards_dir, fixtures_dir] {
        let Ok(read) = std::fs::read_dir(dir) else {
            continue; // not yet populated
        };
        for entry in read.filter_map(std::result::Result::ok) {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if let Some(rest) = name.strip_prefix("redistrib_") {
                if let Some(version) = rest.strip_suffix(".json") {
                    out.insert(version.to_string());
                }
            }
        }
    }
    out
}

/// Compare two redist labels (e.g. `12.6.3` vs `12.10.0`, or NCCL's
/// `2.30.7-cuda12.9`) for ordering. The leading dotted-numeric version is
/// compared component-wise and numerically; a trailing `-cuda<X.Y>` qualifier
/// is compared after, so NCCL manifests order by NCCL version first then CUDA
/// pairing. Non-numeric fragments sort as 0, which only affects display order.
fn compare_versions(a: &str, b: &str) -> std::cmp::Ordering {
    // Split a label into (version, cuda-qualifier) and parse each dotted run
    // into numeric components for value-ordering.
    let parts = |s: &str| -> (Vec<u64>, Vec<u64>) {
        let (ver, cuda) = match s.split_once("-cuda") {
            Some((v, c)) => (v, c),
            None => (s, ""),
        };
        let nums = |t: &str| -> Vec<u64> {
            if t.is_empty() {
                Vec::new()
            } else {
                t.split('.').map(|p| p.parse().unwrap_or(0)).collect()
            }
        };
        (nums(ver), nums(cuda))
    };
    let (av, ac) = parts(a);
    let (bv, bc) = parts(b);
    av.cmp(&bv).then_with(|| ac.cmp(&bc))
}

/// Render the machine-readable discover summary consumed by CI.
fn discover_json(
    published: &[String],
    known: &std::collections::BTreeSet<String>,
    new_releases: &[String],
) -> String {
    let arr = |items: &[String]| {
        let quoted: Vec<String> = items.iter().map(|v| format!("{v:?}")).collect();
        format!("[{}]", quoted.join(","))
    };
    let known_vec: Vec<String> = known.iter().cloned().collect();
    format!(
        "{{\"published\":{},\"committed\":{},\"new\":{}}}",
        arr(published),
        arr(&known_vec),
        arr(new_releases)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_manifest_names_extracts_versions_from_index_html() {
        // A trimmed sample shaped like NVIDIA's auto-generated directory index.
        let html = r"
            <li><a href='redistrib_11.8.0.json'>redistrib_11.8.0.json</a></li>
            <li><a href='redistrib_12.6.3.json'>redistrib_12.6.3.json</a></li>
            <li><a href='redistrib_13.0.0.json'>redistrib_13.0.0.json</a></li>
            <li><a href='style.css'>style.css</a></li>
        ";
        let got = parse_manifest_names(html);
        assert_eq!(got, vec!["11.8.0", "12.6.3", "13.0.0"]);
    }

    #[test]
    fn parse_manifest_names_ignores_non_manifest_matches() {
        // `redistrib_` appearing without the `.json` suffix must not be taken.
        let html = "redistrib_12.4 something redistrib_12.4.1.json";
        assert_eq!(parse_manifest_names(html), vec!["12.4.1"]);
    }

    #[test]
    fn parse_manifest_names_accepts_nccl_cuda_qualified_labels() {
        // NCCL publishes one manifest per NCCL×CUDA pairing; the `-cuda<X.Y>`
        // qualifier is part of the label and must be preserved.
        let html = r"
            <a href='redistrib_2.30.7-cuda12.9.json'>redistrib_2.30.7-cuda12.9.json</a>
            <a href='redistrib_2.30.7-cuda13.2.json'>redistrib_2.30.7-cuda13.2.json</a>
            <a href='redistrib_12.6.3.json'>redistrib_12.6.3.json</a>
        ";
        let got = parse_manifest_names(html);
        assert_eq!(got, vec!["12.6.3", "2.30.7-cuda12.9", "2.30.7-cuda13.2"]);
    }

    #[test]
    fn parse_manifest_names_requires_digit_after_cuda_qualifier() {
        // A malformed `-cuda` without digits must not extend the label; the
        // plain version is kept and the stray suffix rejected (no `.json` match
        // on the bare version here, so nothing is taken).
        let html = "redistrib_2.30.7-cudaX.json";
        assert_eq!(parse_manifest_names(html), Vec::<String>::new());
    }

    #[test]
    fn parse_manifest_names_dedups() {
        let html = "redistrib_12.4.1.json redistrib_12.4.1.json";
        assert_eq!(parse_manifest_names(html), vec!["12.4.1"]);
    }

    #[test]
    fn compare_versions_orders_numerically_not_lexically() {
        // Lexical order would put 12.10.0 before 12.9.0; numeric must not.
        let mut v = vec![
            "12.9.0".to_string(),
            "12.10.0".to_string(),
            "12.6.3".to_string(),
        ];
        v.sort_by(|a, b| compare_versions(a, b));
        assert_eq!(v, vec!["12.6.3", "12.9.0", "12.10.0"]);
    }

    #[test]
    fn compare_versions_orders_nccl_cuda_qualified_labels() {
        // NCCL version compared first, then the CUDA pairing.
        let mut v = vec![
            "2.30.7-cuda13.2".to_string(),
            "2.30.7-cuda12.9".to_string(),
            "2.29.3-cuda13.1".to_string(),
        ];
        v.sort_by(|a, b| compare_versions(a, b));
        assert_eq!(
            v,
            vec!["2.29.3-cuda13.1", "2.30.7-cuda12.9", "2.30.7-cuda13.2"]
        );
    }

    #[test]
    fn evaluated_releases_reads_shard_and_manifest_names() {
        let base = std::env::temp_dir().join(format!(
            "cudabom-discover-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        let shards = base.join("shards");
        let fixtures = base.join("fixtures");
        std::fs::create_dir_all(&shards).unwrap();
        std::fs::create_dir_all(&fixtures).unwrap();
        // A rich release derived to a shard, and a thin release with only a
        // saved manifest (no shard): both must count as evaluated.
        std::fs::write(shards.join("redistrib_12.4.1.json"), "{}").unwrap();
        std::fs::write(fixtures.join("redistrib_11.0.3.json"), "{}").unwrap();
        std::fs::write(shards.join("README.md"), "ignore me").unwrap();

        let got = evaluated_releases(&shards, &fixtures);
        assert!(got.contains("12.4.1"), "rich shard counts");
        assert!(got.contains("11.0.3"), "thin saved manifest counts");
        assert_eq!(got.len(), 2);

        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn discover_json_shape_is_stable() {
        let published = vec!["11.8.0".to_string(), "12.4.1".to_string()];
        let mut known = std::collections::BTreeSet::new();
        known.insert("11.8.0".to_string());
        let new_releases = vec!["12.4.1".to_string()];
        let json = discover_json(&published, &known, &new_releases);
        assert_eq!(
            json,
            r#"{"published":["11.8.0","12.4.1"],"committed":["11.8.0"],"new":["12.4.1"]}"#
        );
    }
}
