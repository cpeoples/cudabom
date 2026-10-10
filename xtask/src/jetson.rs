//! `cargo xtask jetson discover`: synthesize redist-shaped manifests for
//! NVIDIA Jetson (L4T / JetPack) CUDA packages.
//!
//! Jetson modules run Linux (L4T / JetPack), not Android, and their CUDA stack
//! ships as Debian packages from `https://repo.download.nvidia.com/jetson/`,
//! not as the `.tar.xz` redistributables under
//! `developer.download.nvidia.com/compute/`. The Tegra `aarch64` binaries have
//! distinct build-ids and file hashes from the generic `linux-sbsa`
//! redistributables, so a scan of a real Jetson `libcublas.so` matches only a
//! structural family in the existing corpus, never an exact version.
//!
//! This module closes that gap without inventing anything. NVIDIA publishes a
//! GPG-signed APT index (`dists/<release>/main/binary-arm64/Packages`) that
//! lists, for every CUDA library package, its exact `Version`, pool
//! `Filename`, and `SHA256`. That is the same authoritative shape the redist
//! manifests carry (version <-> archive sha256, straight from NVIDIA), so each
//! JetPack release is turned into a `redistrib_<release>.json` in the exact
//! [`RedistManifest`] shape the rest of the pipeline already consumes:
//!
//!   - the APT `Source` name maps to the existing manifest key by replacing
//!     `-` with `_` (`cuda-cudart` -> `cuda_cudart`, `libcublas` -> `libcublas`),
//!     so `resolve_component` attributes it with no profile-table change;
//!   - the pool `Filename` becomes the archive `relative_path`;
//!   - NVIDIA's `SHA256` becomes the archive `sha256` (the archive layer);
//!   - the platform key is `linux-aarch64-tegra`, distinct from the generic
//!     `linux-aarch64`/`linux-sbsa` platforms so corpus paths never collide.
//!
//! `fingerprints build` then unpacks each `.deb` (see `extract_deb`) and
//! derives the binary layer (build-id + inner-`.so` hash) exactly as it does
//! for the `.tar.xz` redistributables, yielding Tegra-exact fingerprints.

use std::path::PathBuf;

use anyhow::{Context, Result};
use cudabom_identify::{lock_from_manifest, resolve_component, RedistManifest};
use serde_json::{json, Map, Value};

use crate::apt::{manifest_key_for, parse_cuda_library_packages, DebPackage};
use crate::corpus::{build_retry, get_options};
use crate::verbosity::{detail, status};
use crate::{flag, has_flag};

/// The JetPack L4T releases whose APT index publishes CUDA packages: JetPack 5
/// (r35.x) and JetPack 6 (r36.x). A release that serves no CUDA library is
/// skipped at discovery, so a forward-looking entry is harmless; adding a new
/// JetPack is a one-line change here.
const DEFAULT_RELEASES: &[&str] = &["r35.4", "r35.5", "r36.3", "r36.4", "r36.5"];
/// Platform key for Jetson Tegra aarch64 archives. Distinct from the generic
/// `linux-aarch64`/`linux-sbsa` keys so the corpus layout and fingerprints do
/// not collide with the server redistributables.
const JETSON_PLATFORM: &str = "linux-aarch64-tegra";
/// Fixtures subdirectory for synthesized Jetson manifests.
const DEFAULT_FIXTURES_DIR: &str = "fixtures/redist/jetson";
/// Shard and corpus-lock directory for the Jetson tree.
const DEFAULT_SHARD_DIR: &str = "fingerprints/jetson";

/// `jetson discover [--base-url <url>] [--release <r> ...] [--fixtures <dir>]
/// [--out <dir>] [--json] [--dry-run] [retry flags]`
///
/// Fetch each JetPack release's APT `Packages` index, synthesize a
/// redist-shaped manifest of its runtime CUDA library packages, and (unless
/// `--dry-run`) write it under the Jetson fixtures directory so `fingerprints
/// build` can fetch and derive it.
pub(crate) fn discover(args: &[String]) -> Result<()> {
    let base_url = flag(args, "--base-url").unwrap_or_else(crate::sources::jetson_base);
    let releases = collect_releases(args);
    let fixtures_dir =
        PathBuf::from(flag(args, "--fixtures").unwrap_or_else(|| DEFAULT_FIXTURES_DIR.to_string()));
    let lock_dir =
        PathBuf::from(flag(args, "--out").unwrap_or_else(|| DEFAULT_SHARD_DIR.to_string()));
    let dry_run = has_flag(args, "--dry-run");
    let emit_json = has_flag(args, "--json");
    let retry = build_retry(args);

    let mut per_release_json: Vec<(String, usize)> = Vec::new();

    for release in &releases {
        let index_url = format!(
            "{}/common/dists/{release}/main/binary-arm64/Packages",
            base_url.trim_end_matches('/')
        );
        if !emit_json {
            status!("xtask: [jetson {release}] fetching package index {index_url}");
        }
        let body = cudabom_fetch::get(&index_url, &get_options(retry, None))
            .with_context(|| format!("fetching Jetson package index {index_url}"))?;
        let text = String::from_utf8_lossy(&body);

        let packages = parse_cuda_library_packages(&text);
        if packages.is_empty() {
            if !emit_json {
                status!("xtask: [jetson {release}] no CUDA library packages; skipping");
            }
            continue;
        }

        let manifest_json = synthesize_manifest(release, &packages)?;

        if !emit_json {
            status!(
                "xtask: [jetson {release}] {} runtime CUDA library package(s)",
                packages.len()
            );
            for p in &packages {
                detail!(
                    "xtask:   {} {} -> {}",
                    p.source,
                    p.version,
                    manifest_key_for(&p.source)
                );
            }
        }
        per_release_json.push((release.clone(), packages.len()));

        if dry_run {
            continue;
        }

        std::fs::create_dir_all(&fixtures_dir)
            .with_context(|| format!("creating {}", fixtures_dir.display()))?;
        let out_path = fixtures_dir.join(format!("redistrib_{release}.json"));
        std::fs::write(&out_path, &manifest_json)
            .with_context(|| format!("writing {}", out_path.display()))?;
        // Validate the synthesized manifest round-trips through the real parser,
        // so a shape bug is caught here rather than during the build.
        let manifest = RedistManifest::from_json(manifest_json.as_bytes())
            .map_err(|e| anyhow::anyhow!("synthesized {}: {e}", out_path.display()))?;
        if !emit_json {
            status!("xtask: [jetson {release}] wrote {}", out_path.display());
        }

        // Write a corpus lockfile so `corpus fetch` can retrieve the `.deb`
        // archives. The pool `Filename` is relative to `<base>/common`, and the
        // Tegra archives are keyed under the `linux-aarch64-tegra` platform.
        let lock_base = format!("{}/common", base_url.trim_end_matches('/'));
        let lock = lock_from_manifest(&manifest, &lock_base, &[JETSON_PLATFORM], resolve_component);
        if !lock.entries.is_empty() {
            std::fs::create_dir_all(&lock_dir)
                .with_context(|| format!("creating {}", lock_dir.display()))?;
            let lock_path = lock_dir.join(format!("corpus.{release}.lock.json"));
            let lock_json = lock.to_json().map_err(|e| anyhow::anyhow!(e))?;
            std::fs::write(&lock_path, lock_json)
                .with_context(|| format!("writing {}", lock_path.display()))?;
            if !emit_json {
                status!(
                    "xtask: [jetson {release}] wrote {} lock entr(ies) -> {}",
                    lock.entries.len(),
                    lock_path.display()
                );
            }
        }
    }

    if emit_json {
        let objs: Vec<String> = per_release_json
            .iter()
            .map(|(r, n)| format!("{r:?}:{n}"))
            .collect();
        println!("{{{}}}", objs.join(","));
    } else if !dry_run {
        status!(
            "xtask: jetson discover complete. Next: `cargo xtask fingerprints build --from {} --out {}`",
            fixtures_dir.display(),
            DEFAULT_SHARD_DIR
        );
    }
    Ok(())
}

/// Build a `redistrib_<release>.json` body in the [`RedistManifest`] shape from
/// the parsed packages. Each package becomes a component keyed by its
/// normalized manifest key, carrying one `linux-aarch64-tegra` archive with
/// NVIDIA's own pool path and sha256.
fn synthesize_manifest(release: &str, packages: &[DebPackage]) -> Result<String> {
    let mut manifest = Map::new();
    manifest.insert("release_label".into(), json!(release));
    manifest.insert("release_product".into(), json!("jetson"));

    for p in packages {
        let mut archive = Map::new();
        archive.insert("relative_path".into(), json!(p.filename));
        archive.insert("sha256".into(), json!(p.sha256));
        if let Some(size) = p.size {
            // Manifests publish size as a string of bytes, matching NVIDIA's.
            archive.insert("size".into(), json!(size.to_string()));
        }
        let component = json!({
            "version": p.version,
            JETSON_PLATFORM: Value::Object(archive),
        });
        manifest.insert(manifest_key_for(&p.source), component);
    }

    let mut json = serde_json::to_string_pretty(&Value::Object(manifest))
        .context("serializing synthesized Jetson manifest")?;
    json.push('\n');
    Ok(json)
}

/// The releases to discover: `--release <r>` values, or [`DEFAULT_RELEASES`].
fn collect_releases(args: &[String]) -> Vec<String> {
    let releases = crate::repeated_flag(args, "--release");
    if releases.is_empty() {
        DEFAULT_RELEASES.iter().map(|r| (*r).to_string()).collect()
    } else {
        releases
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "Package: libcublas-12-6\n\
Source: libcublas\n\
Version: 12.6.1.4-1\n\
Architecture: arm64\n\
Provides: libcublas.so.12 (= 12.6.1.4)\n\
Filename: pool/main/libc/libcublas/libcublas-12-6_12.6.1.4-1_arm64.deb\n\
Size: 218073004\n\
SHA256: 3ff5d9c20e8cf1b8fd36841271846f2d2de23aaca9bf2e9213d5dac8e6488693\n\
Description: CUBLAS native runtime libraries\n\
 CUBLAS native runtime libraries\n\
\n\
Package: cuda-cudart-12-6\n\
Source: cuda-cudart\n\
Version: 12.6.68-1\n\
Provides: libcudart.so.12 (= 12.6.68)\n\
Filename: pool/main/c/cuda-cudart/cuda-cudart-12-6_12.6.68-1_arm64.deb\n\
SHA256: AABBCCDD\n";

    #[test]
    fn synthesized_manifest_parses_as_a_redist_manifest() {
        let pkgs = parse_cuda_library_packages(SAMPLE);
        let json = synthesize_manifest("r36.4", &pkgs).unwrap();
        let manifest = RedistManifest::from_json(json.as_bytes())
            .expect("synthesized manifest must parse as a redist manifest");
        assert_eq!(manifest.release_label.as_deref(), Some("r36.4"));
        // cuda-cudart -> cuda_cudart key, with a tegra archive carrying the hash.
        let cudart = &manifest.components["cuda_cudart"];
        assert_eq!(cudart.version, "12.6.68");
        let archive = &cudart.archives[JETSON_PLATFORM];
        assert_eq!(archive.sha256, "aabbccdd");
        assert!(archive
            .relative_path
            .ends_with("cuda-cudart-12-6_12.6.68-1_arm64.deb"));
    }
}
