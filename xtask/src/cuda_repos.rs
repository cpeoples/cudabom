//! `cargo xtask cuda-repos discover`: synthesize redist-shaped manifests for
//! NVIDIA's per-distro CUDA package repositories.
//!
//! Besides the `.tar.xz` redistributables under
//! `developer.download.nvidia.com/compute/<product>/redist/`, NVIDIA ships the
//! same CUDA libraries as per-distro `.deb` / `.rpm` packages under
//! `compute/cuda/repos/<distro>/<arch>/`. Those are separately built binaries
//! with their own build-ids and inner-`.so` hashes, so a scan of a library
//! pulled from, say, an Ubuntu or RHEL CUDA install matches only a structural
//! family in the redist corpus, never an exact version. This closes that gap
//! the same way the Jetson task does: parse NVIDIA's own package index and
//! synthesize `redistrib_*.json` manifests the existing pipeline already
//! consumes.
//!
//! The APT distros (Ubuntu, Debian, WSL) are read through the shared `Packages`
//! parser ([`crate::apt`]); the RPM distros (RHEL, Fedora, SLES, ...) through
//! the `repodata`/`primary.xml` parser ([`crate::rpm`]). Both yield the same
//! package shape, so one dedup-and-synthesize path serves both formats.
//!
//! Content addressing: the same CUDA archive is frequently byte-identical
//! across distros and releases. Discovery records each distinct archive sha256
//! once (first distro/arch that ships it), so identical binaries are fetched
//! and derived a single time rather than once per distro.

use std::collections::HashSet;
use std::path::PathBuf;

use anyhow::{Context, Result};
use cudabom_identify::{lock_from_manifest, resolve_component, RedistManifest};
use serde_json::{json, Map, Value};

use crate::apt::{manifest_key_for, DebPackage};
use crate::corpus::{build_retry, get_options};
use crate::verbosity::{detail, status};
use crate::{flag, has_flag};

/// The package format a distro's repo uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Format {
    /// Debian APT: a `Packages` index of `.deb`s.
    Apt,
    /// YUM/DNF: `repodata/repomd.xml` -> `primary.xml` of `.rpm`s.
    Rpm,
}

/// A distro target in the `cuda/repos` channel: the `<distro>` path segment,
/// its package format, and the architecture subdirectories it publishes.
#[allow(clippy::struct_field_names)]
struct Distro {
    /// Path segment under `compute/cuda/repos/` (e.g. `ubuntu2404`).
    distro: &'static str,
    /// Package index format.
    format: Format,
    /// Architecture subdirectories to scan (e.g. `x86_64`, `sbsa`, `arm64`).
    arches: &'static [&'static str],
}

/// The distros NVIDIA publishes CUDA packages for under `compute/cuda/repos/`.
/// APT distros serve a Debian `Packages` index; RPM distros serve
/// `repodata/repomd.xml`. The arch set is per-distro because older targets
/// predate `sbsa`/`arm64`, and a `<distro>/<arch>` that does not exist is
/// skipped at discovery. Adding a distro or arch is a one-line change here.
const DISTROS: &[Distro] = &[
    // APT: Debian, Ubuntu, WSL.
    Distro {
        distro: "ubuntu2004",
        format: Format::Apt,
        arches: &["x86_64", "sbsa", "cross-linux-sbsa"],
    },
    Distro {
        distro: "ubuntu2204",
        format: Format::Apt,
        arches: &["x86_64", "sbsa", "cross-linux-sbsa"],
    },
    Distro {
        distro: "ubuntu2404",
        format: Format::Apt,
        arches: &[
            "x86_64",
            "sbsa",
            "arm64",
            "cross-linux-sbsa",
            "cross-linux-aarch64",
        ],
    },
    Distro {
        distro: "ubuntu2604",
        format: Format::Apt,
        arches: &["x86_64", "sbsa", "arm64"],
    },
    Distro {
        distro: "debian11",
        format: Format::Apt,
        arches: &["x86_64"],
    },
    Distro {
        distro: "debian12",
        format: Format::Apt,
        arches: &["x86_64", "sbsa"],
    },
    Distro {
        distro: "debian13",
        format: Format::Apt,
        arches: &["x86_64", "sbsa"],
    },
    Distro {
        distro: "wsl-ubuntu",
        format: Format::Apt,
        arches: &["x86_64"],
    },
    // RPM: RHEL, Fedora, SLES, openSUSE, Amazon, Azure, Kylin.
    Distro {
        distro: "rhel8",
        format: Format::Rpm,
        arches: &["x86_64", "sbsa", "cross-linux-sbsa"],
    },
    Distro {
        distro: "rhel9",
        format: Format::Rpm,
        arches: &["x86_64", "sbsa", "cross-linux-sbsa"],
    },
    Distro {
        distro: "rhel10",
        format: Format::Rpm,
        arches: &["x86_64", "sbsa", "aarch64"],
    },
    Distro {
        distro: "fedora41",
        format: Format::Rpm,
        arches: &["x86_64"],
    },
    Distro {
        distro: "fedora42",
        format: Format::Rpm,
        arches: &["x86_64"],
    },
    Distro {
        distro: "sles15",
        format: Format::Rpm,
        arches: &["x86_64", "sbsa"],
    },
    Distro {
        distro: "opensuse15",
        format: Format::Rpm,
        arches: &["x86_64"],
    },
    Distro {
        distro: "amzn2023",
        format: Format::Rpm,
        arches: &["x86_64", "sbsa"],
    },
    Distro {
        distro: "azl3",
        format: Format::Rpm,
        arches: &["x86_64"],
    },
    Distro {
        distro: "kylin10",
        format: Format::Rpm,
        arches: &["x86_64", "sbsa"],
    },
];

/// Fixtures subdirectory for synthesized per-distro manifests.
const DEFAULT_FIXTURES_DIR: &str = "fixtures/redist/cuda-repos";
/// Shard and corpus-lock directory for the per-distro repos tree.
const DEFAULT_SHARD_DIR: &str = "fingerprints/cuda-repos";

/// `cuda-repos discover [--base-url <url>] [--distro <d> ...] [--arch <a> ...]
/// [--fixtures <dir>] [--out <dir>] [--limit N] [--json] [--dry-run]
/// [retry flags]`
///
/// Fetch each distro/arch package index (APT `Packages` or YUM `repomd.xml`),
/// synthesize a redist-shaped manifest of its runtime CUDA library packages
/// (deduplicated by archive sha256 across the whole run), and (unless
/// `--dry-run`) write it under the repos fixtures directory so `fingerprints
/// build` can fetch and derive it.
// One straight-line fetch/dedup/write loop over the target matrix; splitting it
// would scatter the shared dedup set and per-target logging across helpers for
// no real gain.
#[allow(clippy::too_many_lines)]
pub(crate) fn discover(args: &[String]) -> Result<()> {
    let base_url_override = flag(args, "--base-url");
    let targets = collect_targets(args)?;
    let fixtures_dir =
        PathBuf::from(flag(args, "--fixtures").unwrap_or_else(|| DEFAULT_FIXTURES_DIR.to_string()));
    let lock_dir =
        PathBuf::from(flag(args, "--out").unwrap_or_else(|| DEFAULT_SHARD_DIR.to_string()));
    let limit = flag(args, "--limit")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(0);
    let dry_run = has_flag(args, "--dry-run");
    let emit_json = has_flag(args, "--json");
    let retry = build_retry(args);

    // Content-addressed dedup across the whole run: the same CUDA archive is
    // byte-identical across many distros, so once a sha256 is recorded it is
    // not re-synthesized for another distro/arch.
    let mut seen_sha256: HashSet<String> = HashSet::new();
    let mut per_target_json: Vec<(String, usize)> = Vec::new();
    let mut written = 0usize;

    'targets: for (distro, arch, format) in &targets {
        let base = base_url_override.clone().map_or_else(
            || {
                crate::sources::cuda_repos_base(distro, arch)
                    .trim_end_matches('/')
                    .to_string()
            },
            |u| u.trim_end_matches('/').to_string(),
        );
        let parsed = match fetch_index(&base, *format, retry, emit_json, distro, arch) {
            Ok(Some(pkgs)) => pkgs,
            Ok(None) => continue,
            Err(e) => {
                // A distro/arch that does not publish an index (older targets,
                // arch not offered) is skipped, not fatal: the matrix is a
                // superset and NVIDIA's layout varies by distro age.
                if !emit_json {
                    status!("xtask: [cuda-repos {distro}/{arch}] no index ({e}); skipping");
                }
                continue;
            }
        };

        // Keep only packages whose archive sha256 has not been recorded by an
        // earlier distro/arch this run.
        let mut fresh: Vec<DebPackage> = Vec::new();
        for p in parsed {
            if seen_sha256.insert(p.sha256.clone()) {
                fresh.push(p);
            }
        }
        if fresh.is_empty() {
            if !emit_json {
                status!("xtask: [cuda-repos {distro}/{arch}] no new distinct packages; skipping");
            }
            continue;
        }

        if !emit_json {
            status!(
                "xtask: [cuda-repos {distro}/{arch}] {} new distinct runtime package(s)",
                fresh.len()
            );
            for p in &fresh {
                detail!(
                    "xtask:   {} {} -> {}",
                    p.source,
                    p.version,
                    manifest_key_for(&p.source)
                );
            }
        }
        per_target_json.push((format!("{distro}/{arch}"), fresh.len()));

        if dry_run {
            if limit > 0 && per_target_json.len() >= limit {
                break 'targets;
            }
            continue;
        }

        let platform = format!("linux-{arch}-{distro}");
        let release = format!("{distro}-{arch}");
        let manifest_json = synthesize_manifest(&release, &platform, &fresh)?;

        std::fs::create_dir_all(&fixtures_dir)
            .with_context(|| format!("creating {}", fixtures_dir.display()))?;
        let out_path = fixtures_dir.join(format!("redistrib_{release}.json"));
        std::fs::write(&out_path, &manifest_json)
            .with_context(|| format!("writing {}", out_path.display()))?;
        let manifest = RedistManifest::from_json(manifest_json.as_bytes())
            .map_err(|e| anyhow::anyhow!("synthesized {}: {e}", out_path.display()))?;
        if !emit_json {
            status!("xtask: [cuda-repos {release}] wrote {}", out_path.display());
        }

        // The pool `Filename` in these indices is relative to the distro/arch
        // base directory (e.g. `./libcublas-13-4_..._amd64.deb`).
        let lock = lock_from_manifest(&manifest, &base, &[&platform], resolve_component);
        if !lock.entries.is_empty() {
            std::fs::create_dir_all(&lock_dir)
                .with_context(|| format!("creating {}", lock_dir.display()))?;
            let lock_path = lock_dir.join(format!("corpus.{release}.lock.json"));
            let lock_json = lock.to_json().map_err(|e| anyhow::anyhow!(e))?;
            std::fs::write(&lock_path, lock_json)
                .with_context(|| format!("writing {}", lock_path.display()))?;
            if !emit_json {
                status!(
                    "xtask: [cuda-repos {release}] wrote {} lock entr(ies) -> {}",
                    lock.entries.len(),
                    lock_path.display()
                );
            }
        }

        written += 1;
        if limit > 0 && written >= limit {
            break 'targets;
        }
    }

    if emit_json {
        let objs: Vec<String> = per_target_json
            .iter()
            .map(|(t, n)| format!("{t:?}:{n}"))
            .collect();
        println!("{{{}}}", objs.join(","));
    } else if !dry_run {
        status!(
            "xtask: cuda-repos discover complete ({written} distro/arch manifest(s)). Next: `cargo xtask fingerprints build --from {} --out {}`",
            fixtures_dir.display(),
            DEFAULT_SHARD_DIR
        );
    }
    Ok(())
}

/// Fetch and parse the package index for one distro/arch, routing by format.
///
/// Returns `Ok(Some(pkgs))` with the parsed runtime libraries, `Ok(None)` when
/// the index exists but yields nothing to do, and `Err` when the index could
/// not be fetched (so the caller can skip a non-existent distro/arch).
fn fetch_index(
    base: &str,
    format: Format,
    retry: cudabom_fetch::RetryPolicy,
    emit_json: bool,
    distro: &str,
    arch: &str,
) -> Result<Option<Vec<DebPackage>>> {
    match format {
        Format::Apt => {
            let index_url = format!("{base}/Packages");
            if !emit_json {
                status!("xtask: [cuda-repos {distro}/{arch}] fetching {index_url}");
            }
            let body = cudabom_fetch::get(&index_url, &get_options(retry, None))
                .with_context(|| format!("fetching {index_url}"))?;
            let text = String::from_utf8_lossy(&body);
            Ok(Some(crate::apt::parse_cuda_library_packages(&text)))
        }
        Format::Rpm => {
            let repomd_url = crate::rpm::repomd_url(base);
            if !emit_json {
                status!("xtask: [cuda-repos {distro}/{arch}] fetching {repomd_url}");
            }
            let repomd = cudabom_fetch::get(&repomd_url, &get_options(retry, None))
                .with_context(|| format!("fetching {repomd_url}"))?;
            let repomd_text = String::from_utf8_lossy(&repomd);
            let Some(href) = crate::rpm::primary_href(&repomd_text) else {
                if !emit_json {
                    status!(
                        "xtask: [cuda-repos {distro}/{arch}] no primary.xml in repomd; skipping"
                    );
                }
                return Ok(None);
            };
            let primary_url = format!("{base}/{href}");
            let primary_gz = cudabom_fetch::get(&primary_url, &get_options(retry, None))
                .with_context(|| format!("fetching {primary_url}"))?;
            let primary_xml = crate::rpm::gunzip_to_string(&primary_gz)?;
            Ok(Some(crate::rpm::parse_cuda_library_packages(&primary_xml)))
        }
    }
}

/// Build a `redistrib_<release>.json` body in the [`RedistManifest`] shape for
/// one distro/arch. Each package becomes a component keyed by its normalized
/// manifest key, carrying one archive under the composite `platform` key so the
/// corpus layout never collides with the redist or Jetson trees.
fn synthesize_manifest(release: &str, platform: &str, packages: &[DebPackage]) -> Result<String> {
    let mut manifest = Map::new();
    manifest.insert("release_label".into(), json!(release));
    manifest.insert("release_product".into(), json!("cuda-repos"));

    for p in packages {
        let mut archive = Map::new();
        archive.insert("relative_path".into(), json!(p.filename));
        archive.insert("sha256".into(), json!(p.sha256));
        if let Some(size) = p.size {
            archive.insert("size".into(), json!(size.to_string()));
        }
        let component = json!({
            "version": p.version,
            platform: Value::Object(archive),
        });
        manifest.insert(manifest_key_for(&p.source), component);
    }

    let mut json = serde_json::to_string_pretty(&Value::Object(manifest))
        .context("serializing synthesized cuda-repos manifest")?;
    json.push('\n');
    Ok(json)
}

/// Resolve the `(distro, arch, format)` triples to scan from the arguments.
///
/// `--distro <d>` (repeatable) and `--arch <a>` (repeatable) narrow the matrix;
/// with no flags the full [`DISTROS`] matrix is used. An unknown `--distro`
/// is an error so a typo does not silently scan nothing.
fn collect_targets(args: &[String]) -> Result<Vec<(String, String, Format)>> {
    let want_distros = crate::repeated_flag(args, "--distro");
    let want_arches = crate::repeated_flag(args, "--arch");

    for d in &want_distros {
        if !DISTROS.iter().any(|t| t.distro == d) {
            let known: Vec<&str> = DISTROS.iter().map(|t| t.distro).collect();
            anyhow::bail!("unknown --distro {d:?}; known: {}", known.join(", "));
        }
    }

    let mut out = Vec::new();
    for t in DISTROS {
        if !want_distros.is_empty() && !want_distros.iter().any(|d| d == t.distro) {
            continue;
        }
        for arch in t.arches {
            if !want_arches.is_empty() && !want_arches.iter().any(|a| a == arch) {
                continue;
            }
            out.push((t.distro.to_string(), (*arch).to_string(), t.format));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "Package: libcublas-13-4\n\
Source: libcublas\n\
Version: 13.7.0.27-1\n\
Architecture: amd64\n\
Provides: libcublas.so.13 (= 13.7.0.27)\n\
Filename: ./libcublas-13-4_13.7.0.27-1_amd64.deb\n\
Size: 410241818\n\
SHA256: abedfb721a2ae5b9780ae3146305703ef3d2fee30b71d597b18f43c52efdf1fd\n";

    #[test]
    fn synthesized_manifest_uses_composite_platform_key() {
        let pkgs = crate::apt::parse_cuda_library_packages(SAMPLE);
        let platform = "linux-x86_64-ubuntu2404";
        let json = synthesize_manifest("ubuntu2404-x86_64", platform, &pkgs).unwrap();
        let manifest = RedistManifest::from_json(json.as_bytes())
            .expect("synthesized manifest must parse as a redist manifest");
        let cublas = &manifest.components["libcublas"];
        assert_eq!(cublas.version, "13.7.0.27");
        let archive = &cublas.archives[platform];
        assert_eq!(
            archive.sha256,
            "abedfb721a2ae5b9780ae3146305703ef3d2fee30b71d597b18f43c52efdf1fd"
        );
        assert!(archive
            .relative_path
            .ends_with("libcublas-13-4_13.7.0.27-1_amd64.deb"));
    }

    #[test]
    fn collect_targets_rejects_unknown_distro() {
        let args = vec!["--distro".to_string(), "nope".to_string()];
        assert!(collect_targets(&args).is_err());
    }

    #[test]
    fn collect_targets_narrows_matrix() {
        let args = vec![
            "--distro".to_string(),
            "wsl-ubuntu".to_string(),
            "--arch".to_string(),
            "x86_64".to_string(),
        ];
        let targets = collect_targets(&args).unwrap();
        assert_eq!(
            targets,
            vec![("wsl-ubuntu".to_string(), "x86_64".to_string(), Format::Apt)]
        );
    }

    #[test]
    fn collect_targets_includes_rpm_distros() {
        let args = vec!["--distro".to_string(), "rhel9".to_string()];
        let targets = collect_targets(&args).unwrap();
        // rhel9 publishes three arches, all RPM.
        assert_eq!(targets.len(), 3);
        assert!(targets
            .iter()
            .all(|(d, _, f)| d == "rhel9" && *f == Format::Rpm));
    }
}
