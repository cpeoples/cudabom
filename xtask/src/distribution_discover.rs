//! `cargo xtask distribution discover`: find in-the-wild CUDA wheels on PyPI.
//!
//! The distribution eval (`eval/distribution.manifest.json`) is content-pinned so it is
//! reproducible, but that means it only ever tests the artifacts someone added
//! by hand. This task closes that gap *without* ever downloading a wheel: PyPI's
//! JSON API returns, for every release of a project, each distribution file's
//! URL, size, and sha256 **in metadata**. So discovery is a cheap,
//! metadata-only crawl, kilobytes, not gigabytes, that proposes new manifest
//! entries. The heavy part (actually scanning a wheel) stays in `eval --distribution`,
//! which is disk-governed by its own `--tier`/`--stream` controls.
//!
//! Scope is deliberately broad: both NVIDIA's official `nvidia-*-cu1X` wheels
//! *and* third-party frameworks that bundle their own CUDA libraries (PyTorch,
//! CuPy, JAX, …). The reviewed package list below is the only hardcoded
//! knowledge; every *version* is discovered live.
//!
//! Workflow, mirroring `corpus discover` / `fingerprint-refresh`: `distribution
//! discover` (dry-run default) prints the new wheels found, and `distribution
//! discover --write` appends the newest N per package to the manifest as pinned
//! entries for review (a human checks the diff before merge). A nightly workflow
//! runs `--write` and opens a PR, so new releases and any stragglers are picked
//! up automatically after an initial local seed crawl.

use std::collections::BTreeSet;

use anyhow::{bail, Context, Result};
use cudabom_fetch::{get, GetOptions};
use serde_json::Value;

use crate::verbosity::{detail, status};
use crate::{flag, has_flag};

/// Default distribution manifest to compare against / append to.
const DEFAULT_MANIFEST: &str = "eval/distribution.manifest.json";
/// PyPI JSON API base. The per-project endpoint is `{base}/{project}/json`.
const PYPI_JSON_BASE: &str = "https://pypi.org/pypi";
/// How many newest releases per package to propose by default.
const DEFAULT_LIMIT: usize = 1;

/// The reviewed set of CUDA-bearing PyPI projects to crawl. This list is the
/// *only* hardcoded knowledge: PyPI has no "list every CUDA wheel" API, so the
/// curated project set must live somewhere; every *version* is still discovered
/// live. Adding a project is a one-line, reviewable change.
///
/// The project -> CUDA component mapping is **not** encoded here: it is derived
/// from the single canonical resolver (`cudabom_identify::canonicalize_declared_name`),
/// so official NVIDIA wheels (`nvidia-nccl-cu12` -> `nccl`) and detection-only
/// third-party frameworks (`torch` -> none) are classified by the same table the
/// scanner uses. Official wheels first, then third-party frameworks that vendor
/// CUDA (whose version is the framework's, not CUDA's).
const CUDA_PROJECTS: &[&str] = &[
    // Official NVIDIA wheels: project version == CUDA component version.
    "nvidia-cuda-runtime-cu12",
    "nvidia-cuda-runtime-cu13",
    "nvidia-cudnn-cu12",
    "nvidia-cudnn-cu13",
    "nvidia-nccl-cu12",
    "nvidia-nccl-cu13",
    "nvidia-cublas-cu12",
    "nvidia-cublas-cu13",
    "nvidia-cufft-cu12",
    "nvidia-curand-cu12",
    "nvidia-cusolver-cu12",
    "nvidia-cusparse-cu12",
    "nvidia-cuda-nvrtc-cu12",
    "cutensor-cu12",
    // Third-party frameworks that bundle CUDA (detection-only: resolver returns
    // `None`, so these carry no CUDA ground-truth version).
    "cupy-cuda12x",
    "torch",
    "jax-cuda12-plugin",
    "tensorflow",
];

/// Resolve a PyPI project name to the CUDA component an official wheel of it
/// maps to, via the single canonical resolver. `None` for third-party
/// frameworks that merely bundle CUDA: scored detection-only.
fn expect_component_for(project: &str) -> Option<String> {
    cudabom_identify::canonicalize_declared_name(project)
}

/// `cargo xtask distribution discover [--manifest <f>] [--limit N] [--project <name>]
/// [--write] [--json]`
pub(crate) fn run(args: &[String]) -> Result<()> {
    let manifest_path = flag(args, "--manifest").unwrap_or_else(|| DEFAULT_MANIFEST.to_string());
    let limit: usize = flag(args, "--limit")
        .map(|s| s.parse())
        .transpose()
        .context("--limit must be a non-negative integer")?
        .unwrap_or(DEFAULT_LIMIT);
    let only_project = flag(args, "--project");
    let write = has_flag(args, "--write");
    let as_json = has_flag(args, "--json");

    // Load the existing manifest so we only propose genuinely new wheels. A
    // missing manifest is an empty set (the initial-seed case).
    let manifest_bytes = std::fs::read(&manifest_path).unwrap_or_default();
    let mut manifest: Value = if manifest_bytes.is_empty() {
        serde_json::json!({ "schema_version": 1, "artifacts": [] })
    } else {
        serde_json::from_slice(&manifest_bytes)
            .with_context(|| format!("parsing {manifest_path}"))?
    };
    let known_urls = existing_urls(&manifest);

    let projects: Vec<&str> = match &only_project {
        Some(name) => CUDA_PROJECTS
            .iter()
            .copied()
            .filter(|p| *p == name)
            .collect(),
        None => CUDA_PROJECTS.to_vec(),
    };
    if projects.is_empty() {
        bail!("no known CUDA project matches --project {only_project:?}");
    }

    status!(
        "xtask: distribution discover across {} project(s), newest {limit} release(s) each",
        projects.len()
    );

    let mut proposed: Vec<ProposedWheel> = Vec::new();
    for project in projects {
        match discover_project(project, limit, &known_urls) {
            Ok(mut wheels) => proposed.append(&mut wheels),
            Err(e) => status!("xtask: [skip] {}: {e:#}", project),
        }
    }

    proposed.sort_by(|a, b| a.id.cmp(&b.id));

    if as_json {
        let arr: Vec<Value> = proposed.iter().map(ProposedWheel::to_entry).collect();
        println!("{}", serde_json::to_string_pretty(&Value::Array(arr))?);
    } else {
        report(&proposed);
    }

    if write && !proposed.is_empty() {
        append_to_manifest(&mut manifest, &proposed);
        let serialized = serde_json::to_string_pretty(&manifest)? + "\n";
        std::fs::write(&manifest_path, serialized)
            .with_context(|| format!("writing {manifest_path}"))?;
        status!(
            "xtask: wrote {} new artifact(s) to {manifest_path}",
            proposed.len()
        );
    } else if write {
        status!("xtask: nothing new to write; {manifest_path} is up to date");
    }

    Ok(())
}

/// A newly discovered wheel, pinned by URL + sha256, ready to become a manifest
/// entry.
#[derive(Debug, Clone)]
struct ProposedWheel {
    id: String,
    note: String,
    url: String,
    sha256: String,
    size: u64,
    expect_component: Option<String>,
    version: String,
}

impl ProposedWheel {
    /// Render as a `distribution.manifest.json` artifact object.
    fn to_entry(&self) -> Value {
        let expect = match &self.expect_component {
            Some(component) => serde_json::json!([
                { "component": component, "version": self.version }
            ]),
            // Third-party bundle: detection-only (no CUDA ground-truth version).
            None => serde_json::json!([]),
        };
        serde_json::json!({
            "id": self.id,
            "kind": "wheel",
            "note": self.note,
            "url": self.url,
            "sha256": self.sha256,
            "expect": expect,
        })
    }
}

/// Query PyPI for a project and return the newest `limit` wheels not already in
/// the manifest. Metadata-only: no wheel is downloaded.
fn discover_project(
    project: &str,
    limit: usize,
    known_urls: &BTreeSet<String>,
) -> Result<Vec<ProposedWheel>> {
    if limit == 0 {
        return Ok(Vec::new());
    }
    let expect_component = expect_component_for(project);
    let url = format!("{PYPI_JSON_BASE}/{project}/json");
    detail!("xtask:   GET {url}");
    let body = get(
        &url,
        &GetOptions {
            user_agent: cudabom_fetch::DEFAULT_USER_AGENT.to_string(),
            ..GetOptions::default()
        },
    )
    .with_context(|| format!("fetching PyPI metadata for {project}"))?;
    let doc: Value =
        serde_json::from_slice(&body).with_context(|| format!("parsing JSON for {project}"))?;

    // `releases` maps version -> [file objects]. Sort versions newest-first by
    // PEP 440-ish ordering (good enough for the common numeric case; discovery
    // is a proposal a human reviews, not an authoritative sort).
    let releases = doc
        .get("releases")
        .and_then(Value::as_object)
        .context("PyPI response has no releases map")?;

    let mut versions: Vec<&String> = releases.keys().collect();
    // Newest-first. sort_by_key would need an owned key per element; a cached
    // comparator keeps it simple and the list is short (one project's releases).
    versions.sort_by_cached_key(|v| std::cmp::Reverse(version_key(v)));

    let mut out = Vec::new();
    for version in versions {
        if out.len() >= limit {
            break;
        }
        // Skip pre-releases (rc/alpha/beta/dev): the eval wants shipped versions
        // users actually run, not candidates.
        if is_prerelease(version) {
            continue;
        }
        let Some(files) = releases.get(version).and_then(Value::as_array) else {
            continue;
        };
        // Prefer a manylinux x86_64 wheel: the platform the eval scans. Skip
        // sdists, yanked files, and non-wheel artifacts.
        let Some(file) = pick_linux_wheel(files) else {
            continue;
        };
        let file_url = file.get("url").and_then(Value::as_str).unwrap_or_default();
        if file_url.is_empty() || known_urls.contains(file_url) {
            continue;
        }
        let sha256 = file
            .get("digests")
            .and_then(|d| d.get("sha256"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        if sha256.is_empty() {
            continue;
        }
        let size = file.get("size").and_then(Value::as_u64).unwrap_or(0);
        let kind = if expect_component.is_some() {
            "official NVIDIA wheel"
        } else {
            "third-party CUDA-bundling wheel (detection-only)"
        };
        out.push(ProposedWheel {
            id: format!("wheel-{project}-{version}"),
            note: format!(
                "{project}: {} {version}, discovered from PyPI ({:.1} MB).",
                kind,
                mb(size)
            ),
            url: file_url.to_string(),
            sha256: sha256.to_string(),
            size,
            expect_component: expect_component.clone(),
            version: (*version).clone(),
        });
    }
    Ok(out)
}

/// Choose a manylinux x86_64 wheel from a release's file list, if present. Pure
/// metadata inspection: the `.whl` filename encodes platform tags (PEP 427).
fn pick_linux_wheel(files: &[Value]) -> Option<&Value> {
    files.iter().find(|f| {
        if f.get("yanked").and_then(Value::as_bool).unwrap_or(false) {
            return false;
        }
        if f.get("packagetype").and_then(Value::as_str) != Some("bdist_wheel") {
            return false;
        }
        let name = f
            .get("filename")
            .and_then(Value::as_str)
            .unwrap_or_default();
        name.contains("manylinux") && name.contains("x86_64")
    })
}

/// Megabytes for display, computed without a lossy direct `u64 as f64` cast
/// that clippy (rightly) flags for very large values.
fn mb(bytes: u64) -> f64 {
    // u32-wide math is exact in f64; sizes here are comfortably under 4 GB.
    f64::from(u32::try_from(bytes).unwrap_or(u32::MAX)) / 1.0e6
}

/// A coarse, numeric-first sort key for a version string. Splits on `.`/`-` and
/// zero-pads numeric components so `12.4.127` sorts after `12.4.99`. Non-numeric
/// pre-release tags fall back to lexical order after the numeric prefix.
fn version_key(v: &str) -> Vec<String> {
    v.split(['.', '-'])
        .map(|part| {
            if let Ok(n) = part.parse::<u64>() {
                format!("{n:020}")
            } else {
                format!("~{part}") // sort textual tags after numeric
            }
        })
        .collect()
}

/// True if a version string looks like a pre-release (rc/alpha/beta/dev/pre),
/// per PEP 440's common spellings. Discovery proposes shipped releases only.
fn is_prerelease(v: &str) -> bool {
    let lower = v.to_ascii_lowercase();
    ["rc", "a", "b", "dev", "pre", "alpha", "beta"]
        .iter()
        .any(|tag| {
            // Match a tag that follows a digit or a '.' separator, e.g.
            // "2.22.0rc0", "1.0a1", "3.0.dev2": not an incidental letter
            // inside a segment.
            lower.match_indices(tag).any(|(i, _)| {
                i > 0 && {
                    let prev = lower.as_bytes()[i - 1];
                    prev.is_ascii_digit() || prev == b'.'
                }
            })
        })
}

/// The set of artifact URLs already pinned in the manifest, so discovery never
/// re-proposes a known wheel.
fn existing_urls(manifest: &Value) -> BTreeSet<String> {
    manifest
        .get("artifacts")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|a| a.get("url").and_then(Value::as_str))
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// Append proposed wheels to the manifest's `artifacts` array in place.
fn append_to_manifest(manifest: &mut Value, proposed: &[ProposedWheel]) {
    let artifacts = manifest
        .as_object_mut()
        .and_then(|m| m.get_mut("artifacts"))
        .and_then(Value::as_array_mut);
    if let Some(artifacts) = artifacts {
        for wheel in proposed {
            artifacts.push(wheel.to_entry());
        }
    }
}

/// Print a human-readable summary of what discovery found.
fn report(proposed: &[ProposedWheel]) {
    if proposed.is_empty() {
        status!("xtask: no new CUDA wheels found; manifest is up to date");
        return;
    }
    status!("xtask: {} new CUDA wheel(s):", proposed.len());
    let total: u64 = proposed.iter().map(|w| w.size).sum();
    for w in proposed {
        let gt = w.expect_component.as_deref().map_or_else(
            || "detection-only".to_string(),
            |c| format!("{c} {}", w.version),
        );
        status!("  {:48} {:7.1} MB  [{gt}]", w.id, mb(w.size));
    }
    status!(
        "  (if all were scanned, that is ~{:.1} GB of downloads: governed by eval --distribution --tier/--stream)",
        mb(total) / 1000.0
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_key_orders_numeric_patch_correctly() {
        // 12.4.127 must sort after 12.4.99 (numeric, not lexical).
        assert!(version_key("12.4.127") > version_key("12.4.99"));
        assert!(version_key("12.4.0") < version_key("12.4.1"));
        assert!(version_key("13.0.0") > version_key("12.9.9"));
    }

    #[test]
    fn prerelease_versions_are_detected() {
        assert!(is_prerelease("2.22.0rc0"));
        assert!(is_prerelease("1.0a1"));
        assert!(is_prerelease("1.0b2"));
        assert!(is_prerelease("3.0.dev2"));
        assert!(!is_prerelease("12.4.127"));
        assert!(!is_prerelease("2.5.1"));
        assert!(!is_prerelease("9.0.0.312"));
    }

    #[test]
    fn pick_linux_wheel_prefers_manylinux_x86_64() {
        let files = serde_json::json!([
            { "packagetype": "sdist", "filename": "pkg-1.0.tar.gz", "yanked": false },
            { "packagetype": "bdist_wheel", "filename": "pkg-1.0-cp310-cp310-win_amd64.whl", "yanked": false },
            { "packagetype": "bdist_wheel", "filename": "pkg-1.0-cp310-cp310-manylinux2014_x86_64.whl", "yanked": false },
        ]);
        let arr = files.as_array().unwrap();
        let picked = pick_linux_wheel(arr).expect("a linux wheel");
        assert!(picked
            .get("filename")
            .and_then(Value::as_str)
            .unwrap()
            .contains("manylinux2014_x86_64"));
    }

    #[test]
    fn pick_linux_wheel_skips_yanked() {
        let files = serde_json::json!([
            { "packagetype": "bdist_wheel", "filename": "pkg-1.0-cp310-cp310-manylinux2014_x86_64.whl", "yanked": true },
        ]);
        assert!(pick_linux_wheel(files.as_array().unwrap()).is_none());
    }

    #[test]
    fn existing_urls_collects_pinned_urls() {
        let manifest = serde_json::json!({
            "artifacts": [
                { "id": "a", "url": "https://x/one.whl" },
                { "id": "b", "url": "https://x/two.whl" },
                { "id": "c" }
            ]
        });
        let urls = existing_urls(&manifest);
        assert_eq!(urls.len(), 2);
        assert!(urls.contains("https://x/one.whl"));
    }

    #[test]
    fn proposed_official_wheel_carries_expected_component() {
        let w = ProposedWheel {
            id: "wheel-nvidia-cuda-runtime-cu12-12.4.127".to_string(),
            note: "n".to_string(),
            url: "https://x/w.whl".to_string(),
            sha256: "abc".to_string(),
            size: 1,
            expect_component: Some("cudart".to_string()),
            version: "12.4.127".to_string(),
        };
        let entry = w.to_entry();
        let expect = entry.get("expect").and_then(Value::as_array).unwrap();
        assert_eq!(expect.len(), 1);
        assert_eq!(
            expect[0].get("component").and_then(Value::as_str),
            Some("cudart")
        );
        assert_eq!(
            expect[0].get("version").and_then(Value::as_str),
            Some("12.4.127")
        );
    }

    #[test]
    fn proposed_thirdparty_wheel_is_detection_only() {
        let w = ProposedWheel {
            id: "wheel-torch-2.5.1".to_string(),
            note: "n".to_string(),
            url: "https://x/torch.whl".to_string(),
            sha256: "abc".to_string(),
            size: 1,
            expect_component: None,
            version: "2.5.1".to_string(),
        };
        let entry = w.to_entry();
        let expect = entry.get("expect").and_then(Value::as_array).unwrap();
        assert!(expect.is_empty(), "third-party bundle is detection-only");
    }

    #[test]
    fn official_wheels_resolve_to_a_component_via_canonical_resolver() {
        // Every `nvidia-*`/`cutensor-*` wheel in the crawl list must resolve to
        // a CUDA component through the single canonical resolver, proving the
        // project -> component mapping is not re-encoded locally.
        for project in CUDA_PROJECTS {
            let is_official = project.starts_with("nvidia-") || project.starts_with("cutensor-");
            if is_official {
                assert!(
                    expect_component_for(project).is_some(),
                    "official wheel {project} must resolve to a component"
                );
            }
        }
    }

    #[test]
    fn thirdparty_frameworks_are_detection_only_via_resolver() {
        for project in ["cupy-cuda12x", "torch", "jax-cuda12-plugin", "tensorflow"] {
            assert!(
                expect_component_for(project).is_none(),
                "third-party framework {project} must be detection-only"
            );
        }
    }
}
