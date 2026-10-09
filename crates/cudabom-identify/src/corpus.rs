//! The corpus lockfile: a committed, reviewable list of the real NVIDIA
//! redistributable archives used to derive binary fingerprints.
//!
//! Rationale: fingerprint derivation needs real `.so` bytes, but cudabom never
//! commits NVIDIA binaries. The repeatable, reviewable bridge is a *lockfile*
//! (like Cargo.lock / package-lock.json): it records exactly which archives to
//! fetch and their expected sha256, so any machine reproduces the same corpus,
//! and a reviewer sees precisely what changed. The digests are NVIDIA's own,
//! taken from the redist manifest, never invented.
//!
//! `cudabom-identify` owns only the *schema and derivation* (pure, tested). The
//! actual network fetch lives in the `xtask` corpus command atop `cudabom-fetch`
//! so this crate stays free of a network dependency.

use serde::{Deserialize, Serialize};

use crate::redist::RedistManifest;

/// A committed corpus lockfile.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CorpusLock {
    /// Schema version so a reader can reject data it does not understand.
    pub schema_version: u32,
    /// The archives to fetch, in a deterministic order.
    pub entries: Vec<CorpusEntry>,
}

/// One archive to fetch and verify.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CorpusEntry {
    /// Canonical cudabom component name (e.g. `cudart`).
    pub component: String,
    /// Exact version (e.g. `11.4.108`).
    pub version: String,
    /// Platform key (e.g. `linux-x86_64`).
    pub platform: String,
    /// Absolute URL to the archive.
    pub url: String,
    /// Expected sha256 (lowercase hex) of the archive, from NVIDIA's manifest.
    pub sha256: String,
}

impl CorpusLock {
    /// The current lockfile schema version.
    pub const CURRENT_SCHEMA: u32 = 1;

    /// Parse a lockfile from JSON bytes.
    ///
    /// # Errors
    /// Returns an error string if the JSON is malformed or the schema is newer
    /// than this build understands.
    pub fn from_json(bytes: &[u8]) -> Result<Self, String> {
        let lock: CorpusLock = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
        if lock.schema_version > Self::CURRENT_SCHEMA {
            return Err(format!(
                "corpus lock schema {} is newer than supported {}",
                lock.schema_version,
                Self::CURRENT_SCHEMA
            ));
        }
        Ok(lock)
    }

    /// Load and merge every `corpus.*.lock.json` shard in a directory into one
    /// lockfile, sorted deterministically and de-duplicated by
    /// (component, version, platform).
    ///
    /// The corpus is sharded per CUDA release (`corpus.<release>.lock.json`) so
    /// each file stays small and diffs stay reviewable; a full corpus fetch
    /// reads them all at once. Shards are read in sorted filename order for
    /// determinism.
    ///
    /// # Errors
    /// Returns an error string if the directory cannot be read or a shard is
    /// malformed / uses a newer schema.
    pub fn from_dir(dir: &std::path::Path) -> Result<Self, String> {
        // Collect `corpus.*.lock.json` shards recursively so a parent lock
        // directory holding per-product subdirectories (`fingerprints/cudnn`,
        // `fingerprints/nccl`, ...) is fetched in one pass alongside the cuda
        // tree's root-level shards.
        let mut shards: Vec<std::path::PathBuf> = Vec::new();
        collect_lock_shards(dir, &mut shards)
            .map_err(|e| format!("reading {}: {e}", dir.display()))?;
        shards.sort();

        let mut merged = Self {
            schema_version: Self::CURRENT_SCHEMA,
            entries: Vec::new(),
        };
        let mut seen = std::collections::BTreeSet::new();
        for shard in shards {
            let bytes =
                std::fs::read(&shard).map_err(|e| format!("reading {}: {e}", shard.display()))?;
            let lock = Self::from_json(&bytes).map_err(|e| format!("{}: {e}", shard.display()))?;
            for entry in lock.entries {
                let key = (
                    entry.component.clone(),
                    entry.version.clone(),
                    entry.platform.clone(),
                );
                if seen.insert(key) {
                    merged.entries.push(entry);
                }
            }
        }
        merged.entries.sort_by(|a, b| {
            a.component
                .cmp(&b.component)
                .then(a.version.cmp(&b.version))
                .then(a.platform.cmp(&b.platform))
        });
        Ok(merged)
    }

    /// Serialize to pretty JSON (newline-terminated) for a reviewable diff.
    ///
    /// # Errors
    /// Returns an error string if serialization fails.
    pub fn to_json(&self) -> Result<String, String> {
        let mut s = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        s.push('\n');
        Ok(s)
    }

    /// Keep only the first `n` entries (already in deterministic order), for a
    /// subset-first smoke run. `n == 0` is treated as "no limit".
    #[must_use]
    pub fn limited(mut self, n: usize) -> Self {
        if n > 0 && self.entries.len() > n {
            self.entries.truncate(n);
        }
        self
    }
}

/// Recursively collect every `corpus.*.lock.json` shard under `dir` into `out`.
///
/// Recursion supports the multi-product layout where sibling trees keep their
/// lockfiles in subdirectories (`fingerprints/<product>/corpus.*.lock.json`)
/// while the cuda tree keeps them at the root. Returns an error only if the
/// top-level directory cannot be read; unreadable nested entries are skipped.
fn collect_lock_shards(
    dir: &std::path::Path,
    out: &mut Vec<std::path::PathBuf>,
) -> std::io::Result<()> {
    crate::db::collect_files_matching(dir, out, is_lock_shard)
}

/// True for a corpus provenance lock, named `corpus.*.lock.json`.
fn is_lock_shard(path: &std::path::Path) -> bool {
    path.file_name()
        .and_then(|s| s.to_str())
        .is_some_and(|name| name.starts_with("corpus.") && name.ends_with(".lock.json"))
}

/// True if a requested platform `want` selects an archive keyed `have`.
///
/// Matches either exactly (`linux-x86_64` == `linux-x86_64`, the flat trees) or
/// as the CUDA-variant form `<want>-cuda<N>` (`linux-x86_64` selects
/// `linux-x86_64-cuda12` and `linux-x86_64-cuda13`, the nested trees). The
/// variant suffix is required to be `-cuda` followed by digits so a sibling
/// platform like `linux-sbsa` is never matched by `linux-s...`.
fn platform_matches(want: &str, have: &str) -> bool {
    if want == have {
        return true;
    }
    have.strip_prefix(want)
        .and_then(|rest| rest.strip_prefix("-cuda"))
        .is_some_and(|digits| !digits.is_empty() && digits.chars().all(|c| c.is_ascii_digit()))
}

/// Build corpus entries from a redist manifest, for the given platforms and the
/// components that have a reviewed profile (so we only fetch what we can
/// attribute). `resolve_component` maps a manifest key to a canonical component
/// name, returning `None` for keys without a profile. The archive URL joins
/// `base_url` with each archive's `relative_path`; entries are sorted for a
/// deterministic lockfile.
#[must_use]
pub fn lock_from_manifest(
    manifest: &RedistManifest,
    base_url: &str,
    platforms: &[&str],
    resolve_component: impl Fn(&str) -> Option<String>,
) -> CorpusLock {
    let base = base_url.trim_end_matches('/');
    let mut entries = Vec::new();

    for (key, component) in &manifest.components {
        let Some(canonical) = resolve_component(key) else {
            continue;
        };
        for (platform, archive) in &component.archives {
            // Match the requested platform against the archive's platform key.
            // Flat trees key archives as `linux-x86_64`; CUDA-variant-nested
            // trees (cuDNN, cuTENSOR, ...) key them as `linux-x86_64-cuda12`.
            // A requested `linux-x86_64` must select both the flat archive and
            // every CUDA variant of that platform, so match on either an exact
            // key or the `<platform>-cuda<N>` variant form.
            if !platforms.iter().any(|p| platform_matches(p, platform)) {
                continue;
            }
            entries.push(CorpusEntry {
                component: canonical.clone(),
                version: component.version.clone(),
                platform: platform.clone(),
                url: format!("{base}/{}", archive.relative_path),
                sha256: archive.sha256.clone(),
            });
        }
    }

    entries.sort_by(|a, b| {
        a.component
            .cmp(&b.component)
            .then(a.version.cmp(&b.version))
            .then(a.platform.cmp(&b.platform))
    });

    CorpusLock {
        schema_version: CorpusLock::CURRENT_SCHEMA,
        entries,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{
        "release_label": "11.4.2",
        "cuda_cudart": {
            "name": "CUDA Runtime (cudart)",
            "version": "11.4.108",
            "linux-x86_64": {
                "relative_path": "cuda_cudart/linux-x86_64/cuda_cudart-linux-x86_64-11.4.108-archive.tar.xz",
                "sha256": "d08a1b731e5175aa3ae06a6d1c6b3059dd9ea13836d947018ea5e3ec2ca3d62b"
            },
            "windows-x86_64": {
                "relative_path": "cuda_cudart/windows-x86_64/cuda_cudart-windows-x86_64-11.4.108-archive.zip",
                "sha256": "b59756c27658d1ea87a17c06d064d1336576431cd64da5d1790d909e455d06d3"
            }
        },
        "cuda_nvcc": {
            "name": "CUDA NVCC",
            "version": "11.4.152",
            "linux-x86_64": {
                "relative_path": "cuda_nvcc/linux-x86_64/x.tar.xz",
                "sha256": "1111111111111111111111111111111111111111111111111111111111111111"
            }
        }
    }"#;

    fn resolver(key: &str) -> Option<String> {
        // Only cudart is "profiled" in this test.
        (key == "cuda_cudart").then(|| "cudart".to_string())
    }

    #[test]
    fn builds_entries_for_selected_platforms_and_profiled_components() {
        let m = RedistManifest::from_json(SAMPLE.as_bytes()).unwrap();
        let lock = lock_from_manifest(
            &m,
            "https://developer.download.nvidia.com/compute/cuda/redist/",
            &["linux-x86_64"],
            resolver,
        );

        // Only cudart linux-x86_64: nvcc is unprofiled, windows filtered out.
        assert_eq!(lock.entries.len(), 1);
        let e = &lock.entries[0];
        assert_eq!(e.component, "cudart");
        assert_eq!(e.version, "11.4.108");
        assert_eq!(e.platform, "linux-x86_64");
        assert_eq!(
            e.url,
            "https://developer.download.nvidia.com/compute/cuda/redist/cuda_cudart/linux-x86_64/cuda_cudart-linux-x86_64-11.4.108-archive.tar.xz"
        );
        assert_eq!(
            e.sha256,
            "d08a1b731e5175aa3ae06a6d1c6b3059dd9ea13836d947018ea5e3ec2ca3d62b"
        );
    }

    #[test]
    fn lock_round_trips_through_json() {
        let m = RedistManifest::from_json(SAMPLE.as_bytes()).unwrap();
        let lock = lock_from_manifest(&m, "https://x/", &["linux-x86_64"], resolver);
        let json = lock.to_json().unwrap();
        let reloaded = CorpusLock::from_json(json.as_bytes()).unwrap();
        assert_eq!(reloaded, lock);
    }

    #[test]
    fn platform_matches_exact_and_cuda_variants() {
        // Flat key: exact match only.
        assert!(platform_matches("linux-x86_64", "linux-x86_64"));
        // Variant key: `<platform>-cuda<N>` matches.
        assert!(platform_matches("linux-x86_64", "linux-x86_64-cuda12"));
        assert!(platform_matches("linux-x86_64", "linux-x86_64-cuda13"));
        // A sibling platform must not be matched by prefix overlap.
        assert!(!platform_matches("linux-x86_64", "linux-x86_64-foo"));
        assert!(!platform_matches("linux-sbsa", "linux-sbsa-cudaX"));
        assert!(!platform_matches("linux-s", "linux-sbsa"));
        assert!(!platform_matches("linux-x86_64", "linux-sbsa-cuda12"));
    }

    #[test]
    fn selects_all_cuda_variants_of_a_requested_platform() {
        // A cuDNN-shaped manifest: one profiled component, variant-nested.
        let json = r#"{
            "release_label": "9.27.0",
            "cudnn": {
                "name": "cuDNN",
                "version": "9.27.0.42",
                "cuda_variant": ["12", "13"],
                "linux-x86_64": {
                    "cuda12": { "relative_path": "cudnn/l/x12.tar.xz", "sha256": "a12" },
                    "cuda13": { "relative_path": "cudnn/l/x13.tar.xz", "sha256": "a13" }
                },
                "linux-sbsa": {
                    "cuda12": { "relative_path": "cudnn/s/s12.tar.xz", "sha256": "s12" }
                }
            }
        }"#;
        let m = RedistManifest::from_json(json.as_bytes()).unwrap();
        let lock = lock_from_manifest(
            &m,
            "https://developer.download.nvidia.com/compute/cudnn/redist/",
            &["linux-x86_64"],
            |k| (k == "cudnn").then(|| "cudnn".to_string()),
        );
        // Both CUDA variants of linux-x86_64 selected; linux-sbsa excluded.
        assert_eq!(lock.entries.len(), 2);
        let platforms: Vec<&str> = lock.entries.iter().map(|e| e.platform.as_str()).collect();
        assert!(platforms.contains(&"linux-x86_64-cuda12"));
        assert!(platforms.contains(&"linux-x86_64-cuda13"));
        assert!(lock.entries.iter().all(|e| e.component == "cudnn"));
    }

    #[test]
    fn rejects_future_schema() {
        let json = r#"{ "schema_version": 999, "entries": [] }"#;
        assert!(CorpusLock::from_json(json.as_bytes()).is_err());
    }

    #[test]
    fn rejects_unknown_fields() {
        let json = r#"{ "schema_version": 1, "entries": [], "bogus": true }"#;
        assert!(CorpusLock::from_json(json.as_bytes()).is_err());
    }

    #[test]
    fn from_dir_merges_and_dedups_shards() {
        let dir = tempfile::tempdir().unwrap();
        // Two per-release shards, sharing one duplicate entry (a, 1) and
        // holding distinct ones. from_dir must merge, sort, and de-dup.
        std::fs::write(
            dir.path().join("corpus.11.4.2.lock.json"),
            r#"{ "schema_version": 1, "entries": [
                { "component": "a", "version": "1", "platform": "linux-x86_64", "url": "u-a1", "sha256": "h-a1" }
            ] }"#,
        )
        .unwrap();
        std::fs::write(
            dir.path().join("corpus.12.4.1.lock.json"),
            r#"{ "schema_version": 1, "entries": [
                { "component": "a", "version": "1", "platform": "linux-x86_64", "url": "u-a1", "sha256": "h-a1" },
                { "component": "b", "version": "2", "platform": "linux-x86_64", "url": "u-b2", "sha256": "h-b2" }
            ] }"#,
        )
        .unwrap();
        // A non-matching file must be ignored.
        std::fs::write(dir.path().join("notes.txt"), "ignore me").unwrap();

        let merged = CorpusLock::from_dir(dir.path()).unwrap();
        assert_eq!(merged.entries.len(), 2, "duplicate (a,1) collapsed");
        assert_eq!(merged.entries[0].component, "a");
        assert_eq!(merged.entries[1].component, "b");
    }

    #[test]
    fn from_dir_rejects_a_malformed_shard() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("corpus.bad.lock.json"),
            r#"{ "schema_version": 999, "entries": [] }"#,
        )
        .unwrap();
        assert!(CorpusLock::from_dir(dir.path()).is_err());
    }

    #[test]
    fn limited_truncates_and_treats_zero_as_no_limit() {
        let lock = CorpusLock {
            schema_version: 1,
            entries: vec![
                CorpusEntry {
                    component: "a".into(),
                    version: "1".into(),
                    platform: "linux-x86_64".into(),
                    url: "u1".into(),
                    sha256: "h1".into(),
                },
                CorpusEntry {
                    component: "b".into(),
                    version: "1".into(),
                    platform: "linux-x86_64".into(),
                    url: "u2".into(),
                    sha256: "h2".into(),
                },
            ],
        };
        assert_eq!(lock.clone().limited(1).entries.len(), 1);
        assert_eq!(lock.clone().limited(0).entries.len(), 2); // 0 == no limit
        assert_eq!(lock.limited(99).entries.len(), 2); // n > len is a no-op
    }
}
