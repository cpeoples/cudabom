//! The fingerprint database schema.
//!
//! This module defines the *shape* of the fingerprint data, never its contents.
//! Per the project rule (spec Section 8 / `fingerprints/README.md`), cudabom
//! must not invent fingerprints: every hash, build-id, symbol set, and version
//! pattern is derived from an official NVIDIA redistributable by
//! `cargo xtask fingerprints build` and reviewed before it is committed as
//! JSON. The database loaded here is therefore empty until that derived data
//! exists; an empty database yields only the structural (format-derived)
//! identifications the matchers can prove on their own.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// The complete fingerprint database: a set of known CUDA components plus the
/// derived signals that identify each.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FingerprintDb {
    /// Schema version of this database file, so a reader can reject data it
    /// does not understand.
    pub schema_version: u32,
    /// Release-level metadata for this shard, straight from the redist
    /// manifest. Absent for a merged/aggregate database that spans releases.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release: Option<ReleaseInfo>,
    /// For a merged (multi-release) database: each release label mapped to its
    /// first-party `release_date`. A single shard leaves this empty and carries
    /// its date in [`FingerprintDb::release`] instead; `from_dir` folds every
    /// shard's date into this map so consumers can date a finding by the
    /// release that shipped it (`release_versions` gives the label).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub release_dates: BTreeMap<String, String>,
    /// Derivation provenance for this shard: the exact inputs (hashed) and the
    /// tool version that produced it. A nightly build compares these against
    /// the current inputs and skips re-deriving an unchanged shard, so the
    /// pipeline stays deterministic and cheap. Absent for merged databases.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<Provenance>,
    /// Known components, keyed by canonical name (e.g. `cudart`, `cublas`).
    pub components: Vec<ComponentFingerprint>,
}

/// First-party release metadata for a shard, copied verbatim from the redist
/// manifest's top-level fields. Never guessed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ReleaseInfo {
    /// The CUDA release label this shard was derived from (e.g. `12.4.1`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// The manifest's `release_date` (e.g. `2024-04-03`), a single first-party
    /// date for the whole release. There is no per-file publish date in the
    /// redist manifest, so this is the only grounded date we record.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date: Option<String>,
}

/// Records the exact inputs a shard was derived from, so a rebuild can prove
/// whether re-derivation is needed. Every field is content-addressed or a fixed
/// tool identifier; none is guessed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Provenance {
    /// sha256 (lowercase hex) of the exact redist manifest bytes used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manifest_sha256: Option<String>,
    /// sha256 digests (lowercase hex, sorted, de-duplicated) of every corpus
    /// archive whose unpacked binaries contributed to this shard. Empty when
    /// the shard was derived from the manifest alone (no binary layer).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub corpus_sha256: Vec<String>,
    /// The `cargo xtask` tool version that produced this shard, so a change in
    /// derivation logic (new tool version) also forces a rebuild.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_version: Option<String>,
}

/// Everything known about one CUDA component for identification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentFingerprint {
    /// Canonical component name (e.g. `cudart`, `cublas`, `cudnn`, `nccl`).
    pub name: String,
    /// Human-readable component description as NVIDIA states it in the redist
    /// manifest (e.g. `CUDA Runtime (cudart)`). First-party, never guessed;
    /// absent when no manifest provided one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// License name as NVIDIA states it in the redist manifest (e.g. `CUDA
    /// Toolkit`). First-party; absent when no manifest provided one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub license: Option<String>,
    /// SONAME stems this component is published under, without the version
    /// suffix (e.g. `libcudart.so`, `libcublas.so`). Used to attribute a
    /// dynamic dependency or an embedded library to this component.
    #[serde(default)]
    pub soname_stems: Vec<String>,
    /// Known exact file hashes (sha256, lowercase hex) mapped to the exact
    /// version(s) they identify. A hash match is the strongest signal.
    ///
    /// The value is a *set* of versions, not one: NVIDIA re-ships a
    /// byte-identical library under more than one component version across
    /// toolkit releases (the binary was not rebuilt, only relabeled). Such a
    /// hash therefore legitimately corresponds to every one of those versions,
    /// and recording all of them is the truthful claim: collapsing to a single
    /// version would silently discard the others. Sorted and de-duplicated.
    #[serde(default)]
    pub file_hashes: BTreeMap<String, Vec<String>>,
    /// Known GNU build-ids (lowercase hex) mapped to the version(s) they
    /// identify. A set for the same reason as [`Self::file_hashes`]: one
    /// build-id can belong to several relabeled-but-identical releases.
    #[serde(default)]
    pub build_ids: BTreeMap<String, Vec<String>>,
    /// Version-string patterns to look for in rodata, each a plain substring
    /// (not a regex) plus the capture rule. Kept intentionally simple and
    /// data-driven; the derivation step records the exact observed strings.
    #[serde(default)]
    pub version_markers: Vec<VersionMarker>,
    /// Component-identifying exported symbol names derived from this component's
    /// binaries (e.g. `ncclAllReduce`, `cutensorInit`). These are the public,
    /// namespaced API symbols NVIDIA ships; they survive static *linking* and
    /// are present in a static archive's member objects, where a file hash or
    /// SONAME is not. A match on this set names the component (never a version),
    /// so it is a `Likely`-strength signal, the honest claim for the large
    /// static archives whose member hashes are not fingerprinted. Sorted and
    /// de-duplicated. Empty for components with no derived symbol set.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub symbol_markers: Vec<String>,
    /// Maps each observed component version to the CUDA toolkit release
    /// label(s) that shipped it, derived first-party from the redist manifest's
    /// `release_label`. This is the grounded link that lets toolkit-level
    /// advisories (keyed to a CUDA release like `12.4.1`) correlate against a
    /// scanned individual library keyed to its own version (e.g. cudart
    /// `12.4.127`). A version may appear in more than one release, so the value
    /// is a sorted, de-duplicated set.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub release_versions: BTreeMap<String, Vec<String>>,
}

/// A documented version-string marker derived from a real binary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VersionMarker {
    /// A literal substring that, when present in rodata, indicates this
    /// component (e.g. a product banner). Matched literally, never guessed.
    pub contains: String,
    /// The version this marker attributes, when the marker itself is
    /// version-specific. `None` means the marker only supports identity, not a
    /// version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

impl FingerprintDb {
    /// The current DB schema version this build understands.
    ///
    /// v2 changed `file_hashes`/`build_ids` values from a single version string
    /// to a set of versions (see those fields); a v1 reader cannot interpret v2
    /// shards, so the version is bumped. v3 adds `symbol_markers` (an additive,
    /// defaulted field): a v2 reader would reject the unknown field, so the
    /// version is bumped again, but a v3 reader still accepts v2 shards (the
    /// field simply defaults to empty).
    pub const CURRENT_SCHEMA: u32 = 3;

    /// Load a database from JSON bytes.
    ///
    /// # Errors
    /// Returns an error if the JSON is malformed or its `schema_version` is
    /// newer than this build understands.
    pub fn from_json(bytes: &[u8]) -> Result<Self, DbError> {
        let db: FingerprintDb =
            serde_json::from_slice(bytes).map_err(|e| DbError::Parse(e.to_string()))?;
        if db.schema_version > Self::CURRENT_SCHEMA {
            return Err(DbError::UnsupportedSchema {
                found: db.schema_version,
                supported: Self::CURRENT_SCHEMA,
            });
        }
        Ok(db)
    }

    /// True if the database has no components (the default state before any
    /// fingerprints have been derived and committed).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.components.is_empty()
    }

    /// Load and merge every `*.json` shard in a directory into one database.
    ///
    /// The fingerprint database is sharded on disk (one file per NVIDIA release;
    /// see `fingerprints/README.md`) so that refreshes produce small, reviewable
    /// diffs and growth stays bounded per file. This reads them in sorted order
    /// for determinism and merges them by canonical component name.
    ///
    /// Conflicting facts are never silently overwritten: if two shards map the
    /// same file hash or build-id to *different* versions, the collision is
    /// recorded in the returned [`MergeReport`] so it can be investigated. The
    /// first-seen value wins in the merged database, keeping the result
    /// deterministic.
    ///
    /// A missing or empty directory yields an empty database and no conflicts.
    ///
    /// # Errors
    /// Returns [`DbError::Parse`] if a shard is malformed and
    /// [`DbError::UnsupportedSchema`] if a shard's schema is too new.
    pub fn from_dir(dir: &std::path::Path) -> Result<(Self, MergeReport), DbError> {
        // Collect `*.json` shards recursively, so a parent directory holding
        // per-product subdirectories (`fingerprints/cuda`, `fingerprints/cudnn`,
        // ...) loads them all. Shard file names are globally unique across
        // products, so a flat merge is unambiguous.
        let mut shards: Vec<std::path::PathBuf> = Vec::new();
        if collect_json_shards(dir, &mut shards).is_err() {
            // A not-yet-populated database directory is not an error.
            return Ok((Self::default(), MergeReport::default()));
        }
        shards.sort();

        let mut merged = Self {
            schema_version: Self::CURRENT_SCHEMA,
            release: None,
            release_dates: BTreeMap::new(),
            provenance: None,
            components: Vec::new(),
        };
        let report = MergeReport::default();

        for shard in shards {
            let bytes = std::fs::read(&shard).map_err(|e| DbError::Parse(e.to_string()))?;
            let db = Self::from_json(&bytes)?;
            merged.merge_from(db);
        }

        merged.components.sort_by(|a, b| a.name.cmp(&b.name));
        Ok((merged, report))
    }

    /// Merge another database into this one.
    ///
    /// Version sets are unioned, so a hash or build-id that appears in several
    /// shards ends up mapped to every version it represents. There is no
    /// "conflict" to report: an identical binary shipped under multiple version
    /// labels is a fact to record, not a collision to resolve.
    fn merge_from(&mut self, other: FingerprintDb) {
        // Fold this shard's release date into the merged date map, so the
        // aggregate database can date a finding by the release that shipped it.
        if let Some(release) = &other.release {
            if let (Some(label), Some(date)) = (&release.label, &release.date) {
                self.release_dates
                    .entry(label.clone())
                    .or_insert_with(|| date.clone());
            }
        }
        for incoming in other.components {
            if let Some(existing) = self.components.iter_mut().find(|c| c.name == incoming.name) {
                // First-seen descriptive metadata wins; fill only if absent.
                if existing.description.is_none() {
                    existing.description = incoming.description;
                }
                if existing.license.is_none() {
                    existing.license = incoming.license;
                }
                merge_version_map(&mut existing.file_hashes, incoming.file_hashes);
                merge_version_map(&mut existing.build_ids, incoming.build_ids);
                extend_unique(&mut existing.soname_stems, incoming.soname_stems);
                extend_unique(&mut existing.version_markers, incoming.version_markers);
                extend_unique(&mut existing.symbol_markers, incoming.symbol_markers);
                existing.symbol_markers.sort();
                for (version, releases) in incoming.release_versions {
                    let set = existing.release_versions.entry(version).or_default();
                    for release in releases {
                        crate::matcher::insert_version(set, &release);
                    }
                }
            } else {
                self.components.push(incoming);
            }
        }
    }
}

/// Recursively collect every `*.json` shard under `dir` into `out`.
///
/// Recursion lets a parent fingerprints directory hold per-product
/// subdirectories (`fingerprints/cuda`, `fingerprints/cudnn`, ...) while scans
/// load the union with one call. Returns an error only if the top-level
/// directory cannot be read; unreadable nested entries are skipped.
fn collect_json_shards(
    dir: &std::path::Path,
    out: &mut Vec<std::path::PathBuf>,
) -> std::io::Result<()> {
    collect_files_matching(dir, out, is_shard_file)
}

/// Recursively collect files under `dir` for which `accept` returns true, into
/// `out`. Only the top-level read can fail; errors reading nested directories
/// are ignored so one unreadable subtree does not fail the whole load.
pub(crate) fn collect_files_matching(
    dir: &std::path::Path,
    out: &mut Vec<std::path::PathBuf>,
    accept: fn(&std::path::Path) -> bool,
) -> std::io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let Ok(entry) = entry else { continue };
        let path = entry.path();
        if path.is_dir() {
            let _ = collect_files_matching(&path, out, accept);
        } else if accept(&path) {
            out.push(path);
        }
    }
    Ok(())
}

/// True for a fingerprint shard file. Shards are named `redistrib_*.json`,
/// mirroring NVIDIA's redist manifest naming. Other JSON that shares the
/// database tree, notably the `corpus.*.lock.json` provenance locks that sit
/// beside the per-product shard directories, is deliberately skipped so the
/// recursive load never tries to parse a non-shard document.
fn is_shard_file(path: &std::path::Path) -> bool {
    if path.extension().and_then(|s| s.to_str()) != Some("json") {
        return false;
    }
    path.file_name()
        .and_then(|s| s.to_str())
        .is_some_and(|name| name.starts_with("redistrib_"))
}

/// Union one hash/build-id version map into another. Each key accumulates the
/// full set of versions it maps to, kept sorted and de-duplicated so the result
/// is deterministic regardless of shard order.
fn merge_version_map(
    into: &mut BTreeMap<String, Vec<String>>,
    from: BTreeMap<String, Vec<String>>,
) {
    for (key, versions) in from {
        let set = into.entry(key).or_default();
        for version in versions {
            crate::matcher::insert_version(set, &version);
        }
    }
}

/// Append each item from `from` to `into`, skipping values already present.
fn extend_unique<T: PartialEq>(into: &mut Vec<T>, from: Vec<T>) {
    for item in from {
        if !into.contains(&item) {
            into.push(item);
        }
    }
}
/// The result of merging fingerprint shards.
///
/// With version sets (see [`ComponentFingerprint::file_hashes`]) there is no
/// longer a version collision to report, identical bytes under multiple
/// version labels are unioned rather than treated as a conflict, so this is
/// retained as a stable return type that callers can inspect, and is empty in
/// all current cases. It is kept (rather than removed) so the merge API can
/// grow future, genuinely-conflicting diagnostics without another signature
/// change.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MergeReport {
    /// Human-readable descriptions of any cross-shard collisions encountered.
    /// Empty in the normal case (version sets absorb the only case that used to
    /// produce one).
    pub conflicts: Vec<String>,
}

impl MergeReport {
    /// True if the merge was clean (no conflicts).
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.conflicts.is_empty()
    }
}

/// Errors from loading a fingerprint database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DbError {
    /// The JSON could not be parsed.
    Parse(String),
    /// The database uses a schema newer than this build supports.
    UnsupportedSchema { found: u32, supported: u32 },
}

impl std::fmt::Display for DbError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Parse(msg) => write!(f, "fingerprint database parse error: {msg}"),
            Self::UnsupportedSchema { found, supported } => write!(
                f,
                "fingerprint database schema {found} is newer than supported {supported}"
            ),
        }
    }
}

impl std::error::Error for DbError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_db_is_empty() {
        let db = FingerprintDb::default();
        assert!(db.is_empty());
        assert_eq!(db.schema_version, 0);
    }

    #[test]
    fn round_trips_a_minimal_component() {
        let json = r#"{
            "schema_version": 1,
            "components": [
                {
                    "name": "cudart",
                    "soname_stems": ["libcudart.so"],
                    "file_hashes": {},
                    "build_ids": {},
                    "version_markers": []
                }
            ]
        }"#;
        let db = FingerprintDb::from_json(json.as_bytes()).unwrap();
        assert_eq!(db.components.len(), 1);
        assert_eq!(db.components[0].name, "cudart");
        assert_eq!(db.components[0].soname_stems, vec!["libcudart.so"]);
    }

    #[test]
    fn rejects_future_schema() {
        let json = r#"{ "schema_version": 999, "components": [] }"#;
        let err = FingerprintDb::from_json(json.as_bytes()).unwrap_err();
        assert!(matches!(err, DbError::UnsupportedSchema { .. }));
    }

    #[test]
    fn rejects_unknown_fields() {
        let json = r#"{ "schema_version": 1, "bogus": true }"#;
        assert!(FingerprintDb::from_json(json.as_bytes()).is_err());
    }

    #[test]
    fn release_and_provenance_round_trip() {
        let json = r#"{
            "schema_version": 1,
            "release": { "label": "12.4.1", "date": "2024-04-03" },
            "provenance": {
                "manifest_sha256": "abc123",
                "corpus_sha256": ["dd", "ee"],
                "tool_version": "0.1.0"
            },
            "components": [ { "name": "cudart" } ]
        }"#;
        let db = FingerprintDb::from_json(json.as_bytes()).unwrap();
        let release = db.release.as_ref().unwrap();
        assert_eq!(release.label.as_deref(), Some("12.4.1"));
        assert_eq!(release.date.as_deref(), Some("2024-04-03"));
        let prov = db.provenance.as_ref().unwrap();
        assert_eq!(prov.manifest_sha256.as_deref(), Some("abc123"));
        assert_eq!(prov.corpus_sha256, vec!["dd", "ee"]);
        assert_eq!(prov.tool_version.as_deref(), Some("0.1.0"));

        // A merged (multi-release) database carries neither block.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("s.json"), json).unwrap();
        let (merged, _) = FingerprintDb::from_dir(dir.path()).unwrap();
        assert!(merged.release.is_none());
        assert!(merged.provenance.is_none());
    }

    #[test]
    fn from_dir_on_missing_directory_is_empty_and_clean() {
        let (db, report) =
            FingerprintDb::from_dir(std::path::Path::new("/nonexistent/cudabom/fp")).unwrap();
        assert!(db.is_empty());
        assert!(report.is_clean());
    }

    #[test]
    fn from_dir_merges_shards_and_dedups_stems() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("redistrib_a.json"),
            r#"{ "schema_version": 2, "components": [
                { "name": "cudart", "soname_stems": ["libcudart.so"],
                  "file_hashes": { "aa": ["12.4.1"] } } ] }"#,
        )
        .unwrap();
        std::fs::write(
            dir.path().join("redistrib_b.json"),
            r#"{ "schema_version": 2, "components": [
                { "name": "cudart", "soname_stems": ["libcudart.so"],
                  "file_hashes": { "bb": ["12.5.0"] } },
                { "name": "cublas", "soname_stems": ["libcublas.so"] } ] }"#,
        )
        .unwrap();

        let (db, report) = FingerprintDb::from_dir(dir.path()).unwrap();
        assert!(report.is_clean());
        // Two components, sorted: cublas, cudart.
        assert_eq!(db.components.len(), 2);
        assert_eq!(db.components[0].name, "cublas");
        let cudart = &db.components[1];
        // Hashes from both shards merged; the stem was deduplicated.
        assert_eq!(cudart.file_hashes.len(), 2);
        assert_eq!(cudart.soname_stems, vec!["libcudart.so"]);
    }

    #[test]
    fn from_dir_unions_versions_for_identical_bytes() {
        let dir = tempfile::tempdir().unwrap();
        // The same hash under two different versions: NVIDIA re-shipped a
        // byte-identical library under a new label. Both versions are correct,
        // so the merge must record the union rather than dropping one.
        std::fs::write(
            dir.path().join("redistrib_01.json"),
            r#"{ "schema_version": 2, "components": [
                { "name": "cudart", "file_hashes": { "dead": ["12.4.1"] } } ] }"#,
        )
        .unwrap();
        std::fs::write(
            dir.path().join("redistrib_02.json"),
            r#"{ "schema_version": 2, "components": [
                { "name": "cudart", "file_hashes": { "dead": ["12.9.9"] } } ] }"#,
        )
        .unwrap();

        let (db, report) = FingerprintDb::from_dir(dir.path()).unwrap();
        // No conflict: an identical binary under multiple versions is a fact,
        // not a collision.
        assert!(report.is_clean());
        // Both versions are recorded, sorted and de-duplicated.
        assert_eq!(
            db.components[0].file_hashes["dead"],
            vec!["12.4.1".to_string(), "12.9.9".to_string()]
        );
    }

    #[test]
    fn from_dir_recurses_into_per_product_subdirectories() {
        // The multi-tree layout: shards live in per-product subdirectories
        // (`cuda/`, `cudnn/`). A single load of the parent must merge them all.
        let dir = tempfile::tempdir().unwrap();
        let cuda = dir.path().join("cuda");
        let cudnn = dir.path().join("cudnn");
        std::fs::create_dir_all(&cuda).unwrap();
        std::fs::create_dir_all(&cudnn).unwrap();
        std::fs::write(
            cuda.join("redistrib_12.4.1.json"),
            r#"{ "schema_version": 2, "components": [
                { "name": "cudart", "soname_stems": ["libcudart.so"] } ] }"#,
        )
        .unwrap();
        std::fs::write(
            cudnn.join("redistrib_9.27.0.json"),
            r#"{ "schema_version": 2, "components": [
                { "name": "cudnn", "soname_stems": ["libcudnn.so"] } ] }"#,
        )
        .unwrap();

        let (db, report) = FingerprintDb::from_dir(dir.path()).unwrap();
        assert!(report.is_clean());
        let names: Vec<&str> = db.components.iter().map(|c| c.name.as_str()).collect();
        assert!(names.contains(&"cudart"), "cuda subdir loaded");
        assert!(names.contains(&"cudnn"), "cudnn subdir loaded");
    }

    #[test]
    fn v2_shard_without_symbol_markers_still_loads_under_v3() {
        // v3 added `symbol_markers` as a defaulted field, so an older v2 shard
        // (which omits it) must still load, with the field defaulting to empty.
        let json = r#"{
            "schema_version": 2,
            "components": [
                { "name": "cudart", "soname_stems": ["libcudart.so"],
                  "file_hashes": { "aa": ["12.4.1"] } }
            ]
        }"#;
        let db = FingerprintDb::from_json(json.as_bytes()).unwrap();
        assert_eq!(db.components.len(), 1);
        assert!(
            db.components[0].symbol_markers.is_empty(),
            "a v2 shard has no symbol_markers; the field defaults to empty"
        );
    }

    #[test]
    fn symbol_markers_round_trip_and_merge() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("redistrib_a.json"),
            r#"{ "schema_version": 3, "components": [
                { "name": "nccl", "symbol_markers": ["ncclAllReduce"] } ] }"#,
        )
        .unwrap();
        std::fs::write(
            dir.path().join("redistrib_b.json"),
            r#"{ "schema_version": 3, "components": [
                { "name": "nccl", "symbol_markers": ["ncclCommInitRank", "ncclAllReduce"] } ] }"#,
        )
        .unwrap();

        let (db, report) = FingerprintDb::from_dir(dir.path()).unwrap();
        assert!(report.is_clean());
        assert_eq!(db.components.len(), 1);
        // Markers are unioned, sorted, and de-duplicated.
        assert_eq!(
            db.components[0].symbol_markers,
            vec!["ncclAllReduce".to_string(), "ncclCommInitRank".to_string()]
        );
    }
}
