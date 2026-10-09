//! NVIDIA CUDA redistributable manifest ingestion.
//!
//! NVIDIA publishes a signed JSON manifest for every CUDA release at
//! `https://developer.download.nvidia.com/compute/cuda/redist/redistrib_<ver>.json`
//! (schema: `redistrib-v2.schema.json`). Each manifest is small (tens of KB) and
//! lists, for every redistributable component, its exact `version` and, per
//! platform, the `relative_path`, `sha256`, `md5`, and `size` of the published
//! archive. This is authoritative ground truth: exact version <-> archive
//! sha256, straight from NVIDIA, with no need to download the archives to learn
//! it.
//!
//! cudabom uses these manifests two ways:
//!
//! 1. As the source for the version/hash layer of the fingerprint database
//!    (see [`crate::db`]): the archive sha256 pins the exact version of a
//!    *published redistributable archive*.
//! 2. As reviewed test ground truth: a scan of a real archive must reproduce the
//!    version the manifest records for its sha256.
//!
//! Integrity note: the sha256 in a manifest is of the **published archive**
//! (`*.tar.xz` / `*.zip`), not of an individual `.so` unpacked from it. cudabom
//! records this faithfully via [`HashScope`] so the identification layer never
//! claims an archive hash proves the identity of a file extracted from it.

use std::collections::BTreeMap;

/// A parsed CUDA redistributable manifest (`redistrib_*.json`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedistManifest {
    /// Release date, when present (e.g. `2021-09-07`).
    pub release_date: Option<String>,
    /// Release label, when present (e.g. `11.4.2`).
    pub release_label: Option<String>,
    /// Components, keyed by their manifest key (e.g. `cuda_cudart`).
    pub components: BTreeMap<String, RedistComponent>,
}

/// One redistributable component within a manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedistComponent {
    /// Manifest key (e.g. `cuda_cudart`).
    pub key: String,
    /// Descriptive name (e.g. `CUDA Runtime (cudart)`).
    pub name: String,
    /// License name (e.g. `CUDA Toolkit`).
    pub license: Option<String>,
    /// Exact component version (e.g. `11.4.108`).
    pub version: String,
    /// Per-platform published archives, keyed by platform (e.g.
    /// `linux-x86_64`).
    pub archives: BTreeMap<String, RedistArchive>,
}

/// One published archive for a component on a platform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedistArchive {
    /// Path relative to the manifest URL.
    pub relative_path: String,
    /// sha256 (lowercase hex) of the published archive.
    pub sha256: String,
    /// Size in bytes, when present.
    pub size: Option<u64>,
}

/// What a recorded hash actually identifies. The manifest's sha256 is of the
/// published *archive*, never of an individual file unpacked from it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashScope {
    /// The hash identifies a whole published redistributable archive.
    Archive,
}

/// Errors from parsing a redistributable manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RedistError {
    /// The JSON could not be parsed or did not match the manifest shape.
    Parse(String),
}

impl std::fmt::Display for RedistError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Parse(m) => write!(f, "redist manifest parse error: {m}"),
        }
    }
}

impl std::error::Error for RedistError {}

// --- Raw serde model ---------------------------------------------------------
//
// The manifest is a JSON object whose keys are a mix of scalar metadata
// (`release_date`, `release_label`, `release_product`, ...) and component
// objects. serde cannot express "every key except these known ones is a
// component", so the manifest is parsed as a generic map of `RawValue` and each
// value is classified: an object carrying a `version` is a component; anything
// else is metadata.

impl RedistManifest {
    /// Parse a `redistrib_*.json` manifest from bytes.
    ///
    /// # Errors
    /// Returns [`RedistError::Parse`] if the bytes are not a JSON object in the
    /// documented manifest shape.
    pub fn from_json(bytes: &[u8]) -> Result<Self, RedistError> {
        let root: BTreeMap<String, serde_json::Value> =
            serde_json::from_slice(bytes).map_err(|e| RedistError::Parse(e.to_string()))?;

        let mut release_date = None;
        let mut release_label = None;
        let mut components = BTreeMap::new();

        for (key, value) in root {
            match key.as_str() {
                "release_date" => release_date = value.as_str().map(ToString::to_string),
                "release_label" => release_label = value.as_str().map(ToString::to_string),
                // Other scalar metadata (release_product, etc.) is ignored.
                _ => {
                    if let Some(component) = parse_component(&key, &value) {
                        components.insert(key, component);
                    }
                }
            }
        }

        Ok(Self {
            release_date,
            release_label,
            components,
        })
    }
}

/// Classify and parse one top-level value as a component, or `None` if it is
/// scalar metadata rather than a component object.
fn parse_component(key: &str, value: &serde_json::Value) -> Option<RedistComponent> {
    let obj = value.as_object()?; // scalar metadata (a string/number/etc.)
                                  // A component object is identified by carrying a string `version`.
    let version = obj.get("version").and_then(serde_json::Value::as_str)?;

    let name = obj
        .get("name")
        .and_then(serde_json::Value::as_str)
        .unwrap_or(key)
        .to_string();
    let license = obj
        .get("license")
        .and_then(serde_json::Value::as_str)
        .map(ToString::to_string);

    let mut archives = BTreeMap::new();
    for (platform, pvalue) in obj {
        // Skip the scalar component fields and the `cuda_variant` array; only
        // per-platform objects carry archives.
        let Some(pobj) = pvalue.as_object() else {
            continue;
        };

        // Two manifest shapes exist:
        //
        // 1. Flat (CUDA toolkit, NVPL): the platform object *directly* carries
        //    `relative_path` + `sha256` for a single archive.
        // 2. CUDA-variant-nested (cuDNN, cuTENSOR, cuDSS, nvSHMEM, ...): the
        //    platform object's values are themselves archive objects, keyed by
        //    CUDA major variant (`cuda12`, `cuda13`), because the same release
        //    ships one archive per supported CUDA major. Each is recorded under
        //    a composite platform key `<platform>-<variant>` (e.g.
        //    `linux-x86_64-cuda12`) so both variants are preserved distinctly
        //    rather than one overwriting the other.
        //
        // Detect the flat shape by the presence of a `relative_path` string.
        if let Some(archive) = parse_archive(pobj) {
            archives.insert(platform.clone(), archive);
            continue;
        }
        for (variant, vvalue) in pobj {
            let Some(vobj) = vvalue.as_object() else {
                continue;
            };
            if let Some(archive) = parse_archive(vobj) {
                archives.insert(format!("{platform}-{variant}"), archive);
            }
        }
    }

    Some(RedistComponent {
        key: key.to_string(),
        name,
        license,
        version: version.to_string(),
        archives,
    })
}

/// Parse a single archive object (`relative_path` + `sha256` [+ `size`]), or
/// `None` if the object is not an archive leaf (e.g. a CUDA-variant container
/// whose children are the archives).
fn parse_archive(obj: &serde_json::Map<String, serde_json::Value>) -> Option<RedistArchive> {
    let (Some(relative_path), Some(sha256)) = (
        obj.get("relative_path").and_then(serde_json::Value::as_str),
        obj.get("sha256").and_then(serde_json::Value::as_str),
    ) else {
        return None;
    };
    // size is published as a string of bytes in the manifests.
    let size = obj.get("size").and_then(|s| {
        s.as_str()
            .and_then(|s| s.parse::<u64>().ok())
            .or_else(|| s.as_u64())
    });
    Some(RedistArchive {
        relative_path: relative_path.to_string(),
        sha256: sha256.to_ascii_lowercase(),
        size,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A trimmed but structurally faithful slice of a real `redistrib_*.json`.
    /// Values (versions, sha256) mirror the documented CUDA 11.4.2 manifest.
    const SAMPLE: &str = r#"{
        "release_date": "2021-09-07",
        "release_label": "11.4.2",
        "release_product": "cuda",
        "cuda_cudart": {
            "name": "CUDA Runtime (cudart)",
            "license": "CUDA Toolkit",
            "version": "11.4.108",
            "linux-x86_64": {
                "relative_path": "cuda_cudart/linux-x86_64/cuda_cudart-linux-x86_64-11.4.108-archive.tar.xz",
                "sha256": "d08a1b731e5175aa3ae06a6d1c6b3059dd9ea13836d947018ea5e3ec2ca3d62b",
                "md5": "da198656b27a3559004c3b7f20e5d074",
                "size": "828300"
            },
            "windows-x86_64": {
                "relative_path": "cuda_cudart/windows-x86_64/cuda_cudart-windows-x86_64-11.4.108-archive.zip",
                "sha256": "b59756c27658d1ea87a17c06d064d1336576431cd64da5d1790d909e455d06d3",
                "md5": "7f6837a46b78198402429a3760ab28fc",
                "size": "2897751"
            }
        }
    }"#;

    #[test]
    fn parses_release_metadata_and_components() {
        let m = RedistManifest::from_json(SAMPLE.as_bytes()).unwrap();
        assert_eq!(m.release_date.as_deref(), Some("2021-09-07"));
        assert_eq!(m.release_label.as_deref(), Some("11.4.2"));
        assert_eq!(m.components.len(), 1);

        let c = &m.components["cuda_cudart"];
        assert_eq!(c.key, "cuda_cudart");
        assert_eq!(c.name, "CUDA Runtime (cudart)");
        assert_eq!(c.license.as_deref(), Some("CUDA Toolkit"));
        assert_eq!(c.version, "11.4.108");
        assert_eq!(c.archives.len(), 2);
    }

    #[test]
    fn parses_per_platform_archive_ground_truth() {
        let m = RedistManifest::from_json(SAMPLE.as_bytes()).unwrap();
        let a = &m.components["cuda_cudart"].archives["linux-x86_64"];
        assert_eq!(
            a.sha256,
            "d08a1b731e5175aa3ae06a6d1c6b3059dd9ea13836d947018ea5e3ec2ca3d62b"
        );
        assert_eq!(a.size, Some(828_300));
        assert!(a.relative_path.ends_with("11.4.108-archive.tar.xz"));
    }

    #[test]
    fn ignores_scalar_metadata_that_is_not_a_component() {
        // release_product is a scalar; it must not become a component.
        let m = RedistManifest::from_json(SAMPLE.as_bytes()).unwrap();
        assert!(!m.components.contains_key("release_product"));
    }

    #[test]
    fn rejects_non_object_json() {
        assert!(matches!(
            RedistManifest::from_json(b"[]"),
            Err(RedistError::Parse(_))
        ));
    }

    #[test]
    fn sha256_is_lowercased() {
        let json = r#"{
            "cuda_x": {
                "version": "1.2.3",
                "linux-x86_64": {
                    "relative_path": "p",
                    "sha256": "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"
                }
            }
        }"#;
        let m = RedistManifest::from_json(json.as_bytes()).unwrap();
        assert_eq!(
            m.components["cuda_x"].archives["linux-x86_64"].sha256,
            "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
        );
    }

    /// A trimmed slice of a CUDA-variant-nested manifest (cuDNN/cuTENSOR shape):
    /// each platform object holds one archive per CUDA major variant.
    const VARIANT_SAMPLE: &str = r#"{
        "release_date": "2025-01-01",
        "release_label": "9.27.0",
        "release_product": "cudnn",
        "cudnn": {
            "name": "cuDNN",
            "license": "cuDNN",
            "version": "9.27.0.42",
            "cuda_variant": ["12", "13"],
            "linux-x86_64": {
                "cuda12": {
                    "relative_path": "cudnn/linux-x86_64/cudnn-9.27.0.42_cuda12-archive.tar.xz",
                    "sha256": "AA11",
                    "size": "100"
                },
                "cuda13": {
                    "relative_path": "cudnn/linux-x86_64/cudnn-9.27.0.42_cuda13-archive.tar.xz",
                    "sha256": "BB22",
                    "size": "200"
                }
            },
            "linux-sbsa": {
                "cuda12": {
                    "relative_path": "cudnn/linux-sbsa/cudnn-9.27.0.42_cuda12-archive.tar.xz",
                    "sha256": "CC33"
                }
            }
        }
    }"#;

    #[test]
    fn parses_cuda_variant_nested_archives_with_composite_keys() {
        let m = RedistManifest::from_json(VARIANT_SAMPLE.as_bytes()).unwrap();
        let c = &m.components["cudnn"];
        assert_eq!(c.version, "9.27.0.42");
        // One archive per (platform, variant), keyed `<platform>-<variant>`.
        assert_eq!(c.archives.len(), 3);
        assert_eq!(c.archives["linux-x86_64-cuda12"].sha256, "aa11");
        assert_eq!(c.archives["linux-x86_64-cuda12"].size, Some(100));
        assert_eq!(c.archives["linux-x86_64-cuda13"].sha256, "bb22");
        assert_eq!(c.archives["linux-sbsa-cuda12"].sha256, "cc33");
        assert_eq!(c.archives["linux-sbsa-cuda12"].size, None);
    }

    #[test]
    fn cuda_variant_array_field_is_not_mistaken_for_an_archive() {
        // The `cuda_variant` array must not become an archive entry.
        let m = RedistManifest::from_json(VARIANT_SAMPLE.as_bytes()).unwrap();
        let c = &m.components["cudnn"];
        assert!(!c.archives.keys().any(|k| k.contains("cuda_variant")));
    }

    #[test]
    fn flat_and_variant_shapes_can_coexist_across_components() {
        // A manifest mixing a flat component and a variant-nested one parses
        // both correctly (defensive: trees are not assumed homogeneous).
        let json = r#"{
            "release_label": "x",
            "flat_lib": {
                "version": "1.0",
                "linux-x86_64": { "relative_path": "flat", "sha256": "DEAD" }
            },
            "variant_lib": {
                "version": "2.0",
                "linux-x86_64": {
                    "cuda12": { "relative_path": "v12", "sha256": "BEEF" }
                }
            }
        }"#;
        let m = RedistManifest::from_json(json.as_bytes()).unwrap();
        assert_eq!(
            m.components["flat_lib"].archives["linux-x86_64"].sha256,
            "dead"
        );
        assert_eq!(
            m.components["variant_lib"].archives["linux-x86_64-cuda12"].sha256,
            "beef"
        );
    }
}
