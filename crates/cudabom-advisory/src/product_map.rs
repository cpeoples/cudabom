//! Mapping CSAF product identities to cudabom component names.
//!
//! CSAF bulletins name products in NVIDIA's own vocabulary (e.g. "CUDA Toolkit",
//! "cuDNN", full product-tree branch names). cudabom identifies components by
//! canonical short names (`cudart`, `cudnn`, ...). The bridge between the two is
//! this maintained, reviewed mapping, loaded from a file so it can be updated
//! without a code change.
//!
//! The map is intentionally explicit: a CSAF product that has no mapping is
//! *not* guessed. `cudabom db status` reports unmapped products so the map can
//! be extended, rather than silently dropping or misattributing an advisory.
//!
//! Matching is done on normalized product text (case-insensitive, trimmed) and
//! also supports substring rules, since CSAF product names often embed a
//! version (e.g. "NVIDIA CUDA Toolkit 12.4").

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// A product -> component mapping.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProductMap {
    /// Schema version of this map file.
    pub schema_version: u32,
    /// Exact (normalized) product name -> component name.
    pub exact: BTreeMap<String, String>,
    /// Ordered substring rules: if the normalized product text contains
    /// `contains`, it maps to `component`. Checked after exact matches, in
    /// order, so more specific rules can be listed first.
    pub rules: Vec<SubstringRule>,
}

/// A substring mapping rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubstringRule {
    /// Normalized substring to look for in the product text.
    pub contains: String,
    /// The cudabom component name to map to.
    pub component: String,
}

impl ProductMap {
    /// The current product-map schema version this build understands.
    pub const CURRENT_SCHEMA: u32 = 1;

    /// Load a product map from JSON bytes.
    ///
    /// # Errors
    /// Returns an error if the JSON is malformed or the schema is newer than
    /// this build understands.
    pub fn from_json(bytes: &[u8]) -> Result<Self, MapError> {
        let map: ProductMap =
            serde_json::from_slice(bytes).map_err(|e| MapError::Parse(e.to_string()))?;
        if map.schema_version > Self::CURRENT_SCHEMA {
            return Err(MapError::UnsupportedSchema {
                found: map.schema_version,
                supported: Self::CURRENT_SCHEMA,
            });
        }
        Ok(map)
    }

    /// Resolve a CSAF product name to a cudabom component name, or `None` when
    /// the product is not mapped.
    #[must_use]
    pub fn resolve(&self, product: &str) -> Option<&str> {
        let normalized = normalize(product);
        if let Some(component) = self.exact.get(&normalized) {
            return Some(component.as_str());
        }
        for rule in &self.rules {
            if normalized.contains(&normalize(&rule.contains)) {
                return Some(rule.component.as_str());
            }
        }
        None
    }
}

/// Normalize product text for matching: lowercase and collapse whitespace.
fn normalize(s: &str) -> String {
    s.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

/// Errors from loading a product map.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MapError {
    Parse(String),
    UnsupportedSchema { found: u32, supported: u32 },
}

impl std::fmt::Display for MapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Parse(msg) => write!(f, "product map parse error: {msg}"),
            Self::UnsupportedSchema { found, supported } => write!(
                f,
                "product map schema {found} is newer than supported {supported}"
            ),
        }
    }
}

impl std::error::Error for MapError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ProductMap {
        let json = r#"{
            "schema_version": 1,
            "exact": { "nvidia cuda runtime": "cudart" },
            "rules": [
                { "contains": "cuda toolkit", "component": "cuda-toolkit" },
                { "contains": "cudnn", "component": "cudnn" }
            ]
        }"#;
        ProductMap::from_json(json.as_bytes()).unwrap()
    }

    #[test]
    fn exact_match_is_case_and_space_insensitive() {
        let m = sample();
        assert_eq!(m.resolve("NVIDIA   CUDA  Runtime"), Some("cudart"));
    }

    #[test]
    fn substring_rule_matches_versioned_product_name() {
        let m = sample();
        assert_eq!(m.resolve("NVIDIA CUDA Toolkit 12.4"), Some("cuda-toolkit"));
        assert_eq!(m.resolve("cuDNN 9.0.0"), Some("cudnn"));
    }

    #[test]
    fn unmapped_product_returns_none() {
        let m = sample();
        assert_eq!(m.resolve("Some Unrelated Product"), None);
    }

    #[test]
    fn empty_map_maps_nothing() {
        let m = ProductMap::default();
        assert_eq!(m.resolve("anything"), None);
    }

    #[test]
    fn rejects_future_schema() {
        let json = r#"{ "schema_version": 99 }"#;
        assert!(matches!(
            ProductMap::from_json(json.as_bytes()),
            Err(MapError::UnsupportedSchema { .. })
        ));
    }
}
