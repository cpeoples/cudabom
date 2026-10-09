//! Derive fingerprint-database entries from real unpacked CUDA shared objects.
//!
//! The manifest-derived layer ([`mod@crate::derive`]) identifies published
//! *archives* by their sha256. This binary layer identifies an individual
//! shared object (`.so`) unpacked from such an archive, by two file-level
//! signals recovered from real bytes:
//!
//! - the **GNU build-id** (`.note.gnu.build-id`), which is stable across copies
//!   of the same build and is the strongest non-hash identifier, and
//! - the **file sha256**, which pins the exact file.
//!
//! Both are facts read from the binary, never guessed. Provenance, which
//! component and version a `.so` belongs to, comes from the archive it was
//! unpacked from (the manifest states the version), so the caller supplies it;
//! this module does not infer a version from a file name.
//!
//! The component's SONAME stem is also recorded, taken from the binary's own
//! `DT_SONAME`, so attribution and the strong signals share one source of truth.

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};

use cudabom_elf::parse;

use crate::db::{ComponentFingerprint, FingerprintDb};

/// The known provenance of a `.so`, supplied by the caller (from the archive it
/// was unpacked from).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BinaryProvenance {
    /// Canonical cudabom component name (e.g. `cudart`).
    pub component: String,
    /// Exact version the containing archive declares (e.g. `11.4.108`).
    pub version: String,
    /// CUDA toolkit release label that shipped this archive (the redist
    /// manifest's `release_label`, e.g. `12.4.1`), when known. Carries the
    /// first-party version -> release link into the binary fingerprint layer.
    pub release_label: Option<String>,
}

/// One derived signal set for a single `.so`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BinaryFingerprint {
    /// Canonical component name.
    pub component: String,
    /// Exact version.
    pub version: String,
    /// Lowercase hex sha256 of the file bytes.
    pub file_sha256: String,
    /// GNU build-id (lowercase hex), when the binary carries one.
    pub build_id: Option<String>,
    /// SONAME stem (e.g. `libcudart.so`), when derivable from `DT_SONAME`.
    pub soname_stem: Option<String>,
    /// CUDA toolkit release label that shipped this file, when known.
    pub release_label: Option<String>,
    /// Component-identifying exported symbols derived from this binary (the
    /// component's namespaced public API, e.g. `nccl*`). Populated for large
    /// static archives whose member hashes are not fingerprinted; empty
    /// otherwise. See [`ComponentFingerprint::symbol_markers`].
    pub symbol_markers: Vec<String>,
}

/// Errors from binary derivation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BinaryError {
    /// The bytes were not a parseable ELF shared object.
    NotElf(String),
}

impl std::fmt::Display for BinaryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotElf(m) => write!(f, "not a parseable ELF: {m}"),
        }
    }
}

impl std::error::Error for BinaryError {}

/// Derive the signal set for one shared object's bytes with known provenance.
///
/// # Errors
/// Returns [`BinaryError::NotElf`] if the bytes are not a parseable ELF.
pub fn fingerprint_binary(
    bytes: &[u8],
    provenance: &BinaryProvenance,
) -> Result<BinaryFingerprint, BinaryError> {
    let facts = parse(bytes).map_err(|e| BinaryError::NotElf(e.to_string()))?;
    Ok(BinaryFingerprint {
        component: provenance.component.clone(),
        version: provenance.version.clone(),
        file_sha256: hex_sha256(bytes),
        build_id: facts.build_id.clone(),
        soname_stem: facts.soname.as_deref().map(soname_stem),
        release_label: provenance.release_label.clone(),
        // A single shared object is identified by its hash/build-id/SONAME, not
        // a symbol set; the symbol-marker signal is reserved for the large
        // static archives those stronger signals cannot cover.
        symbol_markers: Vec::new(),
    })
}

/// Extract the component-identifying exported symbols from one ELF object's
/// bytes: the defined, global symbols whose name begins with the component's
/// namespace prefix (e.g. `nccl`, `cutensor`). NVIDIA's public APIs are
/// namespaced by component, so a `ncclAllReduce` symbol is NCCL unambiguously;
/// restricting to the prefix is the false-positive guard that keeps this a
/// defensible `Likely` signal. Returns an empty set for a non-ELF input, an
/// object with no matching symbols, or an empty prefix.
///
/// This is the signal used for large static archives, whose member hashes do
/// not survive static linking: the symbols do, and they name the component.
#[must_use]
pub fn component_symbols(bytes: &[u8], prefix: &str) -> Vec<String> {
    if prefix.is_empty() {
        return Vec::new();
    }
    let Ok(facts) = parse(bytes) else {
        return Vec::new();
    };
    let lower_prefix = prefix.to_ascii_lowercase();
    let mut symbols: Vec<String> = facts
        .exported_symbols
        .into_iter()
        .filter(|s| s.to_ascii_lowercase().starts_with(&lower_prefix))
        .collect();
    symbols.sort();
    symbols.dedup();
    symbols
}

/// Build a symbol-marker-only [`BinaryFingerprint`] for a static archive member
/// that is not hash-fingerprinted. Carries the component's namespaced exported
/// symbols (see [`component_symbols`]) and no file hash, so attribution is the
/// `Likely`-strength symbol signal rather than an exact hash.
#[must_use]
pub fn symbol_fingerprint(
    symbols: Vec<String>,
    provenance: &BinaryProvenance,
) -> Option<BinaryFingerprint> {
    if symbols.is_empty() {
        return None;
    }
    Some(BinaryFingerprint {
        component: provenance.component.clone(),
        version: provenance.version.clone(),
        // No file hash: a symbol set names the component, not an exact file.
        file_sha256: String::new(),
        build_id: None,
        soname_stem: None,
        release_label: provenance.release_label.clone(),
        symbol_markers: symbols,
    })
}

#[must_use]
pub fn to_db(fingerprints: &[BinaryFingerprint]) -> FingerprintDb {
    let mut by_component: BTreeMap<&str, ComponentFingerprint> = BTreeMap::new();

    for fp in fingerprints {
        let entry = by_component
            .entry(fp.component.as_str())
            .or_insert_with(|| ComponentFingerprint {
                name: fp.component.clone(),
                description: None,
                license: None,
                soname_stems: Vec::new(),
                file_hashes: BTreeMap::new(),
                build_ids: BTreeMap::new(),
                version_markers: Vec::new(),
                symbol_markers: Vec::new(),
                release_versions: BTreeMap::new(),
            });

        // Values are version sets: an identical binary can recur under several
        // versions (relabeled, not rebuilt), and each is a truthful attribution.
        // A symbol-only fingerprint carries no hash, so skip the hash map for it.
        if !fp.file_sha256.is_empty() {
            crate::matcher::insert_version(
                entry.file_hashes.entry(fp.file_sha256.clone()).or_default(),
                &fp.version,
            );
        }
        if let Some(build_id) = &fp.build_id {
            crate::matcher::insert_version(
                entry.build_ids.entry(build_id.clone()).or_default(),
                &fp.version,
            );
        }
        if let Some(stem) = &fp.soname_stem {
            if !entry.soname_stems.contains(stem) {
                entry.soname_stems.push(stem.clone());
            }
        }
        if let Some(release) = &fp.release_label {
            crate::matcher::insert_version(
                entry
                    .release_versions
                    .entry(fp.version.clone())
                    .or_default(),
                release,
            );
        }
        for symbol in &fp.symbol_markers {
            if !entry.symbol_markers.contains(symbol) {
                entry.symbol_markers.push(symbol.clone());
            }
        }
    }

    let mut components: Vec<ComponentFingerprint> = by_component.into_values().collect();
    components.sort_by(|a, b| a.name.cmp(&b.name));
    for c in &mut components {
        c.soname_stems.sort();
        c.symbol_markers.sort();
    }

    FingerprintDb {
        schema_version: FingerprintDb::CURRENT_SCHEMA,
        release: None,
        release_dates: std::collections::BTreeMap::new(),
        provenance: None,
        components,
    }
}

/// Reduce a full SONAME (`libcudart.so.12.4.108`) to its stem (`libcudart.so`).
/// Delegates to the canonical SONAME parser so the stem used here stays in
/// agreement with the one `matcher` compares against. A name without `.so` is
/// returned unchanged.
fn soname_stem(soname: &str) -> String {
    crate::soname::parse_soname(soname).map_or_else(|| soname.to_string(), |parts| parts.stem)
}

/// Lowercase hex sha256 of `bytes`.
fn hex_sha256(bytes: &[u8]) -> String {
    cudabom_core::hex_lower(&Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn soname_stem_strips_version_suffix() {
        assert_eq!(soname_stem("libcudart.so.12.4.108"), "libcudart.so");
        assert_eq!(soname_stem("libcublas.so.12"), "libcublas.so");
        assert_eq!(soname_stem("libcudart.so"), "libcudart.so");
        // No `.so` (unusual): returned unchanged.
        assert_eq!(soname_stem("weird"), "weird");
    }

    #[test]
    fn hex_sha256_is_lowercase_and_64_chars() {
        let h = hex_sha256(b"hello");
        assert_eq!(h.len(), 64);
        assert!(h
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
        assert_eq!(
            h,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn non_elf_bytes_are_rejected() {
        let prov = BinaryProvenance {
            component: "cudart".into(),
            version: "11.4.108".into(),
            release_label: None,
        };
        assert!(matches!(
            fingerprint_binary(b"not an elf", &prov),
            Err(BinaryError::NotElf(_))
        ));
    }

    #[test]
    fn to_db_groups_by_component_and_records_both_signals() {
        let fps = vec![
            BinaryFingerprint {
                component: "cudart".into(),
                version: "11.4.108".into(),
                file_sha256: "aa".into(),
                build_id: Some("bb".into()),
                soname_stem: Some("libcudart.so".into()),
                release_label: Some("11.4.2".into()),
                symbol_markers: Vec::new(),
            },
            BinaryFingerprint {
                component: "cudart".into(),
                version: "12.4.1".into(),
                file_sha256: "cc".into(),
                build_id: None,
                soname_stem: Some("libcudart.so".into()),
                release_label: None,
                symbol_markers: Vec::new(),
            },
            BinaryFingerprint {
                component: "cublas".into(),
                version: "12.4.1".into(),
                file_sha256: "dd".into(),
                build_id: Some("ee".into()),
                soname_stem: Some("libcublas.so".into()),
                release_label: None,
                symbol_markers: Vec::new(),
            },
        ];

        let db = to_db(&fps);
        assert_eq!(db.components.len(), 2);
        // Sorted: cublas, cudart.
        assert_eq!(db.components[0].name, "cublas");
        let cudart = &db.components[1];
        assert_eq!(cudart.file_hashes.len(), 2);
        assert_eq!(cudart.file_hashes["aa"], vec!["11.4.108".to_string()]);
        assert_eq!(cudart.file_hashes["cc"], vec!["12.4.1".to_string()]);
        // Only the first binary carried a build-id.
        assert_eq!(cudart.build_ids.len(), 1);
        assert_eq!(cudart.build_ids["bb"], vec!["11.4.108".to_string()]);
        // The duplicate stem was deduplicated.
        assert_eq!(cudart.soname_stems, vec!["libcudart.so"]);
        // The release mapping was recorded only for the binary that carried a
        // release label.
        assert_eq!(
            cudart.release_versions.get("11.4.108"),
            Some(&vec!["11.4.2".to_string()])
        );
        assert!(!cudart.release_versions.contains_key("12.4.1"));
    }

    #[test]
    fn component_symbols_empty_prefix_and_non_elf_yield_nothing() {
        // An empty prefix matches nothing (the guard), and non-ELF bytes parse
        // to nothing, never a panic.
        assert!(
            component_symbols(b"\x7fELF not really", "nccl").is_empty(),
            "malformed ELF bytes must yield no symbols"
        );
        assert!(
            component_symbols(b"not an elf at all", "nccl").is_empty(),
            "non-ELF bytes must yield no symbols"
        );
        assert!(
            component_symbols(b"anything", "").is_empty(),
            "an empty prefix must match no symbols"
        );
    }

    #[test]
    fn symbol_fingerprint_is_none_for_empty_set() {
        let prov = BinaryProvenance {
            component: "nccl".into(),
            version: "2.20.5".into(),
            release_label: None,
        };
        assert!(symbol_fingerprint(Vec::new(), &prov).is_none());
    }

    #[test]
    fn symbol_fingerprint_carries_markers_without_a_hash() {
        let prov = BinaryProvenance {
            component: "nccl".into(),
            version: "2.20.5".into(),
            release_label: Some("12.4.1".into()),
        };
        let fp = symbol_fingerprint(
            vec!["ncclAllReduce".into(), "ncclCommInitRank".into()],
            &prov,
        )
        .expect("non-empty symbol set yields a fingerprint");
        // A symbol fingerprint names the component via markers, with no file
        // hash (so it does not pollute the exact-hash map).
        assert!(
            fp.file_sha256.is_empty(),
            "a symbol fingerprint carries no file hash"
        );
        assert_eq!(fp.symbol_markers.len(), 2);

        // Folded into a DB, the markers land on the component and the empty hash
        // is not recorded as an exact signal.
        let db = to_db(&[fp]);
        assert_eq!(db.components.len(), 1);
        assert_eq!(db.components[0].name, "nccl");
        assert!(
            db.components[0].file_hashes.is_empty(),
            "the empty hash must not be recorded as an exact signal"
        );
        assert_eq!(
            db.components[0].symbol_markers,
            vec!["ncclAllReduce".to_string(), "ncclCommInitRank".to_string()]
        );
    }
}
