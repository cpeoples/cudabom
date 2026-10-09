//! CUDA component identification for cudabom.
//!
//! Responsibility: own the fingerprint database and the matchers that turn raw
//! facts (from `cudabom-elf`, `cudabom-fatbin`) into
//! [`cudabom_core::Finding`]s: a CUDA component identity, a
//! [`cudabom_core::Relationship`], and a [`cudabom_core::Confidence`] justified
//! by an explicit [`cudabom_core::Evidence`] list.
//!
//! The confidence rules (spec Section 7.2) are implemented in the `matcher`
//! module and documented in `docs/evidence-model.md`. This crate never asserts
//! more than the evidence supports: a confident wrong answer is worse than
//! "unknown".
//!
//! The database is data-driven and empty by default; cudabom does not invent
//! fingerprints (see the `db` module). With an empty database, only the structural
//! (SONAME-grammar) signals produce output, and only as a dependency edge; no
//! component is *named* without derived fingerprint data backing the stem.

mod binary;
mod corpus;
mod db;
mod derive;
mod matcher;
mod redist;
mod soname;

pub use binary::{
    component_symbols, fingerprint_binary, symbol_fingerprint, to_db, BinaryError,
    BinaryFingerprint, BinaryProvenance,
};
pub use corpus::{lock_from_manifest, CorpusEntry, CorpusLock};
pub use db::{
    ComponentFingerprint, DbError, FingerprintDb, MergeReport, Provenance, ReleaseInfo,
    VersionMarker,
};
pub use derive::{
    advisory_terms, canonicalize_declared_name, derive, resolve_component, soname_stems_for,
    Derived,
};
pub use matcher::identify_file;
pub use redist::{HashScope, RedistArchive, RedistComponent, RedistError, RedistManifest};

use cudabom_core::{Evidence, EvidenceKind, Location};
use cudabom_elf::ElfFacts;
use cudabom_fatbin::GpuCode;
use cudabom_pe::PeFacts;

/// The per-file facts the identification engine consumes.
///
/// This is the neutral hand-off between the fact extractors and the matcher, so
/// the CLI can assemble it from whatever it gathered without the identify crate
/// depending on the extractor.
#[derive(Debug, Clone)]
pub struct FileFacts {
    /// Logical path of the file within the scanned artifact.
    pub path: String,
    /// sha256 of the file's bytes, if computed.
    pub sha256: Option<String>,
    /// For container images: the layer digest this file came from.
    pub layer_digest: Option<String>,
    /// ELF facts, when the file is an ELF.
    pub elf: Option<ElfFacts>,
    /// PE facts, when the file is a Windows PE image.
    pub pe: Option<PeFacts>,
    /// GPU code facts, when the file is a standalone fatbin or PTX module.
    pub gpu_code: Option<GpuCode>,
}

impl FileFacts {
    /// Build the [`Location`] for evidence pointing at this file.
    #[must_use]
    pub fn location(&self) -> Location {
        Location {
            path: self.path.clone(),
            sha256: self.sha256.clone(),
            layer_digest: self.layer_digest.clone(),
        }
    }

    /// The target machine architecture of this file, when known.
    ///
    /// Reads the ELF `e_machine`-derived name (e.g. `X86_64`, `Aarch64`) or,
    /// for Windows images, the PE COFF machine name. Returns `None` for inputs
    /// that carry no architecture (e.g. a bare SBOM entry or a GPU code object).
    #[must_use]
    pub fn architecture(&self) -> Option<&str> {
        if let Some(elf) = &self.elf {
            return Some(elf.architecture.as_str());
        }
        if let Some(pe) = &self.pe {
            return Some(pe.machine.as_str());
        }
        None
    }

    /// Build an [`Architecture`](EvidenceKind::Architecture) evidence item for
    /// this file, when its architecture is known.
    #[must_use]
    pub fn architecture_evidence(&self) -> Option<Evidence> {
        self.architecture().map(|arch| Evidence {
            kind: EvidenceKind::Architecture,
            location: self.location(),
            detail: arch.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cudabom_core::{Confidence, EvidenceKind, Relationship};
    use cudabom_elf::{ElfClass, ElfType, Endianness};

    /// A minimal ELF-facts value with the given soname and needed list.
    fn elf_with(soname: Option<&str>, needed: &[&str], build_id: Option<&str>) -> ElfFacts {
        ElfFacts {
            class: ElfClass::Elf64,
            endianness: Endianness::Little,
            elf_type: ElfType::SharedObject,
            architecture: "X86_64".to_string(),
            soname: soname.map(ToString::to_string),
            needed: needed.iter().map(ToString::to_string).collect(),
            runpaths: Vec::new(),
            build_id: build_id.map(ToString::to_string),
            section_names: Vec::new(),
            exported_symbols: Vec::new(),
            dynamically_linked: true,
        }
    }

    fn db_with_cudart() -> FingerprintDb {
        let json = r#"{
            "schema_version": 1,
            "components": [
                { "name": "cudart", "soname_stems": ["libcudart.so"] }
            ]
        }"#;
        FingerprintDb::from_json(json.as_bytes()).unwrap()
    }

    #[test]
    fn empty_db_names_nothing_from_soname() {
        let facts = FileFacts {
            path: "libcudart.so.12".into(),
            sha256: None,
            layer_digest: None,
            elf: Some(elf_with(Some("libcudart.so.12"), &[], None)),
            pe: None,
            gpu_code: None,
        };
        let findings = identify_file(&facts, &FingerprintDb::default());
        // No fingerprint data => no named component from a spoofable SONAME.
        assert!(
            findings.is_empty(),
            "an empty database must not name a component from a SONAME alone"
        );
    }

    #[test]
    fn known_stem_yields_likely_with_major_range() {
        let facts = FileFacts {
            path: "libcudart.so.12".into(),
            sha256: None,
            layer_digest: None,
            elf: Some(elf_with(Some("libcudart.so.12"), &[], None)),
            pe: None,
            gpu_code: None,
        };
        let findings = identify_file(&facts, &db_with_cudart());
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert_eq!(f.component.name, "cudart");
        assert_eq!(f.component.version.as_deref(), Some("12.x"));
        assert_eq!(f.confidence, Confidence::Likely);
        assert_eq!(f.component.relationship, Relationship::EmbeddedCopy);
        assert_eq!(f.evidence[0].kind, EvidenceKind::Soname);
    }

    #[test]
    fn findings_carry_the_binary_architecture() {
        // A SONAME-only `Likely` match on an sbsa (Aarch64) build must record the
        // architecture it came from, so x86_64 and sbsa findings are
        // distinguishable even when they share a stem and ABI major.
        let mut elf = elf_with(Some("libcudart.so.12"), &[], None);
        elf.architecture = "Aarch64".to_string();
        let facts = FileFacts {
            path: "libcudart.so.12".into(),
            sha256: None,
            layer_digest: None,
            elf: Some(elf),
            pe: None,
            gpu_code: None,
        };
        let findings = identify_file(&facts, &db_with_cudart());
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert_eq!(f.confidence, Confidence::Likely);
        let arch = f
            .evidence
            .iter()
            .find(|e| e.kind == EvidenceKind::Architecture)
            .expect("finding should carry an architecture evidence item");
        assert_eq!(arch.detail, "Aarch64");
    }

    #[test]
    fn needed_dependency_is_unknown_dynamic() {
        let facts = FileFacts {
            path: "app".into(),
            sha256: None,
            layer_digest: None,
            elf: Some(elf_with(None, &["libcudart.so.12"], None)),
            pe: None,
            gpu_code: None,
        };
        let findings = identify_file(&facts, &db_with_cudart());
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert_eq!(f.component.name, "cudart");
        assert_eq!(f.component.relationship, Relationship::DynamicDependency);
        assert_eq!(f.confidence, Confidence::Unknown);
        assert_eq!(f.evidence[0].kind, EvidenceKind::NeededEntry);
    }

    #[test]
    fn known_hash_yields_exact() {
        let json = r#"{
            "schema_version": 2,
            "components": [
                {
                    "name": "cudart",
                    "soname_stems": ["libcudart.so"],
                    "file_hashes": { "abc123": ["12.4.1"] }
                }
            ]
        }"#;
        let db = FingerprintDb::from_json(json.as_bytes()).unwrap();
        let facts = FileFacts {
            path: "libcudart.so.12".into(),
            sha256: Some("abc123".into()),
            layer_digest: None,
            elf: Some(elf_with(Some("libcudart.so.12"), &[], None)),
            pe: None,
            gpu_code: None,
        };
        let findings = identify_file(&facts, &db);
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert_eq!(f.confidence, Confidence::Exact);
        assert_eq!(f.component.version.as_deref(), Some("12.4.1"));
        assert_eq!(f.evidence[0].kind, EvidenceKind::KnownFileHash);
    }

    #[test]
    fn no_cuda_signal_yields_nothing() {
        let facts = FileFacts {
            path: "libz.so.1".into(),
            sha256: None,
            layer_digest: None,
            elf: Some(elf_with(Some("libz.so.1"), &["libc.so.6"], None)),
            pe: None,
            gpu_code: None,
        };
        let findings = identify_file(&facts, &db_with_cudart());
        assert!(
            findings.is_empty(),
            "a non-CUDA file must produce no findings"
        );
    }

    #[test]
    fn shared_build_id_stays_exact_and_surfaces_every_candidate_version() {
        // NVIDIA ships one byte-identical .so (one build-id) across several npp
        // patch releases. The match is Exact about the bytes but cannot single
        // out one micro version: `version` is the lowest (deterministic) and
        // `candidate_versions` carries the complete sorted set so the ambiguity
        // is explicit instead of silently reporting only the lowest.
        let json = r#"{
            "schema_version": 2,
            "components": [
                { "name": "npp", "soname_stems": ["libnppc.so"],
                  "build_ids": { "deadbeef": ["11.6.0.55", "11.4.0.110", "11.5.1.53"] } }
            ]
        }"#;
        let db = FingerprintDb::from_json(json.as_bytes()).unwrap();
        let facts = FileFacts {
            path: "libnppc.so.11".into(),
            sha256: None,
            layer_digest: None,
            elf: Some(elf_with(Some("libnppc.so.11"), &[], Some("deadbeef"))),
            pe: None,
            gpu_code: None,
        };
        let findings = identify_file(&facts, &db);
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert_eq!(f.confidence, Confidence::Exact);
        assert_eq!(f.component.name, "npp");
        // Lowest version is the deterministic representative.
        assert_eq!(f.component.version.as_deref(), Some("11.4.0.110"));
        // Full, sorted, de-duplicated candidate set is surfaced.
        assert_eq!(
            f.component.candidate_versions,
            vec![
                "11.4.0.110".to_string(),
                "11.5.1.53".to_string(),
                "11.6.0.55".to_string()
            ]
        );
        assert_eq!(f.evidence[0].kind, EvidenceKind::BuildId);
    }

    #[test]
    fn single_version_build_id_leaves_candidate_set_empty() {
        // The common case: one build-id -> one version. Exact, and no candidate
        // set (nothing ambiguous to show).
        let json = r#"{
            "schema_version": 2,
            "components": [
                { "name": "cudart", "soname_stems": ["libcudart.so"],
                  "build_ids": { "abc123": ["12.4.127"] } }
            ]
        }"#;
        let db = FingerprintDb::from_json(json.as_bytes()).unwrap();
        let facts = FileFacts {
            path: "libcudart.so.12".into(),
            sha256: None,
            layer_digest: None,
            elf: Some(elf_with(Some("libcudart.so.12"), &[], Some("abc123"))),
            pe: None,
            gpu_code: None,
        };
        let findings = identify_file(&facts, &db);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].confidence, Confidence::Exact);
        assert_eq!(findings[0].component.version.as_deref(), Some("12.4.127"));
        assert!(
            findings[0].component.candidate_versions.is_empty(),
            "a single exact version leaves candidate_versions empty"
        );
    }
}
