//! Regression tests that validate cudabom against **real NVIDIA ground truth**.
//!
//! These load the committed fingerprint shards under `fingerprints/cuda/` (which
//! are derived 1:1 from official NVIDIA `redistrib_*.json` manifests) and assert
//! that:
//!
//! 1. the sharded directory loader merges them cleanly, and
//! 2. a real published-archive sha256 resolves to the exact version NVIDIA
//!    records for it, at `Exact` confidence.
//!
//! This is the first end-to-end check against real-world data: the sha256 values
//! asserted here are the actual checksums NVIDIA publishes for the CUDA 11.4.2
//! `cuda_cudart` redistributable archives. If the derivation, schema, loader, or
//! matcher regress, these fail.

use std::path::PathBuf;

use cudabom_core::{Confidence, EvidenceKind, Relationship};
use cudabom_identify::{identify_file, FileFacts, FingerprintDb};

/// Absolute path to the repository's committed fingerprint shard directory.
fn fingerprints_cuda_dir() -> PathBuf {
    // CARGO_MANIFEST_DIR is crates/cudabom-identify; the shards live at the repo
    // root under fingerprints/cuda.
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fingerprints/cuda")
}

#[test]
fn committed_shards_load_and_merge_cleanly() {
    let (db, report) = FingerprintDb::from_dir(&fingerprints_cuda_dir())
        .expect("load committed fingerprint shards");
    assert!(
        report.is_clean(),
        "committed shards have version conflicts: {:?}",
        report.conflicts
    );
    assert!(
        !db.is_empty(),
        "expected at least one derived component in fingerprints/cuda"
    );
}

#[test]
fn real_cudart_archive_hash_resolves_to_exact_version() {
    let (db, _) = FingerprintDb::from_dir(&fingerprints_cuda_dir()).expect("load committed shards");

    // The real sha256 NVIDIA publishes for the CUDA 11.4.2 cudart
    // linux-x86_64 archive (cuda_cudart-linux-x86_64-11.4.108-archive.tar.xz).
    let real_archive_sha = "d08a1b731e5175aa3ae06a6d1c6b3059dd9ea13836d947018ea5e3ec2ca3d62b";

    let facts = FileFacts {
        path: "cuda_cudart-linux-x86_64-11.4.108-archive.tar.xz".into(),
        sha256: Some(real_archive_sha.into()),
        layer_digest: None,
        elf: None,
        pe: None,
        gpu_code: None,
    };

    let findings = identify_file(&facts, &db);
    assert_eq!(findings.len(), 1, "expected exactly one finding");
    let f = &findings[0];
    assert_eq!(f.component.name, "cudart");
    assert_eq!(f.component.version.as_deref(), Some("11.4.108"));
    assert_eq!(f.confidence, Confidence::Exact);
    assert_eq!(f.component.relationship, Relationship::EmbeddedCopy);
    assert_eq!(f.evidence[0].kind, EvidenceKind::KnownFileHash);
    assert_eq!(f.evidence[0].detail, real_archive_sha);
}

#[test]
fn cudart_soname_is_known_after_loading_real_shards() {
    let (db, _) = FingerprintDb::from_dir(&fingerprints_cuda_dir()).expect("load committed shards");

    // A versioned cudart shared object should be attributable via its SONAME
    // stem, which the derived shard records.
    let cudart = db
        .components
        .iter()
        .find(|c| c.name == "cudart")
        .expect("cudart present in real shards");
    assert!(
        cudart.soname_stems.iter().any(|s| s == "libcudart.so"),
        "expected libcudart.so stem, got {:?}",
        cudart.soname_stems
    );
}
