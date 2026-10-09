//! End-to-end tests for the `cudabom reconcile` command.
//!
//! These drive the real binary via `assert_cmd`. A hash-matched ELF yields an
//! exact `cudart` discovery; a declared CycloneDX SBOM is reconciled against it
//! to exercise the matched / declared-only / discovered-only buckets and the
//! attachment of declared VEX statements.

use assert_cmd::Command;
use object::write::{Object, StandardSection, Symbol, SymbolSection};
use object::{Architecture, BinaryFormat, Endianness, SymbolFlags, SymbolKind, SymbolScope};
use sha2::{Digest, Sha256};

fn write_elf(sym: &str) -> Vec<u8> {
    let mut obj = Object::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Little);
    let text = obj.section_id(StandardSection::Text);
    let off = obj.append_section_data(text, &[0x90, 0x90, 0x90, 0x90], 1);
    obj.add_symbol(Symbol {
        name: sym.as_bytes().to_vec(),
        value: off,
        size: 4,
        kind: SymbolKind::Text,
        scope: SymbolScope::Dynamic,
        weak: false,
        section: SymbolSection::Section(text),
        flags: SymbolFlags::None,
    });
    obj.write().unwrap()
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    let d = h.finalize();
    let mut out = String::with_capacity(d.len() * 2);
    for b in d {
        use std::fmt::Write as _;
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// Set up a temp dir with a hash-matched `cudart 12.4.127` ELF and a DB.
fn setup(dir: &std::path::Path) -> std::path::PathBuf {
    let elf = write_elf("reconcile_sym");
    let sha = sha256_hex(&elf);
    let elf_path = dir.join("libcudart.so.12");
    std::fs::write(&elf_path, &elf).unwrap();

    let db_path = dir.join("db.json");
    std::fs::write(
        &db_path,
        format!(
            r#"{{ "schema_version": 2, "components": [ {{ "name": "cudart", "soname_stems": ["libcudart.so"], "file_hashes": {{ "{sha}": ["12.4.127"] }} }} ] }}"#
        ),
    )
    .unwrap();
    db_path
}

#[test]
fn reconcile_matches_declared_and_flags_discovered_only() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = setup(dir.path());
    let elf_path = dir.path().join("libcudart.so.12");

    // Declaration: names cudart under an NGC-style name (matches), plus cublas
    // that is NOT in the artifact (declared-only), plus a non-CUDA package.
    let sbom_path = dir.path().join("sbom.json");
    std::fs::write(
        &sbom_path,
        r#"{
            "bomFormat": "CycloneDX",
            "components": [
                { "type": "library", "bom-ref": "c1", "name": "cuda-cudart", "version": "12.4.127" },
                { "type": "library", "name": "libcublas-12-4", "version": "12.4.5.8" },
                { "type": "library", "name": "openssl", "version": "3.0" }
            ]
        }"#,
    )
    .unwrap();

    // VEX: a not_affected statement about cudart, by bom-ref.
    let vex_path = dir.path().join("vex.json");
    std::fs::write(
        &vex_path,
        r#"{
            "bomFormat": "CycloneDX",
            "vulnerabilities": [
                { "id": "CVE-2025-23248",
                  "analysis": { "state": "not_affected", "justification": "code_not_reachable" },
                  "affects": [ { "ref": "c1" } ] }
            ]
        }"#,
    )
    .unwrap();

    let assert = Command::cargo_bin("cudabom")
        .unwrap()
        .args([
            "reconcile",
            elf_path.to_str().unwrap(),
            "--db",
            db_path.to_str().unwrap(),
            "--sbom",
            sbom_path.to_str().unwrap(),
            "--vex",
            vex_path.to_str().unwrap(),
            "--format",
            "json",
        ])
        .assert()
        .success();

    let out = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let json: serde_json::Value = serde_json::from_str(&out).unwrap();

    // cudart matched, with the VEX statement attached.
    let matched = json["matched"].as_array().unwrap();
    assert_eq!(matched.len(), 1);
    assert_eq!(matched[0]["component"], "cudart");
    assert_eq!(matched[0]["declared_vex"][0]["id"], "CVE-2025-23248");
    assert_eq!(matched[0]["declared_vex"][0]["state"], "not_affected");

    // cublas declared but not discovered.
    let declared_only = json["declared_only"].as_array().unwrap();
    assert_eq!(declared_only.len(), 1);
    assert_eq!(declared_only[0]["component"], "cublas");

    // No discovered-only here (cudart was declared); openssl counted as non-CUDA.
    assert!(
        json["discovered_only"].as_array().unwrap().is_empty(),
        "cudart was declared, so there is nothing discovered-only"
    );
    assert_eq!(json["non_cuda_declared"], 1);
}

#[test]
fn reconcile_flags_discovered_only_when_declaration_omits_cuda() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = setup(dir.path());
    let elf_path = dir.path().join("libcudart.so.12");

    // Declaration omits every CUDA component: cudart is discovered-only.
    let sbom_path = dir.path().join("sbom.json");
    std::fs::write(
        &sbom_path,
        r#"{ "bomFormat": "CycloneDX", "components": [ { "type": "library", "name": "openssl", "version": "3.0" } ] }"#,
    )
    .unwrap();

    let assert = Command::cargo_bin("cudabom")
        .unwrap()
        .args([
            "reconcile",
            elf_path.to_str().unwrap(),
            "--db",
            db_path.to_str().unwrap(),
            "--sbom",
            sbom_path.to_str().unwrap(),
            "--format",
            "json",
        ])
        .assert()
        .success();

    let out = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let json: serde_json::Value = serde_json::from_str(&out).unwrap();

    let discovered_only = json["discovered_only"].as_array().unwrap();
    assert_eq!(discovered_only.len(), 1);
    assert_eq!(discovered_only[0]["component"], "cudart");
    assert_eq!(discovered_only[0]["discovered_version"], "12.4.127");
}

#[test]
fn reconcile_without_any_declaration_source_errors() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = setup(dir.path());
    let elf_path = dir.path().join("libcudart.so.12");

    Command::cargo_bin("cudabom")
        .unwrap()
        .args([
            "reconcile",
            elf_path.to_str().unwrap(),
            "--db",
            db_path.to_str().unwrap(),
        ])
        .assert()
        .failure();
}

#[test]
fn reconcile_against_committed_ngc_fixtures() {
    // The committed NGC-shaped fixtures reconcile without error against a
    // discovered cudart, proving the fixtures parse and the pipeline runs.
    let dir = tempfile::tempdir().unwrap();
    let db_path = setup(dir.path());
    let elf_path = dir.path().join("libcudart.so.12");

    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let sbom = format!("{manifest_dir}/../../fixtures/ngc/sbom.cyclonedx.json");
    let vex = format!("{manifest_dir}/../../fixtures/ngc/vex.cyclonedx.json");

    let assert = Command::cargo_bin("cudabom")
        .unwrap()
        .args([
            "reconcile",
            elf_path.to_str().unwrap(),
            "--db",
            db_path.to_str().unwrap(),
            "--sbom",
            &sbom,
            "--vex",
            &vex,
            "--format",
            "json",
        ])
        .assert()
        .success();

    let out = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let json: serde_json::Value = serde_json::from_str(&out).unwrap();
    // cudart is declared in the fixture SBOM and discovered here -> matched,
    // carrying the fixture VEX statement.
    let matched = json["matched"].as_array().unwrap();
    assert!(matched.iter().any(|m| m["component"] == "cudart"));
}
