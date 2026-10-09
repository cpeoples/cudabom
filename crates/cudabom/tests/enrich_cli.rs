//! End-to-end tests for the `cudabom enrich` command.

use assert_cmd::Command;
use object::write::{Object, StandardSection, Symbol, SymbolSection};
use object::{Architecture, BinaryFormat, Endianness, SymbolFlags, SymbolKind, SymbolScope};

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
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    for b in digest {
        use std::fmt::Write as _;
        let _ = write!(out, "{b:02x}");
    }
    out
}

#[test]
fn enrich_merges_cuda_components_into_existing_sbom() {
    let elf = write_elf("enrich_sym");
    let sha = sha256_hex(&elf);
    let dir = tempfile::tempdir().unwrap();
    let elf_path = dir.path().join("libcudart.so.12");
    std::fs::write(&elf_path, &elf).unwrap();

    let db_path = dir.path().join("db.json");
    std::fs::write(
        &db_path,
        format!(
            r#"{{ "schema_version": 2, "components": [ {{ "name": "cudart", "soname_stems": ["libcudart.so"], "file_hashes": {{ "{sha}": ["12.4.1"] }} }} ] }}"#
        ),
    )
    .unwrap();

    let sbom_path = dir.path().join("input.cdx.json");
    std::fs::write(
        &sbom_path,
        r#"{
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1,
            "components": [ { "type": "library", "name": "numpy", "version": "1.26.0" } ]
        }"#,
    )
    .unwrap();

    let assert = Command::cargo_bin("cudabom")
        .unwrap()
        .args([
            "enrich",
            "--sbom",
            sbom_path.to_str().unwrap(),
            "--db",
            db_path.to_str().unwrap(),
            elf_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    let out = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let doc: serde_json::Value = serde_json::from_str(&out).unwrap();
    let components = doc["components"].as_array().unwrap();
    // numpy preserved, cudart added.
    assert!(components.iter().any(|c| c["name"] == "numpy"));
    let cudart = components
        .iter()
        .find(|c| c["name"] == "cudart")
        .expect("cudart added");
    assert_eq!(cudart["version"], "12.4.1");
    // cudabom recorded itself as a tool.
    assert!(doc["metadata"]["tools"]["components"]
        .as_array()
        .unwrap()
        .iter()
        .any(|t| t["name"] == "cudabom"));
}

#[test]
fn enrich_rejects_non_cyclonedx_input() {
    let dir = tempfile::tempdir().unwrap();
    let elf_path = dir.path().join("libcudart.so.12");
    std::fs::write(&elf_path, write_elf("x")).unwrap();

    let sbom_path = dir.path().join("bad.json");
    std::fs::write(&sbom_path, r#"{ "hello": "world" }"#).unwrap();

    Command::cargo_bin("cudabom")
        .unwrap()
        .args([
            "enrich",
            "--sbom",
            sbom_path.to_str().unwrap(),
            elf_path.to_str().unwrap(),
        ])
        .assert()
        .code(3); // Input error.
}
