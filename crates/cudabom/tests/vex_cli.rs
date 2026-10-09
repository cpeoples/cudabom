//! End-to-end tests for the `cudabom vex` command.

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
fn vex_emits_cyclonedx_with_vulnerability_statement() {
    let elf = write_elf("vex_sym");
    let sha = sha256_hex(&elf);
    let dir = tempfile::tempdir().unwrap();
    let elf_path = dir.path().join("libcudart.so.12");
    std::fs::write(&elf_path, &elf).unwrap();

    let db_path = dir.path().join("db.json");
    std::fs::write(
        &db_path,
        format!(
            r#"{{ "schema_version": 2, "components": [ {{ "name": "cudart", "soname_stems": ["libcudart.so"], "file_hashes": {{ "{sha}": ["12.3"] }} }} ] }}"#
        ),
    )
    .unwrap();

    let adv_path = dir.path().join("advisories.json");
    std::fs::write(
        &adv_path,
        r#"{ "schema_version": 1, "advisories": [ { "id": "CVE-2025-0001", "affected": [ { "component": "cudart", "affected_ranges": [ { "introduced": "12.0", "fixed": "12.4" } ] } ] } ] }"#,
    )
    .unwrap();

    let assert = Command::cargo_bin("cudabom")
        .unwrap()
        .args([
            "vex",
            elf_path.to_str().unwrap(),
            "--db",
            db_path.to_str().unwrap(),
            "--advisories",
            adv_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    let out = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let bom: serde_json::Value = serde_json::from_str(&out).unwrap();

    assert_eq!(bom["bomFormat"], "CycloneDX");
    assert_eq!(bom["specVersion"], "1.6");
    let vulns = bom["vulnerabilities"].as_array().unwrap();
    assert_eq!(vulns.len(), 1);
    assert_eq!(vulns[0]["id"], "CVE-2025-0001");
    // cudart 12.3 is within the affected range -> exploitable.
    assert_eq!(vulns[0]["analysis"]["state"], "exploitable");
    // The statement points at the component's bom-ref.
    let affects_ref = vulns[0]["affects"][0]["ref"].as_str().unwrap();
    assert!(affects_ref.starts_with("cudabom:finding:"));
    // And that bom-ref exists among the components.
    let components = bom["components"].as_array().unwrap();
    assert!(components
        .iter()
        .any(|c| c["bom-ref"] == serde_json::Value::String(affects_ref.to_string())));
}

#[test]
fn vex_without_advisories_emits_sbom_with_no_vulnerabilities() {
    let elf = write_elf("vex_no_adv");
    let sha = sha256_hex(&elf);
    let dir = tempfile::tempdir().unwrap();
    let elf_path = dir.path().join("libcudart.so.12");
    std::fs::write(&elf_path, &elf).unwrap();

    let db_path = dir.path().join("db.json");
    std::fs::write(
        &db_path,
        format!(
            r#"{{ "schema_version": 2, "components": [ {{ "name": "cudart", "soname_stems": ["libcudart.so"], "file_hashes": {{ "{sha}": ["12.3"] }} }} ] }}"#
        ),
    )
    .unwrap();

    let assert = Command::cargo_bin("cudabom")
        .unwrap()
        .args([
            "vex",
            elf_path.to_str().unwrap(),
            "--db",
            db_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    let out = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let bom: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(bom["bomFormat"], "CycloneDX");
    // The component is present, but there are no vulnerability statements.
    assert!(
        !bom["components"].as_array().unwrap().is_empty(),
        "the component is present in the BOM"
    );
    assert!(bom.get("vulnerabilities").is_none() || bom["vulnerabilities"].is_null());
}
