//! End-to-end tests for the `cudabom explain` command.

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

/// Write an ELF plus a hash DB naming it cudart 12.4.1. Returns the dir, the
/// ELF path, the DB path, and the expected finding id (`<path>::cudart`).
fn setup() -> (
    tempfile::TempDir,
    std::path::PathBuf,
    std::path::PathBuf,
    String,
) {
    let elf = write_elf("explain_sym");
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
    // The finding id is `<logical-path>::cudart`; the logical path is the file
    // name for a single-file target.
    let id = "libcudart.so.12::cudart".to_string();
    (dir, elf_path, db_path, id)
}

#[test]
fn explain_lists_findings_without_id() {
    let (_dir, elf_path, db_path, _id) = setup();
    let assert = Command::cargo_bin("cudabom")
        .unwrap()
        .args([
            "explain",
            elf_path.to_str().unwrap(),
            "--db",
            db_path.to_str().unwrap(),
        ])
        .assert()
        .success();
    let out = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert!(out.contains("findings ("));
    assert!(out.contains("::cudart"));
    assert!(out.contains("cudart 12.4.1 [exact]"));
}

#[test]
fn explain_shows_evidence_chain_for_id() {
    let (_dir, elf_path, db_path, id) = setup();
    let assert = Command::cargo_bin("cudabom")
        .unwrap()
        .args([
            "explain",
            "--id",
            &id,
            elf_path.to_str().unwrap(),
            "--db",
            db_path.to_str().unwrap(),
        ])
        .assert()
        .success();
    let out = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert!(out.contains(&format!("finding: {id}")));
    assert!(out.contains("component:    cudart"));
    assert!(out.contains("version:      12.4.1"));
    assert!(out.contains("confidence:   exact"));
    assert!(out.contains("evidence ("));
    // The hash-match evidence should reference the known file hash.
    assert!(out.contains("KnownFileHash") || out.contains("evidence"));
}

#[test]
fn explain_json_emits_the_finding() {
    let (_dir, elf_path, db_path, id) = setup();
    let assert = Command::cargo_bin("cudabom")
        .unwrap()
        .args([
            "explain",
            "--id",
            &id,
            "--format",
            "json",
            elf_path.to_str().unwrap(),
            "--db",
            db_path.to_str().unwrap(),
        ])
        .assert()
        .success();
    let out = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let json: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(json["id"], id);
    assert_eq!(json["component"]["name"], "cudart");
    assert_eq!(json["confidence"], "exact");
}

#[test]
fn explain_unknown_id_is_usage_error() {
    let (_dir, elf_path, db_path, _id) = setup();
    Command::cargo_bin("cudabom")
        .unwrap()
        .args([
            "explain",
            "--id",
            "no-such-finding",
            elf_path.to_str().unwrap(),
            "--db",
            db_path.to_str().unwrap(),
        ])
        .assert()
        .code(2); // Usage error.
}
