//! End-to-end tests for the `cudabom gate` command.
//!
//! These drive the real binary via `assert_cmd`. A hash-based fingerprint DB
//! yields a deterministic, cross-platform exact finding; an advisory index then
//! produces the verdicts the policy acts on.

use assert_cmd::Command;
use object::write::{Object, StandardSection, Symbol, SymbolSection};
use object::{Architecture, BinaryFormat, Endianness, SymbolFlags, SymbolKind, SymbolScope};

/// Build a relocatable x86_64 ELF that defines one global symbol.
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

/// Write an ELF plus a hash DB naming it `cudart <version>`. Returns the temp
/// dir (kept alive by the caller) and the ELF path.
fn setup(version: &str) -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
    let elf = write_elf("gate_sym");
    let sha = sha256_hex(&elf);
    let dir = tempfile::tempdir().unwrap();
    let elf_path = dir.path().join("libcudart.so.12");
    std::fs::write(&elf_path, &elf).unwrap();
    let db_path = dir.path().join("db.json");
    std::fs::write(
        &db_path,
        format!(
            r#"{{ "schema_version": 2, "components": [ {{ "name": "cudart", "soname_stems": ["libcudart.so"], "file_hashes": {{ "{sha}": ["{version}"] }} }} ] }}"#
        ),
    )
    .unwrap();
    (dir, elf_path, db_path)
}

/// An advisory index affecting cudart in [12.0, 12.4).
fn write_advisories(dir: &std::path::Path) -> std::path::PathBuf {
    let path = dir.join("advisories.json");
    std::fs::write(
        &path,
        r#"{ "schema_version": 1, "advisories": [ { "id": "CVE-2025-0001", "affected": [ { "component": "cudart", "affected_ranges": [ { "introduced": "12.0", "fixed": "12.4" } ] } ] } ] }"#,
    )
    .unwrap();
    path
}

#[test]
fn gate_default_policy_fails_on_affected() {
    // cudart 12.3 is inside the affected range -> affected -> default gate fail.
    let (dir, elf_path, db_path) = setup("12.3");
    let adv_path = write_advisories(dir.path());

    let assert = Command::cargo_bin("cudabom")
        .unwrap()
        .args([
            "gate",
            elf_path.to_str().unwrap(),
            "--db",
            db_path.to_str().unwrap(),
            "--advisories",
            adv_path.to_str().unwrap(),
        ])
        .assert()
        .code(1); // Findings/policy-violation exit code.

    let out = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert!(out.contains("gate: FAIL"));
    assert!(out.contains("CVE-2025-0001"));
}

#[test]
fn gate_default_policy_passes_when_not_affected() {
    // cudart 12.4.1 is at/above the fix boundary -> not_affected -> gate pass.
    let (dir, elf_path, db_path) = setup("12.4.1");
    let adv_path = write_advisories(dir.path());

    let assert = Command::cargo_bin("cudabom")
        .unwrap()
        .args([
            "gate",
            elf_path.to_str().unwrap(),
            "--db",
            db_path.to_str().unwrap(),
            "--advisories",
            adv_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    let out = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert!(out.contains("gate: PASS"));
}

#[test]
fn gate_passes_without_advisories_under_default_policy() {
    // No advisory data: the default policy only fails on advisory verdicts, so
    // identification alone passes the gate.
    let (_dir, elf_path, db_path) = setup("12.3");

    Command::cargo_bin("cudabom")
        .unwrap()
        .args([
            "gate",
            elf_path.to_str().unwrap(),
            "--db",
            db_path.to_str().unwrap(),
        ])
        .assert()
        .success();
}

#[test]
fn gate_allowlist_exempts_affected_and_passes() {
    let (dir, elf_path, db_path) = setup("12.3");
    let adv_path = write_advisories(dir.path());
    let policy_path = dir.path().join("policy.json");
    std::fs::write(
        &policy_path,
        r#"{ "schema_version": 1, "allow": [ { "advisory": "CVE-2025-0001", "reason": "mitigated in our build; TICKET-42" } ] }"#,
    )
    .unwrap();

    let assert = Command::cargo_bin("cudabom")
        .unwrap()
        .args([
            "gate",
            elf_path.to_str().unwrap(),
            "--db",
            db_path.to_str().unwrap(),
            "--advisories",
            adv_path.to_str().unwrap(),
            "--policy",
            policy_path.to_str().unwrap(),
            "--format",
            "json",
        ])
        .assert()
        .success();

    let out = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let json: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(json["passed"], true);
    assert_eq!(json["violations"].as_array().unwrap().len(), 0);
    assert_eq!(json["exemptions"][0]["advisory"], "CVE-2025-0001");
    assert_eq!(
        json["exemptions"][0]["reason"],
        "mitigated in our build; TICKET-42"
    );
}

#[test]
fn gate_min_confidence_policy_fails_on_identification() {
    // A policy that fails on Exact identifications, with no advisory data.
    let (dir, elf_path, db_path) = setup("12.3");
    let policy_path = dir.path().join("policy.json");
    std::fs::write(
        &policy_path,
        r#"{ "schema_version": 1, "fail_on": { "advisory_verdicts": ["affected"], "min_confidence": "exact", "under_investigation": false } }"#,
    )
    .unwrap();

    let assert = Command::cargo_bin("cudabom")
        .unwrap()
        .args([
            "gate",
            elf_path.to_str().unwrap(),
            "--db",
            db_path.to_str().unwrap(),
            "--policy",
            policy_path.to_str().unwrap(),
            "--format",
            "json",
        ])
        .assert()
        .code(1);

    let out = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let json: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(json["passed"], false);
    assert_eq!(json["violations"][0]["kind"], "confidence");
    assert_eq!(json["violations"][0]["component"], "cudart");
}

#[test]
fn gate_rejects_bad_policy_as_input_error() {
    let (_dir, elf_path, db_path) = setup("12.3");
    let (dir2, _e, _d) = setup("12.3");
    let policy_path = dir2.path().join("policy.json");
    // Allow entry without a reason: rejected at load time.
    std::fs::write(
        &policy_path,
        r#"{ "schema_version": 1, "allow": [ { "advisory": "CVE-1", "reason": "" } ] }"#,
    )
    .unwrap();

    Command::cargo_bin("cudabom")
        .unwrap()
        .args([
            "gate",
            elf_path.to_str().unwrap(),
            "--db",
            db_path.to_str().unwrap(),
            "--policy",
            policy_path.to_str().unwrap(),
        ])
        .assert()
        .code(3); // Input error.
}
