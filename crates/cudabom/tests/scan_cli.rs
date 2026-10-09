//! End-to-end tests for the `cudabom scan` command.
//!
//! These drive the real binary via `assert_cmd`, over real inputs written to
//! temp files, and assert on the emitted JSON/table. A real (writer-produced)
//! ELF exercises the extract -> ELF-facts -> report pipeline.

use std::io::Write;

use assert_cmd::Command;
use object::write::{Object, StandardSection, Symbol, SymbolSection};
use object::{Architecture, BinaryFormat, Endianness, SymbolFlags, SymbolKind, SymbolScope};
use predicates::prelude::PredicateBooleanExt;

#[path = "../../cudabom-elf/tests/common/dynamic_elf.rs"]
mod dynamic_elf;

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

#[test]
fn scan_elf_json_reports_facts() {
    let dir = tempfile::tempdir().unwrap();
    let elf_path = dir.path().join("libthing.so");
    std::fs::write(&elf_path, write_elf("scan_marker_symbol")).unwrap();

    let assert = Command::cargo_bin("cudabom")
        .unwrap()
        .args(["scan", elf_path.to_str().unwrap(), "--format", "json"])
        .assert()
        .success();

    let out = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let json: serde_json::Value = serde_json::from_str(&out).unwrap();

    assert_eq!(json["schemaVersion"], serde_json::Value::Null); // camelCase not used
    assert_eq!(json["schema_version"], "0.1.0");
    let file = &json["files"][0];
    assert_eq!(file["kind"], "elf");
    assert_eq!(file["elf"]["class"], "elf64");
    assert_eq!(file["elf"]["architecture"], "X86_64");
    // sha256 of the file is present and 64 hex chars.
    let sha = file["sha256"].as_str().unwrap();
    assert_eq!(sha.len(), 64);
}

#[test]
fn scan_directory_table_shows_signal_and_collapses_noise() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a.so"), write_elf("sym_a")).unwrap();
    std::fs::write(dir.path().join("notes.txt"), b"just text").unwrap();

    // Default table leads with the ELF (signal) and collapses the text leaf
    // into the summary line rather than listing it.
    Command::cargo_bin("cudabom")
        .unwrap()
        .args(["scan", dir.path().to_str().unwrap(), "--format", "table"])
        .assert()
        .success()
        .stdout(predicates::str::contains("a.so"))
        .stdout(predicates::str::contains(
            "other file(s) with no CUDA signal",
        ))
        .stdout(predicates::str::contains("notes.txt").not());
}

#[test]
fn scan_directory_table_all_files_lists_everything() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a.so"), write_elf("sym_a")).unwrap();
    std::fs::write(dir.path().join("notes.txt"), b"just text").unwrap();

    // --all-files restores the full per-file listing, including the text leaf,
    // and drops the collapse summary.
    Command::cargo_bin("cudabom")
        .unwrap()
        .args([
            "scan",
            dir.path().to_str().unwrap(),
            "--format",
            "table",
            "--all-files",
        ])
        .assert()
        .success()
        .stdout(predicates::str::contains("a.so"))
        .stdout(predicates::str::contains("notes.txt"))
        .stdout(predicates::str::contains("other file(s) with no CUDA signal").not());
}

#[test]
fn scan_wheel_finds_nested_elf() {
    // A wheel is a zip; embed an ELF inside and confirm the scan reaches it.
    let mut cursor = std::io::Cursor::new(Vec::new());
    {
        let mut zw = zip::ZipWriter::new(&mut cursor);
        let opts: zip::write::FileOptions<'_, ()> =
            zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored);
        zw.start_file("pkg/_lib.so", opts).unwrap();
        zw.write_all(&write_elf("wheel_sym")).unwrap();
        zw.start_file("pkg/__init__.py", opts).unwrap();
        zw.write_all(b"# module").unwrap();
        zw.finish().unwrap();
    }
    let wheel = cursor.into_inner();

    let dir = tempfile::tempdir().unwrap();
    let wheel_path = dir.path().join("thing-1.0-py3-none-any.whl");
    std::fs::write(&wheel_path, wheel).unwrap();

    let assert = Command::cargo_bin("cudabom")
        .unwrap()
        .args(["scan", wheel_path.to_str().unwrap(), "--format", "json"])
        .assert()
        .success();

    let out = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let json: serde_json::Value = serde_json::from_str(&out).unwrap();
    let files = json["files"].as_array().unwrap();
    // The nested .so is surfaced with its logical path inside the wheel and
    // parsed as ELF.
    let so = files
        .iter()
        .find(|f| f["path"].as_str().unwrap().ends_with("pkg/_lib.so"))
        .expect("nested .so present");
    assert_eq!(so["kind"], "elf");
    assert_eq!(so["elf"]["architecture"], "X86_64");
}

#[test]
fn scan_missing_target_is_input_error() {
    Command::cargo_bin("cudabom")
        .unwrap()
        .args(["scan", "/no/such/path/here", "--format", "json"])
        .assert()
        .code(3); // documented Input exit code
}

#[test]
fn scan_standalone_ptx_reports_gpu_code() {
    let dir = tempfile::tempdir().unwrap();
    let ptx_path = dir.path().join("kernel.ptx");
    std::fs::write(
        &ptx_path,
        b"//\n// Generated by NVIDIA NVVM Compiler\n//\n.version 8.3\n.target sm_90\n.address_size 64\n",
    )
    .unwrap();

    let assert = Command::cargo_bin("cudabom")
        .unwrap()
        .args(["scan", ptx_path.to_str().unwrap(), "--format", "json"])
        .assert()
        .success();

    let out = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let json: serde_json::Value = serde_json::from_str(&out).unwrap();
    let file = &json["files"][0];
    let gpu = &file["gpu_code"];
    assert_eq!(gpu["gpu_code_kind"], "ptx");
    assert_eq!(gpu["isa_version"], "8.3");
    assert_eq!(gpu["targets"][0], 90);

    // The aggregated GPU capability manifest surfaces the PTX SM target.
    let cap = &json["capability"];
    assert_eq!(cap["ptx_sm_targets"][0], 90);
    assert_eq!(cap["has_ptx"], true);
    assert_eq!(cap["gpu_code_units"], 1);
}

#[test]
fn scan_standalone_fatbin_reports_container() {
    // Build a minimal fatbin container (matching the fatbin crate's wire tests).
    let payload = b"cubin-bytes";
    let entry_header_len: u32 = 64;
    let mut entry = Vec::new();
    entry.extend_from_slice(&0x0002u16.to_le_bytes()); // kind = cubin
    entry.extend_from_slice(&0u16.to_le_bytes());
    entry.extend_from_slice(&entry_header_len.to_le_bytes());
    entry.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    entry.extend_from_slice(&0u64.to_le_bytes());
    entry.extend_from_slice(&0u64.to_le_bytes());
    while entry.len() < entry_header_len as usize {
        entry.push(0);
    }
    entry.extend_from_slice(payload);

    let mut fat = Vec::new();
    fat.extend_from_slice(&0xBA55_ED50u32.to_le_bytes()); // fatbin magic (on disk: 50 ED 55 BA)
    fat.extend_from_slice(&1u16.to_le_bytes()); // version
    fat.extend_from_slice(&16u16.to_le_bytes()); // header_size
    fat.extend_from_slice(&(entry.len() as u64).to_le_bytes());
    fat.extend_from_slice(&entry);

    let dir = tempfile::tempdir().unwrap();
    let fat_path = dir.path().join("lib.fatbin");
    std::fs::write(&fat_path, &fat).unwrap();

    let assert = Command::cargo_bin("cudabom")
        .unwrap()
        .args(["scan", fat_path.to_str().unwrap(), "--format", "json"])
        .assert()
        .success();

    let out = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let json: serde_json::Value = serde_json::from_str(&out).unwrap();
    let gpu = &json["files"][0]["gpu_code"];
    assert_eq!(gpu["gpu_code_kind"], "fatbin");
    assert_eq!(gpu["version"], 1);
    assert_eq!(gpu["entries"][0]["kind"], "cubin");
}

#[test]
fn scan_with_db_hash_match_is_exact_and_exits_findings() {
    // Hash-based identification needs no SONAME: put the file's own sha256 in
    // the DB and assert an Exact finding. Fully hermetic and cross-platform.
    let elf = write_elf("hashed_sym");
    let sha = sha256_hex(&elf);

    let dir = tempfile::tempdir().unwrap();
    let elf_path = dir.path().join("libcudart.so.12");
    std::fs::write(&elf_path, &elf).unwrap();

    let db_path = dir.path().join("db.json");
    let db = format!(
        r#"{{ "schema_version": 2, "components": [ {{ "name": "cudart", "soname_stems": ["libcudart.so"], "file_hashes": {{ "{sha}": ["12.4.1"] }} }} ] }}"#
    );
    std::fs::write(&db_path, db).unwrap();

    let assert = Command::cargo_bin("cudabom")
        .unwrap()
        .args([
            "scan",
            elf_path.to_str().unwrap(),
            "--db",
            db_path.to_str().unwrap(),
            "--format",
            "json",
        ])
        .assert()
        .success(); // scan is a reporting command: exit 0 by default even with findings.

    let out = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let json: serde_json::Value = serde_json::from_str(&out).unwrap();
    let finding = &json["findings"][0];
    assert_eq!(finding["component"]["name"], "cudart");
    assert_eq!(finding["component"]["version"], "12.4.1");
    assert_eq!(finding["confidence"], "exact");
}

#[test]
fn scan_with_advisories_correlates_and_reports_verdict() {
    // An exact cudart 12.4.1 finding correlated against an advisory affecting
    // [12.0, 12.4): 12.4.1 is at/above the fix boundary, so not_affected.
    let elf = write_elf("adv_hashed_sym");
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

    let adv_path = dir.path().join("advisories.json");
    std::fs::write(
        &adv_path,
        r#"{
            "schema_version": 1,
            "source_commit": "abc123",
            "advisories": [
                {
                    "id": "CVE-2025-0001",
                    "severity": "high",
                    "affected": [
                        { "component": "cudart", "affected_ranges": [ { "introduced": "12.0", "fixed": "12.4" } ] }
                    ]
                }
            ]
        }"#,
    )
    .unwrap();

    let assert = Command::cargo_bin("cudabom")
        .unwrap()
        .args([
            "scan",
            elf_path.to_str().unwrap(),
            "--db",
            db_path.to_str().unwrap(),
            "--advisories",
            adv_path.to_str().unwrap(),
            "--format",
            "json",
        ])
        .assert()
        .success(); // A component was positively identified; scan still exits 0.

    let out = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let json: serde_json::Value = serde_json::from_str(&out).unwrap();

    let advisories = &json["advisories"];
    assert_eq!(advisories["source_commit"], "abc123");
    let m = &advisories["matches"][0];
    assert_eq!(m["advisory_id"], "CVE-2025-0001");
    assert_eq!(m["component"], "cudart");
    assert_eq!(m["verdict"], "not_affected");
    // The coverage caveat is always present.
    assert!(advisories["caveat"]
        .as_str()
        .unwrap()
        .contains("not proof of safety"));
}

#[test]
fn scan_with_advisories_flags_affected_version() {
    // A cudart 12.3 finding is inside the affected range [12.0, 12.4).
    let elf = write_elf("adv_affected_sym");
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
        r#"{
            "schema_version": 1,
            "advisories": [
                { "id": "CVE-2025-0001", "affected": [ { "component": "cudart", "affected_ranges": [ { "introduced": "12.0", "fixed": "12.4" } ] } ] }
            ]
        }"#,
    )
    .unwrap();

    let assert = Command::cargo_bin("cudabom")
        .unwrap()
        .args([
            "scan",
            elf_path.to_str().unwrap(),
            "--db",
            db_path.to_str().unwrap(),
            "--advisories",
            adv_path.to_str().unwrap(),
            "--format",
            "json",
        ])
        .assert()
        .success(); // default --fail-on=none: exits 0 even though affected.

    let out = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let json: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(json["advisories"]["matches"][0]["verdict"], "affected");
    // The summary tallies verdicts so a result reads deliberately.
    assert_eq!(json["advisories"]["summary"]["affected"], 1);
}

#[test]
fn scan_table_groups_advisories_by_severity() {
    // Two affected advisories of different severity must render under grouped,
    // severity-ordered headers with a severity-breakdown summary and a
    // "most severe" headline naming the HIGH one.
    let elf = write_elf("adv_grouped_sym");
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
        r#"{
            "schema_version": 1,
            "advisories": [
                { "id": "CVE-2025-AAAA", "severity": "high", "cvss_score": 7.8,
                  "references": [ "https://nvd.nist.gov/vuln/detail/CVE-2025-AAAA" ],
                  "affected": [ { "component": "cudart", "affected_ranges": [ { "introduced": "12.0", "fixed": "12.4" } ] } ] },
                { "id": "CVE-2025-BBBB", "severity": "low", "cvss_score": 2.1,
                  "affected": [ { "component": "cudart", "affected_ranges": [ { "introduced": "12.0", "fixed": "12.4" } ] } ] }
            ]
        }"#,
    )
    .unwrap();

    let assert = Command::cargo_bin("cudabom")
        .unwrap()
        .args([
            "scan",
            elf_path.to_str().unwrap(),
            "--db",
            db_path.to_str().unwrap(),
            "--advisories",
            adv_path.to_str().unwrap(),
            "--format",
            "table",
        ])
        .assert()
        .success();

    let out = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert!(
        out.contains("summary: 2 affected (1 high, 1 low)"),
        "severity-breakdown summary missing:\n{out}"
    );
    assert!(
        out.contains("most severe: CVE-2025-AAAA"),
        "most-severe headline missing or wrong:\n{out}"
    );
    assert!(
        out.contains("HIGH (1):"),
        "HIGH group header missing:\n{out}"
    );
    assert!(out.contains("LOW (1):"), "LOW group header missing:\n{out}");
    // The HIGH group must appear before the LOW group.
    let high_at = out.find("HIGH (1):").unwrap();
    let low_at = out.find("LOW (1):").unwrap();
    assert!(high_at < low_at, "HIGH must sort before LOW:\n{out}");
    // The aligned row carries the CVSS score, and the single NVD link follows
    // on its own indented line.
    assert!(
        out.contains("CVE-2025-AAAA  CVSS  7.8")
            && out.contains("https://nvd.nist.gov/vuln/detail/CVE-2025-AAAA"),
        "aligned HIGH row missing CVSS/link:\n{out}"
    );
    // The advisories are grouped under the component they concern.
    assert!(
        out.contains("cudart: 2 affected"),
        "per-component advisory header missing:\n{out}"
    );
}

#[test]
fn scan_table_verbose_restores_full_advisory_detail() {
    // `-v` restores the multi-line per-advisory detail (verdict + severity line).
    let elf = write_elf("adv_verbose_sym");
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
        r#"{
            "schema_version": 1,
            "advisories": [
                { "id": "CVE-2025-AAAA", "severity": "high", "cvss_score": 7.8,
                  "description": "A heap overflow in cudart.",
                  "affected": [ { "component": "cudart", "affected_ranges": [ { "introduced": "12.0", "fixed": "12.4" } ] } ] }
            ]
        }"#,
    )
    .unwrap();

    let assert = Command::cargo_bin("cudabom")
        .unwrap()
        .args([
            "-v",
            "scan",
            elf_path.to_str().unwrap(),
            "--db",
            db_path.to_str().unwrap(),
            "--advisories",
            adv_path.to_str().unwrap(),
            "--format",
            "table",
        ])
        .assert()
        .success();

    let out = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    // Verbose keeps the grouped, aligned rows and adds per-advisory detail
    // beneath each: the match reason and the full CVE description.
    assert!(
        out.contains("reason:") && out.contains("within an affected range"),
        "verbose reason line missing:\n{out}"
    );
    assert!(
        out.contains("description: A heap overflow in cudart."),
        "verbose description line missing:\n{out}"
    );
}

#[test]
fn scan_fail_on_found_exits_findings_on_identification() {
    // `--fail-on found` makes a positive identification a non-zero exit, for CI
    // that wants to fail on any CUDA presence.
    let elf = write_elf("failon_found_sym");
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

    Command::cargo_bin("cudabom")
        .unwrap()
        .args([
            "scan",
            elf_path.to_str().unwrap(),
            "--db",
            db_path.to_str().unwrap(),
            "--fail-on",
            "found",
        ])
        .assert()
        .code(1);
}

#[test]
fn scan_fail_on_affected_exits_only_when_affected() {
    // `--fail-on affected` fails when an advisory is affected, but not merely on
    // identification.
    let elf = write_elf("failon_affected_sym");
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
        r#"{
            "schema_version": 1,
            "advisories": [
                { "id": "CVE-2025-0001", "affected": [ { "component": "cudart", "affected_ranges": [ { "introduced": "12.0", "fixed": "12.4" } ] } ] }
            ]
        }"#,
    )
    .unwrap();

    // Affected -> exit 1.
    Command::cargo_bin("cudabom")
        .unwrap()
        .args([
            "scan",
            elf_path.to_str().unwrap(),
            "--db",
            db_path.to_str().unwrap(),
            "--advisories",
            adv_path.to_str().unwrap(),
            "--fail-on",
            "affected",
        ])
        .assert()
        .code(1);

    // Same identification, but no advisories supplied -> nothing affected -> 0.
    Command::cargo_bin("cudabom")
        .unwrap()
        .args([
            "scan",
            elf_path.to_str().unwrap(),
            "--db",
            db_path.to_str().unwrap(),
            "--fail-on",
            "affected",
        ])
        .assert()
        .success();
}

#[test]
fn scan_without_advisories_has_no_advisory_section() {
    let elf = write_elf("no_adv_sym");
    let dir = tempfile::tempdir().unwrap();
    let elf_path = dir.path().join("libcudart.so.12");
    std::fs::write(&elf_path, &elf).unwrap();

    let assert = Command::cargo_bin("cudabom")
        .unwrap()
        .args(["scan", elf_path.to_str().unwrap(), "--format", "json"])
        .assert()
        .success();

    let out = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let json: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert!(json.get("advisories").is_none() || json["advisories"].is_null());
}

#[test]
fn scan_without_db_reports_no_findings() {
    let elf = write_elf("plain_sym");
    let dir = tempfile::tempdir().unwrap();
    let elf_path = dir.path().join("libcudart.so.12");
    std::fs::write(&elf_path, &elf).unwrap();

    // No --db: an empty database names nothing, so the scan succeeds (0) with
    // no findings.
    Command::cargo_bin("cudabom")
        .unwrap()
        .args(["scan", elf_path.to_str().unwrap(), "--format", "json"])
        .assert()
        .success();
}

/// Lowercase hex sha256, matching the digest cudabom computes for a file.
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

/// Compile a real shared object with a SONAME (Linux only). Kept as a
/// belt-and-suspenders check that the parser agrees with a real linker's
/// output; the cross-platform coverage comes from the hand-built fixture test
/// below.
#[cfg(target_os = "linux")]
#[test]
fn scan_real_so_soname_yields_likely_finding() {
    use std::process::Command as StdCommand;

    let cc = if StdCommand::new("cc").arg("--version").output().is_ok() {
        "cc"
    } else {
        eprintln!("no C compiler; skipping");
        return;
    };

    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("c.c");
    let so = dir.path().join("libcudart.so.12");
    std::fs::write(&src, "int cudartGetVersion(){return 12040;}").unwrap();

    let ok = StdCommand::new(cc)
        .args(["-shared", "-fPIC", "-Wl,-soname,libcudart.so.12", "-o"])
        .arg(&so)
        .arg(&src)
        .status()
        .is_ok_and(|s| s.success());
    if !ok {
        eprintln!("compile failed; skipping");
        return;
    }

    let db_path = dir.path().join("db.json");
    std::fs::write(
        &db_path,
        r#"{ "schema_version": 1, "components": [ { "name": "cudart", "soname_stems": ["libcudart.so"] } ] }"#,
    )
    .unwrap();

    let assert = Command::cargo_bin("cudabom")
        .unwrap()
        .args([
            "scan",
            so.to_str().unwrap(),
            "--db",
            db_path.to_str().unwrap(),
            "--format",
            "json",
        ])
        .assert()
        .success();

    let out = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let json: serde_json::Value = serde_json::from_str(&out).unwrap();
    let finding = &json["findings"][0];
    assert_eq!(finding["component"]["name"], "cudart");
    assert_eq!(finding["component"]["version"], "12.x");
    assert_eq!(finding["confidence"], "likely");
}

/// Cross-platform: a hand-built ELF with a real `.dynamic` carrying the SONAME
/// the DB attributes to `cudart`, driven through the full CLI. Proves the
/// SONAME -> Likely identification path on every host (no linker needed).
#[test]
fn scan_dynamic_elf_soname_yields_likely_finding() {
    let elf = dynamic_elf::build_dynamic_elf("libcudart.so.12", &["libc.so.6"]);

    let dir = tempfile::tempdir().unwrap();
    let elf_path = dir.path().join("libcudart.so.12");
    std::fs::write(&elf_path, &elf).unwrap();

    let db_path = dir.path().join("db.json");
    std::fs::write(
        &db_path,
        r#"{ "schema_version": 1, "components": [ { "name": "cudart", "soname_stems": ["libcudart.so"] } ] }"#,
    )
    .unwrap();

    let assert = Command::cargo_bin("cudabom")
        .unwrap()
        .args([
            "scan",
            elf_path.to_str().unwrap(),
            "--db",
            db_path.to_str().unwrap(),
            "--format",
            "json",
        ])
        .assert()
        .success(); // Findings: cudart identified; scan exits 0 by default.

    let out = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let json: serde_json::Value = serde_json::from_str(&out).unwrap();

    // The SONAME finding names cudart at a major-version range, Likely.
    let soname_finding = json["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["confidence"] == "likely")
        .expect("a likely finding");
    assert_eq!(soname_finding["component"]["name"], "cudart");
    assert_eq!(soname_finding["component"]["version"], "12.x");
}

/// The per-binary composition view separates what a binary *contains* (its own
/// SONAME identity) from what it *links* (CUDA `NEEDED` dependencies).
#[test]
fn scan_reports_binary_composition_links_and_contains() {
    // This binary *is* cudart (SONAME) and depends on cublas (NEEDED).
    let elf = dynamic_elf::build_dynamic_elf("libcudart.so.12", &["libc.so.6", "libcublas.so.12"]);

    let dir = tempfile::tempdir().unwrap();
    let elf_path = dir.path().join("libcudart.so.12");
    std::fs::write(&elf_path, &elf).unwrap();

    let db_path = dir.path().join("db.json");
    std::fs::write(
        &db_path,
        r#"{ "schema_version": 1, "components": [
            { "name": "cudart", "soname_stems": ["libcudart.so"] },
            { "name": "cublas", "soname_stems": ["libcublas.so"] }
        ] }"#,
    )
    .unwrap();

    let assert = Command::cargo_bin("cudabom")
        .unwrap()
        .args([
            "scan",
            elf_path.to_str().unwrap(),
            "--db",
            db_path.to_str().unwrap(),
            "--format",
            "json",
        ])
        .assert()
        .success();

    let out = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let json: serde_json::Value = serde_json::from_str(&out).unwrap();

    let binaries = json["composition"]["binaries"].as_array().unwrap();
    assert_eq!(binaries.len(), 1, "one binary in composition");
    let bin = &binaries[0];
    assert_eq!(bin["path"], "libcudart.so.12");

    // Contains cudart (its own SONAME identity).
    let contains = bin["contains"].as_array().unwrap();
    assert_eq!(contains.len(), 1);
    assert_eq!(contains[0]["name"], "cudart");

    // Links cublas (a NEEDED CUDA dependency); libc is not a CUDA component.
    let links = bin["links"].as_array().unwrap();
    assert_eq!(links.len(), 1);
    assert_eq!(links[0]["name"], "cublas");
    // Each node carries a finding id for `cudabom explain`.
    assert!(
        !links[0]["finding_id"].as_str().unwrap().is_empty(),
        "each link node carries a non-empty finding id"
    );
}

#[test]
fn scan_cyclonedx_emits_valid_bom() {
    // A hash-identified component, emitted as CycloneDX 1.6.
    let elf = write_elf("sbom_sym");
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

    let assert = Command::cargo_bin("cudabom")
        .unwrap()
        .args([
            "scan",
            elf_path.to_str().unwrap(),
            "--db",
            db_path.to_str().unwrap(),
            "--format",
            "cyclonedx",
        ])
        .assert()
        .success(); // findings present; scan exits 0 by default

    let out = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let bom: serde_json::Value = serde_json::from_str(&out).unwrap();

    assert_eq!(bom["bomFormat"], "CycloneDX");
    assert_eq!(bom["specVersion"], "1.6");
    assert!(bom["serialNumber"]
        .as_str()
        .unwrap()
        .starts_with("urn:uuid:"));
    let comp = &bom["components"][0];
    assert_eq!(comp["name"], "cudart");
    assert_eq!(comp["version"], "12.4.1");
    assert_eq!(comp["purl"], "pkg:generic/nvidia/cudart@12.4.1");
    // cudabom facts survive as properties.
    let props = comp["properties"].as_array().unwrap();
    assert!(props
        .iter()
        .any(|p| p["name"] == "cudabom:confidence" && p["value"] == "exact"));
}

#[test]
fn scan_sarif_emits_valid_log_with_advisory_result() {
    let elf = write_elf("sarif_sym");
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
            "scan",
            elf_path.to_str().unwrap(),
            "--db",
            db_path.to_str().unwrap(),
            "--advisories",
            adv_path.to_str().unwrap(),
            "--format",
            "sarif",
        ])
        .assert()
        .success();

    let out = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let json: serde_json::Value = serde_json::from_str(&out).unwrap();

    assert_eq!(json["version"], "2.1.0");
    let run = &json["runs"][0];
    assert_eq!(run["tool"]["driver"]["name"], "cudabom");
    let results = run["results"].as_array().unwrap();
    // A finding result and an advisory result.
    assert!(results
        .iter()
        .any(|r| r["ruleId"] == "cudabom/identified/exact"));
    let affected = results
        .iter()
        .find(|r| r["ruleId"] == "cudabom/advisory/affected")
        .expect("an affected advisory result");
    assert_eq!(affected["level"], "error");
    assert_eq!(affected["properties"]["advisoryId"], "CVE-2025-0001");
}

#[test]
fn scan_markdown_emits_tables_and_caveat() {
    let elf = write_elf("md_sym");
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
            "scan",
            elf_path.to_str().unwrap(),
            "--db",
            db_path.to_str().unwrap(),
            "--advisories",
            adv_path.to_str().unwrap(),
            "--format",
            "markdown",
        ])
        .assert()
        .success();

    let out = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert!(out.contains("## cudabom scan"));
    assert!(out.contains("### Findings"));
    assert!(out.contains("| cudart | 12.3 | exact |"));
    assert!(out.contains("### Advisories"));
    // The advisory block is headed by the component it concerns, and each CVE
    // is a row with its verdict badge.
    assert!(
        out.contains("**`cudart`**"),
        "per-component advisory header missing:\n{out}"
    );
    assert!(
        out.contains("| CVE-2025-0001 | **affected** |"),
        "affected advisory row missing:\n{out}"
    );
    assert!(out.contains("absence of a match is not proof of safety"));
}
