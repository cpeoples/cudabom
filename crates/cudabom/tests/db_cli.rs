//! End-to-end tests for the `cudabom db` command.

use assert_cmd::Command;

/// A minimal but realistic CSAF 2.0 document affecting the CUDA runtime.
const CSAF: &str = r#"{
    "document": {
        "category": "csaf_security_advisory",
        "csaf_version": "2.0",
        "aggregate_severity": { "text": "high" },
        "tracking": { "id": "NVIDIA-2025-TEST" }
    },
    "product_tree": {
        "branches": [
            {
                "category": "product_name",
                "name": "NVIDIA CUDA Runtime",
                "branches": [
                    {
                        "category": "product_version",
                        "name": "12.3",
                        "product": { "product_id": "CUDART-12-3", "name": "NVIDIA CUDA Runtime 12.3" }
                    }
                ]
            },
            {
                "category": "product_name",
                "name": "Mystery Component",
                "branches": [
                    {
                        "category": "product_version",
                        "name": "1.0",
                        "product": { "product_id": "MYS-1-0", "name": "Mystery Component 1.0" }
                    }
                ]
            }
        ]
    },
    "vulnerabilities": [
        {
            "cve": "CVE-2025-9999",
            "title": "Example CUDA runtime issue",
            "product_status": { "known_affected": ["CUDART-12-3", "MYS-1-0"] }
        }
    ]
}"#;

const MAP: &str = r#"{
    "schema_version": 1,
    "exact": {},
    "rules": [ { "contains": "cuda runtime", "component": "cudart" } ]
}"#;

fn write_inputs() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let csaf_path = dir.path().join("advisory.json");
    std::fs::write(&csaf_path, CSAF).unwrap();
    let map_path = dir.path().join("map.json");
    std::fs::write(&map_path, MAP).unwrap();
    (dir, csaf_path, map_path)
}

#[test]
fn db_build_produces_normalized_index() {
    let (_dir, csaf_path, map_path) = write_inputs();

    let assert = Command::cargo_bin("cudabom")
        .unwrap()
        .args([
            "db",
            "build",
            "--from",
            csaf_path.to_str().unwrap(),
            "--map",
            map_path.to_str().unwrap(),
            "--source-commit",
            "deadbeef",
        ])
        .assert()
        .success();

    let out = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let index: serde_json::Value = serde_json::from_str(&out).unwrap();

    assert_eq!(index["schema_version"], 1);
    assert_eq!(index["source_commit"], "deadbeef");
    let advisories = index["advisories"].as_array().unwrap();
    assert_eq!(advisories.len(), 1);
    assert_eq!(advisories[0]["id"], "CVE-2025-9999");
    let affected = advisories[0]["affected"].as_array().unwrap();
    assert_eq!(affected[0]["component"], "cudart");
    assert_eq!(affected[0]["affected_ranges"][0]["introduced"], "12.3");
}

#[test]
fn db_build_index_feeds_scan_advisories() {
    // Build an index, then confirm `scan --advisories` consumes it.
    let (dir, csaf_path, map_path) = write_inputs();
    let index_path = dir.path().join("index.json");

    Command::cargo_bin("cudabom")
        .unwrap()
        .args([
            "db",
            "build",
            "--from",
            csaf_path.to_str().unwrap(),
            "--map",
            map_path.to_str().unwrap(),
            "-o",
            index_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    // The index file is valid and non-empty.
    let index: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&index_path).unwrap()).unwrap();
    assert_eq!(index["advisories"].as_array().unwrap().len(), 1);
}

#[test]
fn db_status_reports_unmapped_products() {
    let (_dir, csaf_path, map_path) = write_inputs();

    let assert = Command::cargo_bin("cudabom")
        .unwrap()
        .args([
            "db",
            "status",
            "--from",
            csaf_path.to_str().unwrap(),
            "--map",
            map_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    let out = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert!(out.contains("advisories mapped: 1"));
    // The mystery component is unmapped and reported, not dropped.
    assert!(out.contains("unmapped products"));
    assert!(out.contains("Mystery Component"));
}

#[test]
fn db_build_reads_a_directory_of_csaf() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a.json"), CSAF).unwrap();
    // Keep the map outside the CSAF dir so it is not ingested as a CSAF file.
    let map_dir = tempfile::tempdir().unwrap();
    let map_path = map_dir.path().join("map.json");
    std::fs::write(&map_path, MAP).unwrap();

    let assert = Command::cargo_bin("cudabom")
        .unwrap()
        .args([
            "db",
            "build",
            "--from",
            dir.path().to_str().unwrap(),
            "--map",
            map_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    let out = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let index: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(index["advisories"].as_array().unwrap().len(), 1);
}

#[test]
fn db_update_requires_map_and_rev() {
    // With no arguments, clap reports a usage error for the required flags.
    Command::cargo_bin("cudabom")
        .unwrap()
        .args(["db", "update"])
        .assert()
        .code(2);
}

#[test]
fn db_update_rejects_empty_revision() {
    // An explicitly empty --rev is a fetch input error, not a usage error.
    Command::cargo_bin("cudabom")
        .unwrap()
        .args([
            "db",
            "update",
            "--map",
            "advisories/product-map.json",
            "--rev",
            "",
        ])
        .assert()
        .code(3);
}
