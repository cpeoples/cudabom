//! End-to-end tests for the `cudabom update` command and the data-directory
//! resolution that scans use by default.
//!
//! The network fetch itself is not exercised here (it hits GitHub); these tests
//! cover the offline, deterministic behavior: argument handling, data-directory
//! resolution, and how `version --verbose` reports an installed bundle.

use assert_cmd::Command;

/// A minimal fingerprint shard, enough to look like an installed bundle.
const SHARD: &str = r#"{
    "schema_version": 1,
    "release": { "label": "12.4.1", "date": "2024-04-03" },
    "components": [ { "name": "cudart", "soname_stems": ["libcudart.so"] } ]
}"#;

const INDEX: &str = r#"{ "schema_version": 1, "advisories": [] }"#;

/// Lay out a data directory the way `cudabom update` would, and return it.
fn install_bundle(tag: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    std::fs::create_dir_all(root.join("fingerprints/cuda")).unwrap();
    std::fs::create_dir_all(root.join("advisories")).unwrap();
    std::fs::write(root.join("fingerprints/cuda/redistrib_12.4.1.json"), SHARD).unwrap();
    std::fs::write(root.join("advisories/index.json"), INDEX).unwrap();
    std::fs::write(root.join("VERSION"), format!("{tag}\n")).unwrap();
    dir
}

#[test]
fn update_without_a_data_dir_reports_a_clear_error() {
    // With every data-dir source cleared and no --data-dir, the command must
    // fail with an input error rather than panicking or writing somewhere odd.
    // The set of sources is platform-specific, so clear all of them.
    let mut cmd = Command::cargo_bin("cudabom").unwrap();
    cmd.args(["update", "--tag", "v0.0.0-none"])
        .env_remove("CUDABOM_DATA_DIR")
        .env_remove("SNAP_USER_DATA")
        .env_remove("XDG_DATA_HOME")
        .env_remove("HOME")
        .env_remove("LOCALAPPDATA")
        .env_remove("APPDATA")
        .env_remove("USERPROFILE");
    cmd.assert().code(3);
}

#[test]
fn version_verbose_reports_an_installed_bundle() {
    let bundle = install_bundle("v1.2.3");

    let assert = Command::cargo_bin("cudabom")
        .unwrap()
        .args(["version", "--verbose"])
        .env("CUDABOM_DATA_DIR", bundle.path())
        .assert()
        .success();

    let out = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert!(out.contains("data bundle:     v1.2.3"), "got: {out}");
    assert!(out.contains("fingerprint db:  present"), "got: {out}");
    assert!(out.contains("advisory index:  present"), "got: {out}");
}

#[test]
fn version_verbose_reports_when_no_bundle_is_installed() {
    let empty = tempfile::tempdir().unwrap();

    let assert = Command::cargo_bin("cudabom")
        .unwrap()
        .args(["version", "--verbose"])
        .env("CUDABOM_DATA_DIR", empty.path())
        .assert()
        .success();

    let out = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert!(out.contains("data bundle:     not installed"), "got: {out}");
    assert!(out.contains("fingerprint db:  not built"), "got: {out}");
}

#[test]
fn scan_uses_the_installed_data_dir_by_default() {
    // With a data dir installed and no --db flag, a scan resolves the shard set
    // from the data dir. Scanning an empty file yields no findings but must
    // succeed, proving the default DB path loaded without error.
    let bundle = install_bundle("v2.0.0");
    let target = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(target.path(), b"not an elf").unwrap();

    Command::cargo_bin("cudabom")
        .unwrap()
        .args(["scan", target.path().to_str().unwrap(), "--format", "json"])
        .env("CUDABOM_DATA_DIR", bundle.path())
        .assert()
        .success();
}
