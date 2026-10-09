//! Linux-only test that compiles a real shared object and derives its binary
//! fingerprint (build-id + file sha256 + SONAME stem) end-to-end.
//!
//! Gated to Linux because that is where a C toolchain and ELF `.so`s exist and
//! where CI runs; the pure helpers and `to_db` folding are covered by the unit
//! tests on every platform. This proves the binary-derivation path against a
//! genuine, linker-produced ELF rather than a fixture.

#![cfg(target_os = "linux")]

use std::process::Command;

use cudabom_identify::{fingerprint_binary, to_db, BinaryProvenance};

/// Compile a shared object with a known soname and build-id; `None` if no C
/// compiler is available.
fn compile_shared(soname: &str) -> Option<Vec<u8>> {
    let cc = if Command::new("cc").arg("--version").output().is_ok() {
        "cc"
    } else if Command::new("gcc").arg("--version").output().is_ok() {
        "gcc"
    } else {
        return None;
    };
    let dir = tempfile::tempdir().ok()?;
    let src = dir.path().join("lib.c");
    let out = dir.path().join(soname);
    std::fs::write(&src, "int cudabom_symbol(int x){return x+1;}").ok()?;
    let status = Command::new(cc)
        .args(["-shared", "-fPIC"])
        .arg(format!("-Wl,-soname,{soname}"))
        .arg("-Wl,--build-id=sha1")
        .arg("-o")
        .arg(&out)
        .arg(&src)
        .status()
        .ok()?;
    if !status.success() {
        return None;
    }
    std::fs::read(&out).ok()
}

#[test]
fn derives_build_id_hash_and_stem_from_real_so() {
    let Some(bytes) = compile_shared("libcudabomtest.so.1") else {
        eprintln!("no C compiler available; skipping");
        return;
    };

    let prov = BinaryProvenance {
        component: "cudart".into(),
        version: "11.4.108".into(),
        release_label: None,
    };
    let fp = fingerprint_binary(&bytes, &prov).expect("derive fingerprint");

    assert_eq!(fp.component, "cudart");
    assert_eq!(fp.version, "11.4.108");
    // File hash is a lowercase 64-char sha256.
    assert_eq!(fp.file_sha256.len(), 64);
    // build-id was requested via -Wl,--build-id=sha1.
    let build_id = fp.build_id.as_deref().expect("build-id present");
    assert!(!build_id.is_empty() && build_id.chars().all(|c| c.is_ascii_hexdigit()));
    // SONAME stem recovered and stripped of its version suffix.
    assert_eq!(fp.soname_stem.as_deref(), Some("libcudabomtest.so"));

    // Folding into a db records both strong signals under the component.
    let db = to_db(std::slice::from_ref(&fp));
    let cudart = db.components.iter().find(|c| c.name == "cudart").unwrap();
    assert_eq!(
        cudart.file_hashes[&fp.file_sha256],
        vec!["11.4.108".to_string()]
    );
    assert_eq!(cudart.build_ids[build_id], vec!["11.4.108".to_string()]);
    assert_eq!(cudart.soname_stems, vec!["libcudabomtest.so"]);
}
