//! Linux-only tests that compile a real shared object with the system toolchain
//! and assert cudabom recovers its SONAME, NEEDED entries, build-id, and
//! exported symbols. These facts live in the ELF `.dynamic` section and the
//! `.note.gnu.build-id` note, which the `object` writer does not synthesize, so
//! a real linker is used. Gated to Linux because that is where ELF `.so`s and a
//! C toolchain exist (and where CI runs); skipped elsewhere.

#![cfg(target_os = "linux")]

use std::process::Command;

use cudabom_elf::{parse, section_strings, ElfType};

/// Compile `source` into a shared object with the given soname and return its
/// bytes. Returns `None` if no C compiler is available on PATH.
fn compile_shared(source: &str, soname: &str) -> Option<Vec<u8>> {
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
    std::fs::write(&src, source).ok()?;

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
fn recovers_soname_needed_buildid_and_exports() {
    // A function whose name we assert appears among exported dynamic symbols,
    // plus a rodata string we can pull back out. The call into `strlen` forces a
    // real `DT_NEEDED` dependency on libc even under the linker's `--as-needed`
    // default, so the NEEDED assertion below tests fact recovery (not linker
    // policy): without an actual libc reference a modern toolchain emits no
    // `DT_NEEDED` at all.
    let source = r#"
        #include <string.h>
        const char *cudabom_marker = "CUDA test marker 12.4";
        unsigned long cudabom_public_symbol(const char *s) { return strlen(s) + 1; }
    "#;
    let Some(bytes) = compile_shared(source, "libcudabomtest.so.1") else {
        eprintln!("no C compiler available; skipping");
        return;
    };

    let facts = parse(&bytes).expect("parse real .so");

    assert_eq!(facts.elf_type, ElfType::SharedObject);
    assert!(facts.dynamically_linked);

    // SONAME set via -Wl,-soname.
    assert_eq!(facts.soname.as_deref(), Some("libcudabomtest.so.1"));

    // The C runtime is a NEEDED dependency of any normal shared object.
    assert!(
        facts.needed.iter().any(|n| n.starts_with("libc.so")),
        "expected libc among NEEDED, got {:?}",
        facts.needed
    );

    // build-id note requested via -Wl,--build-id.
    let build_id = facts.build_id.expect("build-id present");
    assert!(!build_id.is_empty() && build_id.chars().all(|c| c.is_ascii_hexdigit()));

    // Our exported function appears in the dynamic symbol table.
    assert!(
        facts
            .exported_symbols
            .iter()
            .any(|s| s == "cudabom_public_symbol"),
        "expected exported symbol, got {:?}",
        facts.exported_symbols
    );

    // The rodata marker string is recoverable.
    let strings = section_strings(&bytes, ".rodata", 6, 1000);
    assert!(
        strings.iter().any(|s| s.contains("CUDA test marker 12.4")),
        "expected rodata marker, got {strings:?}"
    );
}

/// Compile `source` into a relocatable object (`.o`), as found inside a static
/// archive. Returns `None` if no C compiler is available on PATH.
fn compile_object(source: &str) -> Option<Vec<u8>> {
    let cc = if Command::new("cc").arg("--version").output().is_ok() {
        "cc"
    } else if Command::new("gcc").arg("--version").output().is_ok() {
        "gcc"
    } else {
        return None;
    };

    let dir = tempfile::tempdir().ok()?;
    let src = dir.path().join("obj.c");
    let out = dir.path().join("obj.o");
    std::fs::write(&src, source).ok()?;

    let status = Command::new(cc)
        .args(["-c", "-fPIC"])
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
fn recovers_exported_symbols_from_relocatable_symtab() {
    // A relocatable `.o` (a static-archive member) has no `.dynsym`; its defined
    // global symbols live in `.symtab`. The parser must surface them so a static
    // archive can be identified by its component's namespaced API symbols.
    let source = r"
        int ncclInternalHelper(int x) { return x + 1; }  /* local-ish name, still global */
        int ncclAllReduce(int x) { return x + 2; }
        static int private_helper(int x) { return x + 3; }  /* static: not global */
    ";
    let Some(bytes) = compile_object(source) else {
        eprintln!("no C compiler available; skipping");
        return;
    };

    let facts = parse(&bytes).expect("parse real .o");
    assert_eq!(facts.elf_type, ElfType::Relocatable);

    // Defined global symbols are recovered from `.symtab`.
    assert!(
        facts.exported_symbols.iter().any(|s| s == "ncclAllReduce"),
        "expected .symtab global symbol, got {:?}",
        facts.exported_symbols
    );
    // A `static` function is not global and must not appear.
    assert!(
        !facts.exported_symbols.iter().any(|s| s == "private_helper"),
        "static symbol must not be exported, got {:?}",
        facts.exported_symbols
    );
}
