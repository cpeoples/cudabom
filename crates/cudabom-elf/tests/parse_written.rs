//! Parser tests against real ELF bytes.
//!
//! Fixtures are produced with the `object` crate's writer (real, valid ELF, no
//! committed binaries) and, for the dynamic-section facts that the writer does
//! not synthesize, a hand-built minimal dynamic ELF with exact byte offsets.

use cudabom_elf::{parse, ElfClass, ElfType, Endianness};
use object::write::{Object, StandardSection, Symbol, SymbolSection};
use object::{
    Architecture, BinaryFormat, Endianness as ObjEndian, SymbolFlags, SymbolKind, SymbolScope,
};

#[path = "common/dynamic_elf.rs"]
mod dynamic_elf;

/// Build a relocatable ELF64 little-endian object for `arch` that defines one
/// global function symbol named `sym`.
fn build_reloc_elf(arch: Architecture, sym: &str) -> Vec<u8> {
    let mut obj = Object::new(BinaryFormat::Elf, arch, ObjEndian::Little);
    let text = obj.section_id(StandardSection::Text);
    // Give the symbol a little content so it is a real definition.
    let offset = obj.append_section_data(text, &[0x90, 0x90, 0x90, 0x90], 1);
    obj.add_symbol(Symbol {
        name: sym.as_bytes().to_vec(),
        value: offset,
        size: 4,
        kind: SymbolKind::Text,
        scope: SymbolScope::Dynamic,
        weak: false,
        section: SymbolSection::Section(text),
        flags: SymbolFlags::None,
    });
    obj.write().expect("write elf")
}

#[test]
fn parses_class_endianness_type_arch() {
    let bytes = build_reloc_elf(Architecture::X86_64, "do_thing");
    let facts = parse(&bytes).expect("parse");

    assert_eq!(facts.class, ElfClass::Elf64);
    assert_eq!(facts.endianness, Endianness::Little);
    assert_eq!(facts.elf_type, ElfType::Relocatable);
    assert_eq!(facts.architecture, "X86_64");
}

#[test]
fn parses_aarch64_arch() {
    let bytes = build_reloc_elf(Architecture::Aarch64, "kernel_entry");
    let facts = parse(&bytes).expect("parse");
    assert_eq!(facts.architecture, "Aarch64");
    assert_eq!(facts.class, ElfClass::Elf64);
}

#[test]
fn records_section_names() {
    let bytes = build_reloc_elf(Architecture::X86_64, "f");
    let facts = parse(&bytes).expect("parse");
    // A text section must be present in the section header table.
    assert!(
        facts.section_names.iter().any(|n| n == ".text"),
        "expected .text among {:?}",
        facts.section_names
    );
}

#[test]
fn rejects_non_elf_without_panicking() {
    assert!(parse(b"not an elf at all").is_err());
    assert!(parse(&[]).is_err());
    // ELF magic but truncated immediately after: must error, not panic.
    assert!(parse(&[0x7f, b'E', b'L', b'F']).is_err());
}

#[test]
fn rejects_unknown_class_byte() {
    // Valid magic, invalid EI_CLASS (byte 4 = 9).
    let mut bytes = vec![0x7f, b'E', b'L', b'F', 9];
    bytes.extend_from_slice(&[0u8; 60]);
    assert!(parse(&bytes).is_err());
}

#[test]
fn parses_soname_and_needed_from_hand_built_dynamic_elf() {
    // A hand-assembled ELF with a real .dynamic section; runs on every host,
    // covering the SONAME/NEEDED path that the object writer cannot synthesize.
    let bytes =
        dynamic_elf::build_dynamic_elf("libcudart.so.12", &["libc.so.6", "libpthread.so.0"]);
    let facts = parse(&bytes).expect("parse hand-built dynamic ELF");

    assert_eq!(facts.class, ElfClass::Elf64);
    assert_eq!(facts.elf_type, ElfType::SharedObject);
    assert_eq!(facts.soname.as_deref(), Some("libcudart.so.12"));
    assert_eq!(facts.needed, vec!["libc.so.6", "libpthread.so.0"]);
    assert!(facts.dynamically_linked);
}
