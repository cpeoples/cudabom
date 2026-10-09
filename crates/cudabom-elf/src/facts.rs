//! The structured facts cudabom extracts from an ELF file.
//!
//! These are raw, observed facts, not identity claims. The identify crate
//! turns them into evidence and component identities. Every field is something
//! that was literally present in the parsed bytes.

use serde::Serialize;

/// ELF class (32- vs 64-bit), from `e_ident[EI_CLASS]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ElfClass {
    /// `ELFCLASS32`
    Elf32,
    /// `ELFCLASS64`
    Elf64,
}

/// ELF data encoding (endianness), from `e_ident[EI_DATA]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Endianness {
    Little,
    Big,
}

/// The ELF object type, from `e_type`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ElfType {
    /// `ET_REL`: relocatable object (`.o`).
    Relocatable,
    /// `ET_EXEC`: executable.
    Executable,
    /// `ET_DYN`: shared object or PIE.
    SharedObject,
    /// `ET_CORE`: core dump.
    Core,
    /// Any other/unknown `e_type` value (recorded verbatim).
    Other(u16),
}

/// Facts extracted from a single ELF file.
///
/// Collections are sorted and de-duplicated so output is deterministic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ElfFacts {
    /// 32- or 64-bit.
    pub class: ElfClass,
    /// Endianness.
    pub endianness: Endianness,
    /// Object type (`e_type`).
    pub elf_type: ElfType,
    /// Target architecture name (e.g. `X86_64`, `Aarch64`), as reported by the
    /// parser from `e_machine`.
    pub architecture: String,
    /// `DT_SONAME` from the dynamic section, if present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub soname: Option<String>,
    /// `DT_NEEDED` shared-library dependencies, in file order.
    pub needed: Vec<String>,
    /// `DT_RUNPATH` / `DT_RPATH` search paths, if present.
    pub runpaths: Vec<String>,
    /// GNU build-id (lowercase hex), from the `.note.gnu.build-id` note.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub build_id: Option<String>,
    /// Section names present in the section header table.
    pub section_names: Vec<String>,
    /// Names of dynamic symbols the object *exports* (defined, global/weak).
    pub exported_symbols: Vec<String>,
    /// Whether the object is dynamically linked (has a `.dynamic`/interp or
    /// dynamic symbol table). Static executables report false.
    pub dynamically_linked: bool,
}
