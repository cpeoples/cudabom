//! The structured facts cudabom extracts from a PE (Portable Executable) file.
//!
//! As with the ELF facts in `cudabom_elf`, these are raw, observed facts, not
//! identity claims. The identify crate turns them into evidence and component
//! identities. Every field is something literally present in the parsed bytes.

use serde::Serialize;

/// PE "bitness", from the optional-header magic (`PE32` vs `PE32+`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PeClass {
    /// `PE32` (0x10b): 32-bit image.
    Pe32,
    /// `PE32+` (0x20b): 64-bit image.
    Pe32Plus,
}

/// The PE image kind, derived from the characteristics / optional header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PeKind {
    /// A DLL (`IMAGE_FILE_DLL` set): the common CUDA Windows case.
    Dll,
    /// An executable image.
    Executable,
    /// Any other / unknown image kind.
    Other,
}

/// A single key/value pair from the version resource's `StringFileInfo`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VersionString {
    /// The key (e.g. `ProductName`, `ProductVersion`, `FileVersion`).
    pub key: String,
    /// The UTF-8 value as read from the resource.
    pub value: String,
}

/// Facts extracted from a single PE file.
///
/// Collections are sorted and de-duplicated so output is deterministic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PeFacts {
    /// 32- or 64-bit image.
    pub class: PeClass,
    /// DLL vs executable.
    pub kind: PeKind,
    /// Target machine name (e.g. `X86_64`, `I386`, `Arm64`), from the COFF
    /// header's `Machine` field.
    pub machine: String,
    /// Imported DLL names, in file order (e.g. `cudart64_12.dll`). The single
    /// strongest *structural* CUDA signal for a Windows binary.
    pub imported_dlls: Vec<String>,
    /// Names of symbols the image *exports*, when it has an export table.
    pub exported_symbols: Vec<String>,
    /// Section names present in the section table.
    pub section_names: Vec<String>,
    /// `VS_VERSIONINFO` `StringFileInfo` entries, when a version resource is
    /// present. NVIDIA stamps `ProductName` (e.g. "NVIDIA CUDA 12.4.99
    /// Runtime"), `ProductVersion`, and `FileVersion` here: the Windows
    /// analogue of a version string. Empty when no resource is found.
    pub version_strings: Vec<VersionString>,
}

impl PeFacts {
    /// The value of a `StringFileInfo` key, if the version resource carried it.
    #[must_use]
    pub fn version_string(&self, key: &str) -> Option<&str> {
        self.version_strings
            .iter()
            .find(|v| v.key.eq_ignore_ascii_case(key))
            .map(|v| v.value.as_str())
    }
}
