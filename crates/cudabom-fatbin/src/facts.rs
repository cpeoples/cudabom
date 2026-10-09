//! Facts cudabom extracts from GPU code (fatbin containers, cubins, PTX).
//!
//! As with ELF facts, these are raw observations, not identity claims. Fields
//! whose meaning is documented and stable (the fatbin wrapper magic, PTX
//! `.target` directives, cubin ELF machine) are reported with confidence; the
//! parser records only what it can verify from the bytes and bounds-checks
//! every offset so malformed GPU code cannot crash or mislead the scanner.

use serde::Serialize;

/// The kind of a single GPU code entry inside a fatbin container.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum EntryKind {
    /// PTX assembly (text intermediate representation).
    Ptx,
    /// A cubin (compiled ELF for a specific SM architecture).
    Cubin,
    /// An entry whose documented kind code was not recognized; the raw code is
    /// preserved for explainability.
    Unknown(u16),
}

/// One code entry within a fatbin container.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FatbinEntry {
    /// PTX vs. cubin vs. unknown.
    pub kind: EntryKind,
    /// The SM (streaming multiprocessor) architecture this entry targets, as a
    /// number (e.g. `90` for `sm_90`), when the header reports one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sm_arch: Option<u32>,
    /// Byte offset of the entry's payload within the containing buffer.
    pub payload_offset: usize,
    /// Byte length of the entry's payload.
    pub payload_len: usize,
    /// Whether the payload is flagged compressed in the entry header.
    pub compressed: bool,
}

/// Facts about a fatbin container (the `0xBA55ED50` wrapper).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FatbinFacts {
    /// Wrapper format version from the header.
    pub version: u16,
    /// Total declared payload size following the wrapper header.
    pub payload_size: u64,
    /// The entries found, capped to a bounded count.
    pub entries: Vec<FatbinEntry>,
    /// True if parsing stopped early because the entry cap was reached.
    pub truncated: bool,
}

/// Facts about a standalone PTX module (text).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PtxFacts {
    /// The `.version` directive value (PTX ISA version), e.g. `8.3`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub isa_version: Option<String>,
    /// SM targets from `.target sm_XX` directives (numeric, de-duplicated).
    pub targets: Vec<u32>,
    /// `.address_size` directive, when present (32 or 64).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address_size: Option<u32>,
}

/// The unified result of inspecting a buffer for GPU code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case", tag = "gpu_code_kind")]
pub enum GpuCode {
    /// A fatbin container.
    Fatbin(FatbinFacts),
    /// Standalone PTX text.
    Ptx(PtxFacts),
}
