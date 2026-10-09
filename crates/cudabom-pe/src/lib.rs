//! PE/COFF fact extraction for cudabom.
//!
//! Responsibility: parse a Windows PE image (DLL or executable) and report
//! structural facts: class/kind/machine, imported DLL names, exported
//! symbols, section names, and the `VS_VERSIONINFO` version strings
//! (`ProductName`/`ProductVersion`/`FileVersion`). These facts are the raw
//! material the identify crate turns into evidence, mirroring the `cudabom_elf`
//! crate for the Windows side of a CUDA toolkit.
//!
//! Parsing uses the `object` crate's format-agnostic reader plus a targeted
//! version-resource scan. The parser is panic-free on malformed input.

mod facts;
mod parse;

pub use facts::{PeClass, PeFacts, PeKind, VersionString};
pub use parse::parse;
