//! ELF fact extraction for cudabom.
//!
//! Responsibility: parse an ELF object, shared library, or executable and
//! report structural facts: class/endianness/type/arch, SONAME, `NEEDED`
//! entries, run paths, GNU build-id, section names, and exported dynamic
//! symbols. These facts are the raw material the identify crate turns into
//! evidence.
//!
//! Parsing is done with the `object` crate's low-level ELF reader, driven
//! generically over the `FileHeader` trait so 32- and 64-bit and both
//! endiannesses share one code path. The parser is panic-free on malformed
//! input: every fallible step returns a [`cudabom_core::Error`], never a crash.

mod facts;
mod parse;

pub use facts::{ElfClass, ElfFacts, ElfType, Endianness};
pub use parse::{find_embedded_elf, parse, section_strings};
