//! ELF parsing implementation.
//!
//! Uses `object::read::elf` generically over the `FileHeader` trait so one code
//! path handles ELF32/ELF64 and little/big endian. We read the header to pick
//! the class/endianness, then dispatch to the matching monomorphized parser.

use cudabom_core::{Error, Result};
use object::read::elf::{Dyn, ElfFile, FileHeader};
use object::{Endian, Endianness as ObjEndianness, Object, ObjectSection, ObjectSymbol};

use crate::facts::{ElfClass, ElfFacts, ElfType, Endianness};

/// Parse `data` as an ELF file and extract [`ElfFacts`].
///
/// Returns [`Error::Malformed`] if the bytes are not a valid ELF the parser can
/// read. Never panics on hostile input.
pub fn parse(data: &[u8]) -> Result<ElfFacts> {
    // Peek at e_ident to choose 32- vs 64-bit; object validates the rest.
    // EI_CLASS is byte index 4: 1 = ELFCLASS32, 2 = ELFCLASS64.
    const EI_CLASS: usize = 4;
    const ELFCLASS32: u8 = 1;
    const ELFCLASS64: u8 = 2;

    let class_byte = *data
        .get(EI_CLASS)
        .ok_or_else(|| Error::malformed("ELF too short for e_ident"))?;

    match class_byte {
        ELFCLASS64 => parse_with::<object::elf::FileHeader64<ObjEndianness>>(data),
        ELFCLASS32 => parse_with::<object::elf::FileHeader32<ObjEndianness>>(data),
        other => Err(Error::malformed(format!("unknown ELF class byte {other}"))),
    }
}

/// ELF magic (`0x7F 'E' 'L' 'F'`, ELF spec `e_ident[EI_MAG0..3]`).
const ELF_MAGIC: [u8; 4] = [0x7F, b'E', b'L', b'F'];

/// Find every ELF object embedded in a larger buffer at a non-zero offset,
/// returning the byte offset and [`ElfFacts`] for each.
///
/// Mirrors `cudabom_fatbin::find_embedded_fatbins`: a fast scan for the ELF
/// magic, then validation by *fully parsing* each candidate (a stray magic that
/// does not parse into a real ELF with a readable header is skipped). This is what
/// catches a CUDA `.so` hidden behind a junk prefix or wrapped in an otherwise
/// unrecognized container, without ever claiming a match on bytes that merely
/// contain the four magic bytes.
///
/// Only offsets `> 0` are reported: a buffer that *is* an ELF at offset 0 is
/// handled by the normal [`parse`] path, so callers use this strictly for the
/// embedded case and do not double-count the host file. `max_hits` bounds the
/// number of containers reported so a buffer full of magic-like bytes cannot
/// cause unbounded work.
#[must_use]
pub fn find_embedded_elf(data: &[u8], max_hits: usize) -> Vec<(usize, ElfFacts)> {
    let mut hits = Vec::new();
    if max_hits == 0 {
        return hits;
    }
    // Nothing can be embedded past offset 0 unless the buffer is at least one
    // byte longer than the magic we scan from offset 1. Guard here so the
    // `data[search_from..]` slice below can never index past the end: an empty
    // or sub-magic buffer (e.g. a zero-length member handed to us by an archive
    // or extractor) must return no hits rather than panic. A scanner fed
    // untrusted input must never crash on a degenerate buffer.
    if data.len() <= ELF_MAGIC.len() {
        return hits;
    }
    // Scan for the 4-byte magic. We start at offset 1 so the host-file ELF
    // (offset 0) is never reported here; that case is the normal `parse` path.
    let mut search_from = 1usize;
    while let Some(rel) = find_magic(&data[search_from..]) {
        let pos = search_from + rel;
        // Validate by fully parsing the slice starting at the candidate. The
        // `object` reader treats offsets as relative to this slice, so trailing
        // junk after the ELF is harmless. Only a slice that parses into a real
        // ELF is recorded.
        if let Ok(facts) = parse(&data[pos..]) {
            hits.push((pos, facts));
            if hits.len() >= max_hits {
                break;
            }
        }
        // Advance past this magic so overlapping/false candidates do not loop.
        search_from = pos + ELF_MAGIC.len();
        if search_from >= data.len() {
            break;
        }
    }
    hits
}

/// Index of the first occurrence of the ELF magic in `data`, if any.
fn find_magic(data: &[u8]) -> Option<usize> {
    data.windows(ELF_MAGIC.len())
        .position(|window| window == ELF_MAGIC)
}

/// Monomorphized parser for a concrete `FileHeader` implementation.
fn parse_with<H>(data: &[u8]) -> Result<ElfFacts>
where
    H: FileHeader<Endian = ObjEndianness>,
{
    let header = H::parse(data).map_err(|e| Error::malformed(format!("bad ELF header: {e}")))?;
    let endian = header
        .endian()
        .map_err(|e| Error::malformed(format!("bad ELF endianness: {e}")))?;

    // High-level view for arch/type/sections/symbols/build-id.
    let file: ElfFile<'_, H, &[u8]> =
        ElfFile::parse(data).map_err(|e| Error::malformed(format!("bad ELF: {e}")))?;

    let class = if header.is_type_64() {
        ElfClass::Elf64
    } else {
        ElfClass::Elf32
    };
    let endianness = if endian.is_little_endian() {
        Endianness::Little
    } else {
        Endianness::Big
    };
    let elf_type = match file.kind() {
        object::ObjectKind::Relocatable => ElfType::Relocatable,
        object::ObjectKind::Executable => ElfType::Executable,
        object::ObjectKind::Dynamic => ElfType::SharedObject,
        object::ObjectKind::Core => ElfType::Core,
        // Record the raw e_type verbatim for anything outside the common set.
        _ => ElfType::Other(header.e_type(endian).0),
    };
    let architecture = format!("{:?}", file.architecture());

    // Section names (deterministic order preserved from the table).
    let mut section_names = Vec::new();
    for section in file.sections() {
        if let Ok(name) = section.name() {
            section_names.push(name.to_string());
        }
    }

    // Symbols this object defines and exports, global and named. A dynamic
    // object exposes these via `.dynsym`; a relocatable object (`.o`, including
    // the members of a static `.a`) has no `.dynsym`, so fall back to the
    // regular symbol table (`.symtab`) for the same "defined, global, named"
    // set. Either way this is the set of names the object publishes.
    let mut exported_symbols = Vec::new();
    for symbol in file.dynamic_symbols() {
        if symbol.is_definition() && symbol.is_global() {
            if let Ok(name) = symbol.name() {
                if !name.is_empty() {
                    exported_symbols.push(name.to_string());
                }
            }
        }
    }
    if exported_symbols.is_empty() {
        for symbol in file.symbols() {
            if symbol.is_definition() && symbol.is_global() {
                if let Ok(name) = symbol.name() {
                    if !name.is_empty() {
                        exported_symbols.push(name.to_string());
                    }
                }
            }
        }
    }
    exported_symbols.sort_unstable();
    exported_symbols.dedup();

    // GNU build-id via the high-level API (borrows only within this scope).
    let build_id = file.build_id().ok().flatten().map(cudabom_core::hex_lower);

    // Dynamic-section facts: SONAME, NEEDED, runpaths.
    let dynamic = read_dynamic::<H>(header, endian, data)?;

    let dynamically_linked = dynamic.is_some() || !exported_symbols.is_empty();
    let (soname, needed, runpaths) = dynamic.unwrap_or_default();

    Ok(ElfFacts {
        class,
        endianness,
        elf_type,
        architecture,
        soname,
        needed,
        runpaths,
        build_id,
        section_names,
        exported_symbols,
        dynamically_linked,
    })
}

/// Collected dynamic-section facts: (SONAME, NEEDED, runpaths).
type DynamicFacts = (Option<String>, Vec<String>, Vec<String>);

/// DT tag constants (ELF spec). `tag32` yields i32 (Elf32_Sword semantics).
const DT_NEEDED: i32 = 1;
const DT_SONAME: i32 = 14;
const DT_RPATH: i32 = 15;
const DT_RUNPATH: i32 = 29;

/// Read `DT_SONAME`, `DT_NEEDED`, and `DT_RUNPATH`/`DT_RPATH` from `.dynamic`.
///
/// Returns `None` if there is no dynamic section (a static object). String
/// values are resolved against the dynamic string table linked by `.dynamic`.
fn read_dynamic<H>(header: &H, endian: ObjEndianness, data: &[u8]) -> Result<Option<DynamicFacts>>
where
    H: FileHeader<Endian = ObjEndianness>,
{
    let sections = header
        .sections(endian, data)
        .map_err(|e| Error::malformed(format!("bad section table: {e}")))?;

    let Some((dynamic, strtab_index)) = sections
        .dynamic(endian, data)
        .map_err(|e| Error::malformed(format!("bad .dynamic: {e}")))?
    else {
        return Ok(None);
    };

    // `dynamic` already returns the string-table index linked by the dynamic
    // section's `sh_link`; resolve against that rather than re-scanning for the
    // first `SHT_DYNAMIC` (which could pick a different section and silently
    // fall back to the null section index 0).
    let strings = sections
        .strings(endian, data, strtab_index)
        .map_err(|e| Error::malformed(format!("bad dynamic string table: {e}")))?;

    let mut soname = None;
    let mut needed = Vec::new();
    let mut runpaths = Vec::new();

    for entry in dynamic {
        let Some(tag) = entry.tag32(endian) else {
            continue;
        };
        let resolve = || -> Option<String> {
            entry
                .string(endian, strings)
                .ok()
                .and_then(|b| std::str::from_utf8(b).ok())
                .map(ToString::to_string)
        };
        match tag {
            DT_SONAME => soname = resolve(),
            DT_NEEDED => {
                if let Some(name) = resolve() {
                    needed.push(name);
                }
            }
            DT_RUNPATH | DT_RPATH => {
                if let Some(path) = resolve() {
                    runpaths.push(path);
                }
            }
            _ => {}
        }
    }

    Ok(Some((soname, needed, runpaths)))
}

/// Extract printable ASCII strings of at least `min_len` bytes from a named
/// section (e.g. `.rodata`), returning at most `max_count` of them.
///
/// This is the raw material for `VersionString` evidence. It is a separate,
/// opt-in call (not part of [`parse`]) because a section like `.rodata` can be
/// large; callers bound the work via `min_len`/`max_count`. Strings are
/// returned in first-seen order, de-duplicated. Returns an empty vec if the
/// section is absent or the file is not a valid ELF.
pub fn section_strings(
    data: &[u8],
    section: &str,
    min_len: usize,
    max_count: usize,
) -> Vec<String> {
    let Ok(file) = object::File::parse(data) else {
        return Vec::new();
    };
    let Some(sec) = file.section_by_name(section) else {
        return Vec::new();
    };
    let Ok(bytes) = sec.data() else {
        return Vec::new();
    };
    extract_ascii_strings(bytes, min_len, max_count)
}

/// Pull printable-ASCII, NUL/whitespace-delimited runs out of a byte buffer.
fn extract_ascii_strings(bytes: &[u8], min_len: usize, max_count: usize) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut current = String::new();

    let flush = |current: &mut String,
                 out: &mut Vec<String>,
                 seen: &mut std::collections::HashSet<String>| {
        if current.len() >= min_len && seen.insert(current.clone()) {
            out.push(std::mem::take(current));
        } else {
            current.clear();
        }
    };

    for &b in bytes {
        // Printable ASCII range (space through tilde).
        if (0x20..=0x7e).contains(&b) {
            current.push(b as char);
        } else {
            flush(&mut current, &mut out, &mut seen);
            if out.len() >= max_count {
                return out;
            }
        }
    }
    flush(&mut current, &mut out, &mut seen);
    out.truncate(max_count);
    out
}

#[cfg(test)]
mod string_tests {
    use super::extract_ascii_strings;

    #[test]
    fn extracts_min_length_runs_only() {
        let data = b"ab\0CUDA Version 12.4\0xy\0longenoughstring";
        let strings = extract_ascii_strings(data, 4, 100);
        assert!(strings.contains(&"CUDA Version 12.4".to_string()));
        assert!(strings.contains(&"longenoughstring".to_string()));
        // "ab" and "xy" are below the 4-char minimum.
        assert!(!strings.iter().any(|s| s == "ab" || s == "xy"));
    }

    #[test]
    fn dedupes_and_caps_count() {
        let data = b"repeat\0repeat\0unique\0";
        let strings = extract_ascii_strings(data, 3, 100);
        assert_eq!(strings.iter().filter(|s| *s == "repeat").count(), 1);

        let many = b"aaaa\0bbbb\0cccc\0dddd\0";
        let capped = extract_ascii_strings(many, 3, 2);
        assert_eq!(capped.len(), 2);
    }
}

#[cfg(test)]
mod embedded_tests {
    use super::find_embedded_elf;
    use object::write;

    /// A minimal, real ELF64 shared object the `object` reader parses normally.
    fn minimal_elf() -> Vec<u8> {
        let mut obj = write::Object::new(
            object::BinaryFormat::Elf,
            object::Architecture::X86_64,
            object::Endianness::Little,
        );
        // A trivial defined symbol in .text so the file has real content.
        let text = obj.section_id(write::StandardSection::Text);
        obj.append_section_data(text, &[0x90, 0x90, 0x90, 0x90], 1);
        obj.write().expect("write minimal ELF")
    }

    #[test]
    fn finds_elf_behind_junk_prefix() {
        let elf = minimal_elf();
        let mut buf = vec![0xABu8; 65_536]; // 64 KiB of non-ELF junk
        let at = buf.len();
        buf.extend_from_slice(&elf);

        let hits = find_embedded_elf(&buf, 8);
        assert_eq!(hits.len(), 1, "expected exactly one embedded ELF");
        assert_eq!(hits[0].0, at, "offset should be the junk-prefix length");
    }

    #[test]
    fn ignores_host_elf_at_offset_zero() {
        // A buffer that *is* an ELF at offset 0 is the normal `parse` path; the
        // embedded scan must not re-report it (it starts searching at offset 1).
        let elf = minimal_elf();
        let hits = find_embedded_elf(&elf, 8);
        assert!(
            hits.iter().all(|(off, _)| *off > 0),
            "offset-0 host ELF must not be reported as embedded"
        );
    }

    #[test]
    fn stray_magic_bytes_are_not_a_match() {
        // The four magic bytes alone do not parse into a real ELF, so a buffer
        // sprinkled with them yields no hits: no false positives.
        let mut buf = vec![0u8; 1024];
        buf[100..104].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
        buf[500..504].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
        assert!(
            find_embedded_elf(&buf, 8).is_empty(),
            "bare ELF magic without a valid header must not be reported"
        );
    }

    #[test]
    fn max_hits_bounds_results() {
        let elf = minimal_elf();
        // Two embedded ELFs, but a cap of one.
        let mut buf = vec![0xAAu8; 16];
        buf.extend_from_slice(&elf);
        buf.extend_from_slice(&[0xAAu8; 16]);
        buf.extend_from_slice(&elf);
        let hits = find_embedded_elf(&buf, 1);
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn empty_and_short_buffers_do_not_panic() {
        // Regression: the embedded scan starts searching at offset 1, so it
        // sliced `data[1..]` unconditionally and panicked on a zero-length
        // buffer, which is exactly what a benign empty `__init__.py` in a
        // Python wheel produces when every walked file is scanned. A scanner
        // must never crash on untrusted input; these must simply yield no hits.
        assert!(
            find_embedded_elf(&[], 8).is_empty(),
            "an empty buffer must yield no hits (no panic)"
        );
        assert!(
            find_embedded_elf(&[0x7F], 8).is_empty(),
            "a one-byte buffer must yield no hits (no panic)"
        );
        assert!(
            find_embedded_elf(&[0x7F, b'E', b'L', b'F'], 8).is_empty(),
            "bare magic with no room for a header must yield no hits"
        );
        // One byte past the magic is still too short to embed anything.
        assert!(
            find_embedded_elf(&[0x7F, b'E', b'L', b'F', 0x00], 8).is_empty(),
            "a buffer too short to embed an ELF must yield no hits"
        );
    }
}
