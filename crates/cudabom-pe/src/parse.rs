//! PE/COFF parsing: turn Windows binary bytes into [`PeFacts`].
//!
//! Parsing uses the `object` crate's format-agnostic reader for the structural
//! facts (machine, kind, sections, imported DLLs, exported symbols) and a
//! targeted scan of the `.rsrc` section for the `VS_VERSIONINFO` resource,
//! from which NVIDIA's `ProductName`/`ProductVersion`/`FileVersion` strings are
//! recovered. The parser is panic-free on malformed input: every fallible step
//! returns a [`cudabom_core::Error`], never a crash.

use std::collections::BTreeSet;

use cudabom_core::{Error, Result};
use object::read::{Object, ObjectSection};
use object::ObjectKind;

use crate::facts::{PeClass, PeFacts, PeKind, VersionString};

/// Parse `bytes` as a PE image and extract [`PeFacts`].
///
/// # Errors
/// Returns [`Error::input`] if the bytes are not a parseable PE image.
pub fn parse(bytes: &[u8]) -> Result<PeFacts> {
    let file = object::read::File::parse(bytes)
        .map_err(|e| Error::input(format!("not a parseable PE: {e}")))?;

    // Reject non-PE inputs that `object` nonetheless parsed (e.g. an ELF): this
    // crate is PE-only, and the extractor dispatches by magic, but guard anyway.
    if file.format() != object::BinaryFormat::Pe && file.format() != object::BinaryFormat::Coff {
        return Err(Error::input(format!(
            "not a PE image (format: {:?})",
            file.format()
        )));
    }

    let class = if file.is_64() {
        PeClass::Pe32Plus
    } else {
        PeClass::Pe32
    };

    let kind = match file.kind() {
        // A DLL is reported as a dynamic image by `object`.
        ObjectKind::Dynamic => PeKind::Dll,
        ObjectKind::Executable => PeKind::Executable,
        _ => PeKind::Other,
    };

    // Same spelling as the ELF path (`object::Architecture`'s Debug form, e.g.
    // `X86_64`) so an architecture compares equal across the ELF and PE paths.
    let machine = format!("{:?}", file.architecture());

    // Imported DLL names (deduplicated, sorted): the strongest structural CUDA
    // signal on Windows is a dependency on e.g. `cudart64_12.dll`.
    let mut dlls: BTreeSet<String> = BTreeSet::new();
    if let Ok(imports) = file.imports() {
        for import in imports.flatten() {
            let lib = String::from_utf8_lossy(import.library()).into_owned();
            if !lib.is_empty() {
                dlls.insert(lib);
            }
        }
    }
    let imported_dlls: Vec<String> = dlls.into_iter().collect();

    // Exported symbol names (deduplicated, sorted).
    let mut exports: BTreeSet<String> = BTreeSet::new();
    if let Ok(exported) = file.exports() {
        for export in exported.flatten() {
            if let Some(name) = export.name().name() {
                let name = String::from_utf8_lossy(name).into_owned();
                if !name.is_empty() {
                    exports.insert(name);
                }
            }
        }
    }
    let exported_symbols: Vec<String> = exports.into_iter().collect();

    // Section names (as present, sorted/deduplicated for determinism).
    let mut sections: BTreeSet<String> = BTreeSet::new();
    for section in file.sections() {
        if let Ok(name) = section.name() {
            sections.insert(name.to_string());
        }
    }
    let section_names: Vec<String> = sections.into_iter().collect();

    // Version resource strings. The VS_VERSIONINFO block lives in `.rsrc`, but
    // its internal strings are UTF-16LE with small binary length/padding words
    // between entries, and the block's byte alignment within the section is not
    // guaranteed. Rather than depend on exact resource-tree offsets or section
    // alignment, locate the `VS_VERSION_INFO` marker in the raw file and parse
    // the StringFileInfo key/value pairs forward from there (handling the
    // binary padding words between entries). This is robust across toolkits
    // and `object` versions.
    let version_strings = parse_version_strings(bytes);

    Ok(PeFacts {
        class,
        kind,
        machine,
        imported_dlls,
        exported_symbols,
        section_names,
        version_strings,
    })
}

/// Extract `StringFileInfo` key/value pairs from the PE's raw bytes.
///
/// The `VS_VERSIONINFO` resource stores its `StringFileInfo` as a sequence of
/// UTF-16LE, NUL-terminated key then value strings, separated by small binary
/// length/padding words. This locates the `VS_VERSION_INFO` marker and then
/// pulls out the printable UTF-16LE runs that follow, pairing each known key
/// with the next printable run as its value. Working from the marker (rather
/// than a fixed section offset) and scanning for printable runs (rather than a
/// fixed stride) makes the parse robust to the block's byte alignment and the
/// interspersed binary header words. Nothing is inferred: keys and values are
/// read verbatim from the resource.
#[must_use]
fn parse_version_strings(bytes: &[u8]) -> Vec<VersionString> {
    const WANTED: &[&str] = &[
        "ProductName",
        "ProductVersion",
        "FileVersion",
        "FileDescription",
        "CompanyName",
        "InternalName",
        "OriginalFilename",
    ];
    // Structural tokens the version resource interleaves between the string
    // key/value pairs. A known key with no value of its own must not be paired
    // with one of these as if it were data.
    const STRUCTURAL: &[&str] = &[
        "StringFileInfo",
        "VarFileInfo",
        "Translation",
        "VS_VERSION_INFO",
    ];

    // Locate the VS_VERSION_INFO marker (UTF-16LE). Without it there is no
    // version resource to read.
    let marker: Vec<u8> = "VS_VERSION_INFO"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    let Some(start) = find_subslice(bytes, &marker) else {
        return Vec::new();
    };
    let region = &bytes[start..];

    // Pull printable UTF-16LE runs (>= 2 chars) from the region. A "run" is a
    // maximal sequence of UTF-16LE code units in the printable range; the small
    // binary length/padding words between entries break runs apart and are
    // skipped. We try the aligned stream starting at the marker (the marker is
    // itself UTF-16LE, so its parity defines the stream alignment).
    let tokens = printable_utf16_runs(region);

    // Pair each wanted key with the next printable run as its value.
    let mut out: Vec<VersionString> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for i in 0..tokens.len() {
        let tok = tokens[i].trim();
        if let Some(key) = WANTED.iter().find(|k| k.eq_ignore_ascii_case(tok)) {
            if let Some(next) = tokens.get(i + 1) {
                let value = next.trim();
                // Reject a "value" that is really another known key (this key
                // had no value), a structural token, or a code-page/language
                // block such as "040904b0" that follows VarFileInfo. The block
                // check requires a hex letter so purely numeric version strings
                // (e.g. "1300") are not mistaken for one.
                let is_key = WANTED.iter().any(|k| k.eq_ignore_ascii_case(value));
                let is_structural = STRUCTURAL.iter().any(|s| s.eq_ignore_ascii_case(value));
                let is_hex_block = value.len() >= 4
                    && value.chars().all(|c| c.is_ascii_hexdigit())
                    && value.chars().any(|c| c.is_ascii_alphabetic());
                if !value.is_empty()
                    && !is_key
                    && !is_structural
                    && !is_hex_block
                    && seen.insert((*key).to_string())
                {
                    out.push(VersionString {
                        key: (*key).to_string(),
                        value: value.to_string(),
                    });
                }
            }
        }
    }
    out
}

/// Maximal runs of printable UTF-16LE text (>= 2 chars) in `bytes`, in order.
///
/// Interprets `bytes` as little-endian u16 code units from offset 0. A code
/// unit counts as "printable" if it is a normal character (not a control code
/// below space, except it stops the run on NUL or an out-of-plane value). The
/// binary length/padding words interspersed in the version resource contain
/// control/zero bytes, so they terminate runs and are naturally excluded.
fn printable_utf16_runs(bytes: &[u8]) -> Vec<String> {
    let mut runs = Vec::new();
    let mut cur: Vec<u16> = Vec::new();
    let units = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]));
    for u in units {
        // Printable: >= 0x20 and not a surrogate half (keeps the parse simple
        // and ASCII/Latin-focused, which covers version-resource strings).
        let printable = u >= 0x20 && !(0xD800..=0xDFFF).contains(&u);
        if printable {
            cur.push(u);
        } else {
            if cur.len() >= 2 {
                runs.push(String::from_utf16_lossy(&cur));
            }
            cur.clear();
        }
    }
    if cur.len() >= 2 {
        runs.push(String::from_utf16_lossy(&cur));
    }
    runs
}

/// Index of the first occurrence of `needle` in `haystack`, if any.
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_pe_bytes_are_rejected() {
        assert!(parse(b"not a pe at all").is_err());
        // An ELF header must not parse as PE.
        assert!(parse(&[0x7F, b'E', b'L', b'F', 2, 1, 1, 0]).is_err());
    }

    #[test]
    fn version_strings_recovered_from_utf16_block() {
        // Build a VS_VERSIONINFO-shaped UTF-16LE token stream with the required
        // marker and small binary padding words between entries (as real PE
        // resources have), to exercise the printable-run parse.
        fn utf16(s: &str) -> Vec<u8> {
            let mut v: Vec<u8> = s.encode_utf16().flat_map(u16::to_le_bytes).collect();
            v.extend_from_slice(&[0, 0]); // NUL terminator
            v
        }
        let pad = [0x58u8, 0x1c, 0x01, 0x00]; // a 4-byte (DWORD) padding word
        let mut blob = Vec::new();
        blob.extend(utf16("VS_VERSION_INFO"));
        blob.extend_from_slice(&pad);
        blob.extend(utf16("ProductName"));
        blob.extend_from_slice(&pad);
        blob.extend(utf16("NVIDIA CUDA 12.4.99 Runtime"));
        blob.extend_from_slice(&pad);
        blob.extend(utf16("ProductVersion"));
        blob.extend_from_slice(&pad);
        blob.extend(utf16("6,14,11,12040"));

        let vs = parse_version_strings(&blob);
        let get = |k: &str| vs.iter().find(|v| v.key == k).map(|v| v.value.as_str());
        assert_eq!(get("ProductName"), Some("NVIDIA CUDA 12.4.99 Runtime"));
        assert_eq!(get("ProductVersion"), Some("6,14,11,12040"));
    }

    #[test]
    fn empty_or_markerless_yields_no_strings() {
        assert!(
            parse_version_strings(&[]).is_empty(),
            "empty input yields no version strings"
        );
        assert!(
            parse_version_strings(&[0, 0]).is_empty(),
            "two zero bytes yield no version strings"
        );
        // Printable UTF-16 but no VS_VERSION_INFO marker: nothing.
        let txt: Vec<u8> = "ProductName\0value"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        assert!(
            parse_version_strings(&txt).is_empty(),
            "UTF-16 text without a VS_VERSION_INFO marker yields nothing"
        );
    }

    #[test]
    fn key_without_value_is_not_paired_with_structural_token() {
        // A key with no value of its own, immediately followed by the
        // VarFileInfo / Translation structural tokens and the 040904b0
        // code-page block. None of those may be recorded as the key's value.
        fn utf16(s: &str) -> Vec<u8> {
            let mut v: Vec<u8> = s.encode_utf16().flat_map(u16::to_le_bytes).collect();
            v.extend_from_slice(&[0, 0]);
            v
        }
        let pad = [0x58u8, 0x1c, 0x01, 0x00];
        let mut blob = Vec::new();
        blob.extend(utf16("VS_VERSION_INFO"));
        blob.extend_from_slice(&pad);
        // FileVersion has no value before the block structure begins.
        blob.extend(utf16("FileVersion"));
        blob.extend_from_slice(&pad);
        blob.extend(utf16("VarFileInfo"));
        blob.extend_from_slice(&pad);
        blob.extend(utf16("Translation"));
        blob.extend_from_slice(&pad);
        blob.extend(utf16("040904b0"));

        let vs = parse_version_strings(&blob);
        assert!(
            vs.iter().all(|v| v.key != "FileVersion"),
            "FileVersion must not be paired with a structural/hex token: {vs:?}"
        );
    }
}
