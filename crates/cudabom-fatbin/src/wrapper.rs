//! NVIDIA fatbin container parsing.
//!
//! The fatbin *wrapper* is a small, publicly documented header used across the
//! toolchain (cuda-gdb, LLVM's offload tooling) to wrap one or more GPU code
//! images. Its layout, little-endian:
//!
//! ```text
//! magic:       u32  = 0xBA55ED50  // on disk: 50 ED 55 BA
//! version:     u16
//! header_size: u16
//! size:        u64        // bytes of payload following the wrapper header
//! ```
//!
//! Following the wrapper is a sequence of entry headers, each describing one
//! PTX or cubin image. The entry header carries a kind code, target SM
//! architecture, a flags word, and the compressed/uncompressed payload sizes
//! and offset. cudabom parses these conservatively: every field is read with an
//! explicit bounds check, entry counts are capped, and any field the parser
//! cannot verify is either omitted or recorded verbatim rather than guessed.
//!
//! Per the project rule, format behavior is validated against constructed
//! fixtures (see the tests) and observed bytes, not assumed. Fields whose exact
//! semantics are not certain are surfaced as raw values, not interpreted.

use crate::facts::{EntryKind, FatbinEntry, FatbinFacts};
use crate::read::Reader;

/// The fatbin wrapper magic. The documented value is `0xBA55ED50`, which on
/// disk (little-endian) appears as the byte sequence `50 ED 55 BA`.
pub const FATBIN_MAGIC: u32 = 0xBA55_ED50;

/// Documented entry kind codes.
const KIND_PTX: u16 = 0x0001;
const KIND_ELF: u16 = 0x0002;

/// Flag bit indicating the entry payload is compressed.
const FLAG_COMPRESSED: u64 = 0x0000_0000_0000_0002;

/// Upper bound on entries parsed from one container, so a hostile or huge
/// fatbin cannot make the scanner allocate unboundedly. Real libraries have
/// many entries but this is generous.
const MAX_ENTRIES: usize = 4096;

/// Documented sizes.
const WRAPPER_LEN: usize = 16; // magic(4) + version(2) + header_size(2) + size(8)

/// Return true if `bytes` begins with the fatbin wrapper magic.
#[must_use]
pub fn has_fatbin_magic(bytes: &[u8]) -> bool {
    Reader::new(bytes)
        .u32_le_at(0)
        .is_some_and(|m| m == FATBIN_MAGIC)
}

/// Parse a fatbin container starting at offset 0 of `bytes`.
///
/// Returns `None` if the buffer does not start with the wrapper magic or is too
/// short to hold the wrapper header. Never panics: a malformed body yields
/// whatever entries could be validated, with `truncated` reflecting an early
/// stop.
#[must_use]
pub(crate) fn parse(bytes: &[u8]) -> Option<FatbinFacts> {
    let reader = Reader::new(bytes);
    if reader.u32_le_at(0)? != FATBIN_MAGIC {
        return None;
    }
    let version = reader.u16_le_at(4)?;
    let header_size = reader.u16_le_at(6)? as usize;
    let payload_size = reader.u64_le_at(8)?;

    // Entries begin after the wrapper header. header_size is the documented
    // wrapper size; fall back to the fixed length if it is implausibly small.
    let start = header_size.max(WRAPPER_LEN);
    let mut cursor = start;

    let mut entries = Vec::new();
    let mut truncated = false;

    // Each entry header is parsed with bounds checks. We stop cleanly at the
    // end of the buffer, at the declared payload end, or at the entry cap.
    // The declared payload follows the wrapper header, so anchor its end on the
    // same start used for the cursor rather than a fixed offset.
    let payload_end = usize::try_from(payload_size)
        .ok()
        .and_then(|p| start.checked_add(p))
        .map_or(bytes.len(), |end| end.min(bytes.len()));

    while cursor < payload_end {
        if entries.len() >= MAX_ENTRIES {
            truncated = true;
            break;
        }
        let Some((entry, next)) = parse_entry(&reader, cursor, payload_end) else {
            // Could not validate another entry header; stop rather than guess.
            break;
        };
        entries.push(entry);
        if next <= cursor {
            // Entries always advance by at least `header_len` (>= 8), so this
            // guard is unreachable; keep it so a future layout change cannot
            // spin the loop.
            break;
        }
        cursor = next;
    }

    Some(FatbinFacts {
        version,
        payload_size,
        entries,
        truncated,
    })
}

/// Parse one entry header at `offset`, returning the entry and the offset of
/// the next entry. Returns `None` if the header cannot be validated in bounds.
///
/// Entry header layout (little-endian). Field offsets follow the reference
/// `fat_text_header` from NVIDIA fatbin reverse-engineering (e.g.
/// n-eiling/cuda-fatbin-decompression); only the fields we consume are named:
///
/// ```text
/// kind:            u16  @0   // 1 = PTX, 2 = ELF/cubin
/// unknown1:        u16  @2
/// header_len:      u32  @4   // size of this entry header
/// payload_size:    u64  @8   // size of the payload following the header
/// compressed_size: u32  @16
/// unknown2:        u32  @20
/// version_minor:   u16  @24
/// version_major:   u16  @26
/// arch:            u32  @28  // SM architecture (compute capability)
/// obj_name_offset: u32  @32
/// obj_name_len:    u32  @36
/// flags:           u64  @40  // bit 1 (0x2) => compressed
/// ```
fn parse_entry(
    reader: &Reader<'_>,
    offset: usize,
    payload_end: usize,
) -> Option<(FatbinEntry, usize)> {
    let kind_code = reader.u16_le_at(offset)?;
    let header_len = usize::try_from(reader.u32_le_at(offset + 4)?).ok()?;
    let payload_size = usize::try_from(reader.u64_le_at(offset + 8)?).ok()?;

    // A header length that is implausibly small cannot be trusted.
    if header_len < 8 {
        return None;
    }

    // SM architecture (@28) and flags (@40) live deeper in the header. Read a
    // field only when it is fully inside this entry's declared header; a shorter
    // header means the field is absent (arch) or clear (flags), never bytes
    // borrowed from the next entry or the payload.
    let in_header = |field_offset: usize, size: usize| field_offset + size <= header_len;
    let sm_arch = if in_header(28, 4) {
        reader.u32_le_at(offset + 28).filter(|&v| v != 0)
    } else {
        None
    };
    let flags = if in_header(40, 8) {
        reader.u64_le_at(offset + 40).unwrap_or(0)
    } else {
        0
    };

    let payload_offset = offset.checked_add(header_len)?;
    // Bound the payload within the container.
    if payload_offset > payload_end {
        return None;
    }
    let payload_len = payload_size.min(payload_end.saturating_sub(payload_offset));

    let kind = match kind_code {
        KIND_PTX => EntryKind::Ptx,
        KIND_ELF => EntryKind::Cubin,
        other => EntryKind::Unknown(other),
    };

    let next = payload_offset.checked_add(payload_len)?;

    Some((
        FatbinEntry {
            kind,
            sm_arch,
            payload_offset,
            payload_len,
            compressed: flags & FLAG_COMPRESSED != 0,
        },
        next,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal fatbin: wrapper + one entry header + payload.
    ///
    /// Field offsets match the real `fat_text_header` layout: kind@0, len@4,
    /// payload_size@8, version_minor@24, version_major@26, arch@28, flags@40.
    fn build_fatbin(kind: u16, sm: u32, payload: &[u8]) -> Vec<u8> {
        build_fatbin_flags(kind, sm, 0, payload)
    }

    fn build_fatbin_flags(kind: u16, sm: u32, flags: u64, payload: &[u8]) -> Vec<u8> {
        let entry_header_len: u32 = 64;
        let mut entry = vec![0u8; entry_header_len as usize];
        entry[0..2].copy_from_slice(&kind.to_le_bytes()); // kind @0
        entry[4..8].copy_from_slice(&entry_header_len.to_le_bytes()); // header_len @4
        entry[8..16].copy_from_slice(&(payload.len() as u64).to_le_bytes()); // payload_size @8
        entry[28..32].copy_from_slice(&sm.to_le_bytes()); // arch @28
        entry[40..48].copy_from_slice(&flags.to_le_bytes()); // flags @40
        entry.extend_from_slice(payload);

        let mut out = Vec::new();
        out.extend_from_slice(&FATBIN_MAGIC.to_le_bytes()); // magic
        out.extend_from_slice(&1u16.to_le_bytes()); // version
        out.extend_from_slice(&u16::try_from(WRAPPER_LEN).unwrap().to_le_bytes()); // header_size
        out.extend_from_slice(&(entry.len() as u64).to_le_bytes()); // payload size
        out.extend_from_slice(&entry);
        out
    }

    #[test]
    fn detects_and_parses_single_cubin_entry() {
        let bytes = build_fatbin(KIND_ELF, 90, b"CUBINPAYLOAD");
        assert!(has_fatbin_magic(&bytes));
        let facts = parse(&bytes).expect("parse fatbin");
        assert_eq!(facts.version, 1);
        assert_eq!(facts.entries.len(), 1);
        let e = &facts.entries[0];
        assert_eq!(e.kind, EntryKind::Cubin);
        assert!(!e.compressed);
        assert_eq!(e.sm_arch, Some(90));
        assert_eq!(e.payload_len, "CUBINPAYLOAD".len());
        assert_eq!(
            &bytes[e.payload_offset..e.payload_offset + e.payload_len],
            b"CUBINPAYLOAD"
        );
    }

    #[test]
    fn compressed_flag_is_read_from_offset_40() {
        // Regression: flags live at @40, not @24. A fixture that set the
        // compressed bit at @40 must be detected as compressed.
        let bytes = build_fatbin_flags(KIND_ELF, 80, FLAG_COMPRESSED, b"PAYLOAD");
        let facts = parse(&bytes).expect("parse");
        assert!(facts.entries[0].compressed);
        assert_eq!(facts.entries[0].sm_arch, Some(80));
    }

    #[test]
    fn ptx_kind_is_classified() {
        let bytes = build_fatbin(KIND_PTX, 80, b".version 8.3");
        let facts = parse(&bytes).unwrap();
        assert_eq!(facts.entries[0].kind, EntryKind::Ptx);
    }

    #[test]
    fn magic_matches_documented_on_disk_byte_order() {
        // Regression: the fatbin wrapper magic is 0xBA55ED50, which on disk
        // (little-endian) is the byte sequence 50 ED 55 BA. A byte-reversed
        // constant would compile and pass symbolic fixtures but silently fail
        // to find every real embedded fatbin (e.g. in libtorch_cuda.so).
        assert_eq!(FATBIN_MAGIC, 0xBA55_ED50);
        assert_eq!(FATBIN_MAGIC.to_le_bytes(), [0x50, 0xED, 0x55, 0xBA]);
        assert!(has_fatbin_magic(&[0x50, 0xED, 0x55, 0xBA, 0, 0, 0, 0]));
    }

    #[test]
    fn non_fatbin_returns_none() {
        assert!(parse(b"not a fatbin").is_none());
        assert!(parse(&[]).is_none());
        assert!(!has_fatbin_magic(b"PK\x03\x04"));
    }

    #[test]
    fn truncated_wrapper_does_not_panic() {
        // Magic present but buffer ends before the full wrapper header.
        let mut bytes = FATBIN_MAGIC.to_le_bytes().to_vec();
        bytes.extend_from_slice(&[1, 0]); // partial
        assert!(parse(&bytes).is_none());
    }

    #[test]
    fn lying_payload_size_is_bounded_not_trusted() {
        // Declare a huge entry payload but provide few bytes: must clamp.
        let mut out = Vec::new();
        out.extend_from_slice(&FATBIN_MAGIC.to_le_bytes());
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&u16::try_from(WRAPPER_LEN).unwrap().to_le_bytes());
        out.extend_from_slice(&64u64.to_le_bytes()); // payload size (small)
                                                     // entry header claims a 1 GiB payload
        out.extend_from_slice(&KIND_ELF.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&16u32.to_le_bytes()); // header_len
        out.extend_from_slice(&(1u64 << 30).to_le_bytes()); // payload_size lie
        out.extend_from_slice(&0u64.to_le_bytes());
        out.extend_from_slice(&0u64.to_le_bytes()); // flags
                                                    // no actual payload bytes
        let facts = parse(&out).expect("parse");
        // The single entry's payload is clamped to what is actually present.
        let e = &facts.entries[0];
        assert!(e.payload_offset + e.payload_len <= out.len());
    }
}
