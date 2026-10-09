//! GPU code inventory for cudabom (fatbins, cubins, PTX).
//!
//! Responsibility: locate embedded GPU code in ELF files and parse standalone
//! GPU code objects. Report entry kind (PTX vs. cubin), SM architecture,
//! compression, and payload extents. These facts feed `FatbinProducer` evidence
//! in `cudabom-identify`.
//!
//! File-format behavior is validated against constructed fixtures and observed
//! bytes, not assumed. Every offset is bounds-checked (see the `read::Reader`
//! type), entry counts are capped, and the parser is panic-free on hostile
//! input.

mod capability;
mod facts;
mod ptx;
mod read;
mod wrapper;

pub use capability::{Builder as CapabilityBuilder, CapabilityManifest};
pub use facts::{EntryKind, FatbinEntry, FatbinFacts, GpuCode, PtxFacts};
pub use wrapper::{has_fatbin_magic, FATBIN_MAGIC};

/// Inspect a standalone buffer for GPU code and return its facts.
///
/// Recognizes a fatbin container (by the wrapper magic) or a PTX module (by its
/// `.version` directive). Returns `None` if the buffer is neither.
#[must_use]
pub fn inspect(bytes: &[u8]) -> Option<GpuCode> {
    if let Some(fat) = wrapper::parse(bytes) {
        return Some(GpuCode::Fatbin(fat));
    }
    if let Some(p) = ptx::parse(bytes) {
        return Some(GpuCode::Ptx(p));
    }
    None
}

/// Find every fatbin container embedded in a larger buffer (e.g. an ELF's
/// `.nv_fatbin` section, or the whole ELF), returning the byte offset and facts
/// for each. Uses a fast scan for the wrapper magic, then validates each
/// candidate by fully parsing it; false-positive magics that do not parse are
/// skipped.
///
/// `max_hits` bounds the number of containers reported so a buffer full of
/// magic-like bytes cannot cause unbounded work.
#[must_use]
pub fn find_embedded_fatbins(bytes: &[u8], max_hits: usize) -> Vec<(usize, FatbinFacts)> {
    // The magic on disk (little-endian) is BA 55 ED 50.
    let needle = FATBIN_MAGIC.to_le_bytes();
    let mut hits = Vec::new();
    let finder = memchr::memmem::Finder::new(&needle);
    for pos in finder.find_iter(bytes) {
        if hits.len() >= max_hits {
            break;
        }
        if let Some(facts) = wrapper::parse(&bytes[pos..]) {
            hits.push((pos, facts));
        }
    }
    hits
}

/// Parse PTX facts from a buffer, if it is PTX. Re-exported for callers that
/// already know the buffer is PTX text (e.g. a fatbin PTX entry).
#[must_use]
pub fn parse_ptx(bytes: &[u8]) -> Option<PtxFacts> {
    ptx::parse(bytes)
}

/// True if the buffer looks like PTX text.
#[must_use]
pub fn looks_like_ptx(bytes: &[u8]) -> bool {
    ptx::looks_like_ptx(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inspect_recognizes_ptx() {
        let ptx = b".version 8.3\n.target sm_90\n.address_size 64\n";
        match inspect(ptx) {
            Some(GpuCode::Ptx(facts)) => {
                assert_eq!(facts.targets, vec![90]);
            }
            other => panic!("expected PTX, got {other:?}"),
        }
    }

    #[test]
    fn inspect_rejects_unrelated_bytes() {
        assert!(inspect(b"\x7fELF....").is_none());
        assert!(inspect(b"hello world").is_none());
    }

    #[test]
    fn finds_embedded_fatbin_at_offset() {
        // Prefix some bytes, then a valid minimal fatbin.
        let mut buf = vec![0xAA; 32];
        let fat = build_minimal_fatbin();
        let at = buf.len();
        buf.extend_from_slice(&fat);

        let hits = find_embedded_fatbins(&buf, 16);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].0, at);
        assert_eq!(hits[0].1.entries.len(), 1);
    }

    /// A minimal fatbin with one cubin entry, mirroring the wrapper test.
    fn build_minimal_fatbin() -> Vec<u8> {
        let payload = b"cubin-bytes";
        let entry_header_len: u32 = 64;
        let mut entry = Vec::new();
        entry.extend_from_slice(&0x0002u16.to_le_bytes()); // kind = ELF/cubin
        entry.extend_from_slice(&0u16.to_le_bytes());
        entry.extend_from_slice(&entry_header_len.to_le_bytes());
        entry.extend_from_slice(&(payload.len() as u64).to_le_bytes());
        entry.extend_from_slice(&0u64.to_le_bytes());
        entry.extend_from_slice(&0u64.to_le_bytes());
        while entry.len() < entry_header_len as usize {
            entry.push(0);
        }
        entry.extend_from_slice(payload);

        let mut out = Vec::new();
        out.extend_from_slice(&FATBIN_MAGIC.to_le_bytes());
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&16u16.to_le_bytes());
        out.extend_from_slice(&(entry.len() as u64).to_le_bytes());
        out.extend_from_slice(&entry);
        out
    }
}
