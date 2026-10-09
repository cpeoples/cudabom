//! Content-kind detection by magic bytes.
//!
//! Filenames lie, so cudabom decides what a file is from its leading bytes
//! using documented format signatures. Each signature below is the format's
//! own defined magic number, not a guess:
//!
//! - ELF: bytes `0x7F 'E' 'L' 'F'` (ELF specification, `e_ident[EI_MAG0..3]`).
//! - ZIP: local file header `PK\x03\x04`, or empty-archive `PK\x05\x06`, or
//!   spanned `PK\x07\x08` (PKWARE APPNOTE, section 4.3). Wheels are ZIPs.
//! - gzip: `0x1F 0x8B` (RFC 1952, section 2.3.1, ID1/ID2).
//! - POSIX tar (ustar): the string `ustar` at byte offset 257 (POSIX.1-1988
//!   `ustar` magic in the header's `magic` field).
//! - Unix ar archive (`.a` static libraries): `!<arch>\n` (System V / BSD ar).
//!
//! Anything unmatched is [`FileKind::Unknown`] and treated as an opaque leaf.

use serde::Serialize;

/// The content kinds cudabom's extractor distinguishes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum FileKind {
    /// ELF object, shared library, or executable.
    Elf,
    /// PE/COFF image (Windows `.dll`/`.exe`).
    Pe,
    /// ZIP archive (also covers Python wheels).
    Zip,
    /// gzip stream (often a gzipped tar).
    Gzip,
    /// POSIX tar archive (ustar).
    Tar,
    /// Unix `ar` archive (static library, `.a`).
    Ar,
    /// Unrecognized; treated as an opaque leaf file.
    Unknown,
}

impl FileKind {
    /// The canonical lowercase token (matches the serde representation), so
    /// human and serialized surfaces print the same spelling.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            FileKind::Elf => "elf",
            FileKind::Pe => "pe",
            FileKind::Zip => "zip",
            FileKind::Gzip => "gzip",
            FileKind::Tar => "tar",
            FileKind::Ar => "ar",
            FileKind::Unknown => "unknown",
        }
    }
}

/// ELF magic: `0x7F` followed by "ELF" (ELF spec, `e_ident`).
const ELF_MAGIC: &[u8] = &[0x7F, b'E', b'L', b'F'];

/// DOS header magic that opens every PE image (`MZ`).
const DOS_MAGIC: &[u8] = b"MZ";
/// Offset of the 4-byte `e_lfanew` field (pointer to the PE header) in the DOS
/// header (PE/COFF specification).
const DOS_LFANEW_OFFSET: usize = 0x3C;
/// The PE signature at `e_lfanew`: "PE\0\0".
const PE_SIGNATURE: &[u8] = &[b'P', b'E', 0, 0];

/// Is `bytes` a PE image? Checks the `MZ` DOS magic, reads `e_lfanew`, and
/// verifies the `PE\0\0` signature there (PE/COFF spec). Bounds-checked so a
/// truncated or hostile file is simply "not PE", never a panic.
fn is_pe(bytes: &[u8]) -> bool {
    if !bytes.starts_with(DOS_MAGIC) {
        return false;
    }
    let Some(lfanew_bytes) = bytes.get(DOS_LFANEW_OFFSET..DOS_LFANEW_OFFSET + 4) else {
        return false;
    };
    let lfanew = u32::from_le_bytes([
        lfanew_bytes[0],
        lfanew_bytes[1],
        lfanew_bytes[2],
        lfanew_bytes[3],
    ]) as usize;
    bytes
        .get(lfanew..lfanew + PE_SIGNATURE.len())
        .is_some_and(|sig| sig == PE_SIGNATURE)
}

/// gzip magic ID1/ID2 (RFC 1952).
const GZIP_MAGIC: &[u8] = &[0x1F, 0x8B];

/// Unix `ar` global header (static libraries).
const AR_MAGIC: &[u8] = b"!<arch>\n";

/// ZIP signatures (PKWARE APPNOTE 4.3.6/4.3.16): local file header, end of
/// central directory (empty archive), and spanned-archive marker.
const ZIP_LOCAL_FILE: &[u8] = &[b'P', b'K', 0x03, 0x04];
const ZIP_EMPTY_EOCD: &[u8] = &[b'P', b'K', 0x05, 0x06];
const ZIP_SPANNED: &[u8] = &[b'P', b'K', 0x07, 0x08];

/// Offset and value of the ustar magic within a POSIX tar header block.
const TAR_USTAR_OFFSET: usize = 257;
const TAR_USTAR_MAGIC: &[u8] = b"ustar";

/// Detect the [`FileKind`] of `bytes` from its leading bytes.
#[must_use]
pub fn detect_kind(bytes: &[u8]) -> FileKind {
    if bytes.starts_with(ELF_MAGIC) {
        return FileKind::Elf;
    }
    if is_pe(bytes) {
        return FileKind::Pe;
    }
    if bytes.starts_with(ZIP_LOCAL_FILE)
        || bytes.starts_with(ZIP_EMPTY_EOCD)
        || bytes.starts_with(ZIP_SPANNED)
    {
        return FileKind::Zip;
    }
    if bytes.starts_with(GZIP_MAGIC) {
        return FileKind::Gzip;
    }
    if bytes.starts_with(AR_MAGIC) {
        return FileKind::Ar;
    }
    // tar has no leading magic; the ustar signature sits at offset 257. Only
    // check when the buffer is at least one 512-byte header block, so a short
    // file that happens to contain "ustar" is not misclassified.
    if bytes.len() >= 512
        && bytes
            .get(TAR_USTAR_OFFSET..TAR_USTAR_OFFSET + TAR_USTAR_MAGIC.len())
            .is_some_and(|slice| slice == TAR_USTAR_MAGIC)
    {
        return FileKind::Tar;
    }
    FileKind::Unknown
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_elf() {
        assert_eq!(
            detect_kind(&[0x7F, b'E', b'L', b'F', 2, 1, 1]),
            FileKind::Elf
        );
    }

    #[test]
    fn detects_pe_via_dos_and_pe_signature() {
        // MZ ... e_lfanew=0x40 ... "PE\0\0" at 0x40.
        let mut bytes = vec![0u8; 0x48];
        bytes[0] = b'M';
        bytes[1] = b'Z';
        bytes[0x3C..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        bytes[0x40..0x44].copy_from_slice(b"PE\0\0");
        assert_eq!(detect_kind(&bytes), FileKind::Pe);
    }

    #[test]
    fn mz_without_pe_signature_is_not_pe() {
        // DOS stub with MZ but no PE signature at e_lfanew: not classified PE.
        let mut bytes = vec![0u8; 0x48];
        bytes[0] = b'M';
        bytes[1] = b'Z';
        bytes[0x3C..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        // leave 0x40.. as zeros (no "PE\0\0")
        assert_eq!(detect_kind(&bytes), FileKind::Unknown);
    }

    #[test]
    fn pe_with_out_of_bounds_lfanew_is_not_pe() {
        // Hostile e_lfanew pointing past EOF must not panic or match.
        let mut bytes = vec![0u8; 0x40];
        bytes[0] = b'M';
        bytes[1] = b'Z';
        bytes[0x3C..0x40].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        assert_eq!(detect_kind(&bytes), FileKind::Unknown);
    }

    #[test]
    fn detects_zip_variants() {
        assert_eq!(detect_kind(b"PK\x03\x04rest"), FileKind::Zip);
        assert_eq!(detect_kind(b"PK\x05\x06"), FileKind::Zip);
        assert_eq!(detect_kind(b"PK\x07\x08"), FileKind::Zip);
    }

    #[test]
    fn detects_gzip() {
        assert_eq!(detect_kind(&[0x1F, 0x8B, 0x08]), FileKind::Gzip);
    }

    #[test]
    fn detects_ar() {
        assert_eq!(detect_kind(b"!<arch>\nmore"), FileKind::Ar);
    }

    #[test]
    fn detects_ustar_tar_at_offset_257() {
        let mut block = vec![0u8; 512];
        block[TAR_USTAR_OFFSET..TAR_USTAR_OFFSET + 5].copy_from_slice(b"ustar");
        assert_eq!(detect_kind(&block), FileKind::Tar);
    }

    #[test]
    fn short_buffer_with_ustar_word_is_not_tar() {
        // "ustar" appearing in a sub-512-byte buffer must not be called tar.
        let bytes = b"this mentions ustar but is tiny";
        assert_eq!(detect_kind(bytes), FileKind::Unknown);
    }

    #[test]
    fn empty_and_unknown() {
        assert_eq!(detect_kind(&[]), FileKind::Unknown);
        assert_eq!(detect_kind(b"random text"), FileKind::Unknown);
    }
}
