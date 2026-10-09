//! A minimal, panic-free little-endian byte reader.
//!
//! Every accessor returns `None` when the requested range is out of bounds, so
//! parsers over untrusted binaries can use `?` and never index out of range.

/// A read-only view over a byte slice with bounds-checked little-endian reads.
pub(crate) struct Reader<'a> {
    bytes: &'a [u8],
}

impl<'a> Reader<'a> {
    #[must_use]
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    /// Read a `u16` (little-endian) at `offset`, or `None` if out of bounds.
    #[must_use]
    pub(crate) fn u16_le_at(&self, offset: usize) -> Option<u16> {
        let end = offset.checked_add(2)?;
        let slice = self.bytes.get(offset..end)?;
        Some(u16::from_le_bytes([slice[0], slice[1]]))
    }

    /// Read a `u32` (little-endian) at `offset`, or `None` if out of bounds.
    #[must_use]
    pub(crate) fn u32_le_at(&self, offset: usize) -> Option<u32> {
        let end = offset.checked_add(4)?;
        let slice = self.bytes.get(offset..end)?;
        Some(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
    }

    /// Read a `u64` (little-endian) at `offset`, or `None` if out of bounds.
    #[must_use]
    pub(crate) fn u64_le_at(&self, offset: usize) -> Option<u64> {
        let end = offset.checked_add(8)?;
        let slice = self.bytes.get(offset..end)?;
        let mut buf = [0u8; 8];
        buf.copy_from_slice(slice);
        Some(u64::from_le_bytes(buf))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_within_bounds() {
        let data = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let r = Reader::new(&data);
        assert_eq!(r.u16_le_at(0), Some(0x0201));
        assert_eq!(r.u32_le_at(0), Some(0x0403_0201));
        assert_eq!(r.u64_le_at(0), Some(0x0807_0605_0403_0201));
    }

    #[test]
    fn out_of_bounds_returns_none() {
        let data = [0x01, 0x02];
        let r = Reader::new(&data);
        assert_eq!(r.u32_le_at(0), None);
        assert_eq!(r.u16_le_at(1), None); // would read byte 2 (absent)
        assert_eq!(r.u64_le_at(0), None);
    }

    #[test]
    fn offset_overflow_returns_none() {
        let data = [0u8; 8];
        let r = Reader::new(&data);
        assert_eq!(r.u32_le_at(usize::MAX), None);
    }
}
