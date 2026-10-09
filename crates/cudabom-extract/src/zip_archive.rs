//! Safe ZIP (and Python wheel) extraction.
//!
//! Each member is validated and size-checked before and during decompression:
//!
//! - the entry name is sanitized (no traversal / absolute / drive paths);
//! - directory entries and non-file entries are skipped;
//! - the declared uncompressed size is checked against the per-file cap and the
//!   decompression ratio cap before reading;
//! - the bytes are read with a hard cap so a lying header cannot overrun;
//! - the entry count and aggregate byte budget are enforced across the archive.
//!
//! Members are expanded recursively (a wheel may contain a tarball) up to the
//! configured depth.

use std::io::Read;

use cudabom_core::{Budget, Error, Location, Result};

use crate::sanitize::{join_logical, read_capped, sanitize_entry_path};
use crate::walk::hex_sha256;
use crate::{expand_bytes, ScannedFile};

/// Expand a ZIP archive held in `bytes`.
pub(crate) fn expand_zip<F>(
    bytes: &[u8],
    parent: &Location,
    depth: u32,
    budget: &mut Budget,
    visit: &mut F,
) -> Result<()>
where
    F: FnMut(ScannedFile) -> Result<()>,
{
    let reader = std::io::Cursor::new(bytes);
    let mut archive =
        zip::ZipArchive::new(reader).map_err(|e| Error::malformed(format!("invalid zip: {e}")))?;

    let count = archive.len() as u64;
    budget.check_entry_count(count)?;

    for i in 0..archive.len() {
        let mut entry = archive
            .by_index(i)
            .map_err(|e| Error::malformed(format!("zip entry {i}: {e}")))?;

        // Skip directories and anything that is not a plain file (the zip crate
        // exposes directory entries via a trailing '/').
        if entry.is_dir() {
            continue;
        }

        // Sanitize the entry's mangled (safe) name when the raw name is not
        // valid UTF-8, else the raw name. Unsafe names are skipped, not fatal;
        // see `sanitize_entry_path`. Budget breaches below still abort.
        let raw_name = entry.name().to_string();
        let Ok(safe) = sanitize_entry_path(&raw_name) else {
            continue;
        };

        let declared = entry.size();
        let compressed = entry.compressed_size();

        // Reject bombs and oversize members before allocating/reading.
        budget.limits().check_member(declared, compressed)?;

        let cap = budget.limits().max_file_bytes;
        let buf = read_capped(entry.by_ref(), declared, cap, "zip", &safe)?;
        let read = buf.len() as u64;

        // Account the actually-produced bytes against the aggregate budget.
        budget.consume(read)?;

        let location = Location {
            path: join_logical(&parent.path, &safe),
            sha256: Some(hex_sha256(&buf)),
            layer_digest: parent.layer_digest.clone(),
        };

        expand_bytes(buf, location, depth + 1, false, budget, visit)?;
    }

    Ok(())
}
