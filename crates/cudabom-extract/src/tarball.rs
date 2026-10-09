//! Safe gzip and tar extraction.
//!
//! gzip: the compressed stream is inflated with a hard output ceiling so a
//! small `.gz` cannot expand into an unbounded buffer (a decompression bomb).
//! The inflated bytes are then re-dispatched by kind (a `.tar.gz` becomes a
//! tar).
//!
//! tar: only regular-file entries are extracted. Symlinks, hardlinks, char/
//! block devices, FIFOs, and directories are skipped, so a tar cannot create a
//! link that escapes the virtual root, and entry names are sanitized. Each
//! member is size-checked and accounted against the shared budget.

use std::io::Read;

use cudabom_core::{Budget, Error, Location, Result};
use flate2::read::GzDecoder;

use crate::sanitize::{join_logical, read_capped, sanitize_entry_path};
use crate::walk::hex_sha256;
use crate::{expand_bytes, ScannedFile};

/// Inflate a gzip stream with a bounded output size, then re-dispatch.
pub(crate) fn expand_gzip<F>(
    bytes: &[u8],
    parent: &Location,
    depth: u32,
    budget: &mut Budget,
    visit: &mut F,
) -> Result<()>
where
    F: FnMut(ScannedFile) -> Result<()>,
{
    let cap = budget.limits().max_file_bytes;
    let mut decoder = GzDecoder::new(bytes);

    // Inflate with a ceiling of cap + 1: if we can read more than cap, the
    // stream is over the per-file limit and is rejected rather than buffered.
    let mut out = Vec::new();
    let read = decoder
        .by_ref()
        .take(cap.saturating_add(1))
        .read_to_end(&mut out)
        .map_err(|e| Error::malformed(format!("gzip inflate error: {e}")))? as u64;

    if read > cap {
        return Err(Error::LimitExceeded(format!(
            "gzip stream {:?} exceeds per-file cap {cap} when inflated",
            parent.path
        )));
    }

    // Ratio guard: compare inflated output against the compressed input.
    budget.limits().check_member(read, bytes.len() as u64)?;
    budget.consume(read)?;

    // The inflated payload keeps the parent's logical path (gzip wraps exactly
    // one stream). Its kind (often tar) is detected in expand_bytes.
    expand_bytes(out, parent.clone(), depth + 1, false, budget, visit)
}

/// Iterate a (decompressed) tar archive, surfacing only regular files.
pub(crate) fn expand_tar<F>(
    bytes: Vec<u8>,
    parent: &Location,
    depth: u32,
    budget: &mut Budget,
    visit: &mut F,
) -> Result<()>
where
    F: FnMut(ScannedFile) -> Result<()>,
{
    let mut archive = tar::Archive::new(std::io::Cursor::new(bytes));
    let entries = archive
        .entries()
        .map_err(|e| Error::malformed(format!("invalid tar: {e}")))?;

    let mut seen: u64 = 0;
    for entry in entries {
        let mut entry = entry.map_err(|e| Error::malformed(format!("tar entry error: {e}")))?;

        seen += 1;
        budget.check_entry_count(seen)?;

        // Only regular files. Everything else (symlink, hardlink, dir, device,
        // fifo) is skipped: this is what prevents link-based escapes.
        if entry.header().entry_type() != tar::EntryType::Regular {
            continue;
        }

        let raw = entry
            .path()
            .map_err(|e| Error::malformed(format!("tar entry path error: {e}")))?
            .to_string_lossy()
            .into_owned();
        // Unsafe entry names (traversal, absolute, Windows drive) are skipped,
        // not fatal; see `sanitize_entry_path`. Budget breaches below still
        // abort, since those are resource-exhaustion.
        let Ok(safe) = sanitize_entry_path(&raw) else {
            continue;
        };

        let declared = entry
            .header()
            .size()
            .map_err(|e| Error::malformed(format!("tar entry {safe:?} size error: {e}")))?;

        // tar members are stored uncompressed inside the archive, so the ratio
        // check does not apply; only the per-file size cap does.
        budget.limits().check_member(declared, 0)?;

        let cap = budget.limits().max_file_bytes;
        let buf = read_capped(entry.by_ref(), declared, cap, "tar", &safe)?;
        budget.consume(buf.len() as u64)?;

        let location = Location {
            path: join_logical(&parent.path, &safe),
            sha256: Some(hex_sha256(&buf)),
            layer_digest: parent.layer_digest.clone(),
        };

        expand_bytes(buf, location, depth + 1, false, budget, visit)?;
    }

    Ok(())
}
