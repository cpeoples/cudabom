//! Safe extraction and artifact walking for cudabom.
//!
//! Responsibility: turn a top-level target (wheel, sdist, directory, tarball,
//! or a single file) into a stream of per-file byte buffers plus their
//! [`cudabom_core::Location`], applying the tunable [`cudabom_core::Limits`] so
//! hostile inputs cannot exhaust the scanner.
//!
//! Safety rules enforced here (see `docs/threat-model.md`): no path traversal,
//! no symlink escape, no absolute-path writes, bounded nesting depth, bounded
//! total/per-file bytes, bounded decompression ratio, and bounded entry count.
//! Nothing is written to disk and nothing is executed; members are materialized
//! in memory, size-checked before and during decompression, and handed to a
//! visitor callback.

mod ar_archive;
mod detect;
mod sanitize;
mod tarball;
mod walk;
mod zip_archive;

use cudabom_core::{Budget, Limits, Location};

pub use detect::{detect_kind, FileKind};

/// A single file surfaced by extraction, with its bytes and provenance.
///
/// `bytes` holds the fully materialized, size-checked contents. `location`
/// records the path relative to the scanned target (using `/` separators, even
/// inside archives) so findings can point back into the artifact.
#[derive(Debug, Clone)]
pub struct ScannedFile {
    /// Where this file sits relative to the scan target.
    pub location: Location,
    /// Detected content kind (by magic bytes, not extension).
    pub kind: FileKind,
    /// The file's bytes.
    pub bytes: Vec<u8>,
}

impl ScannedFile {
    /// Convenience: the logical path of this file.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.location.path
    }
}

/// Recursively extract `target` and invoke `visit` for every leaf file found,
/// enforcing `limits` across the whole traversal.
///
/// `target` may be a directory or a single file (wheel, tarball, ELF, ...).
/// Archives are expanded in memory; nested archives are expanded up to the
/// configured depth. The visitor decides what to do with each file (parse it,
/// hash it, ignore it). Extraction stops and returns an error the moment a
/// safety limit is breached.
pub fn scan_target<F>(
    target: &std::path::Path,
    limits: &Limits,
    mut visit: F,
) -> cudabom_core::Result<()>
where
    F: FnMut(ScannedFile) -> cudabom_core::Result<()>,
{
    let mut budget = limits.budget();
    walk::walk_target(target, &mut budget, &mut visit)
}

/// Expand a single in-memory blob (already read from disk or an outer archive),
/// dispatching on its detected kind. Exposed for callers that already hold
/// bytes (e.g. a nested archive member) and for testing.
///
/// `tolerant_root` marks a blob that was discovered rather than named directly
/// (a file reached by walking a directory): a malformed archive among many is
/// then tolerated instead of aborting the walk. Nested members pass `false` and
/// rely on `depth > 0` for the same tolerance.
pub(crate) fn expand_bytes<F>(
    bytes: Vec<u8>,
    location: Location,
    depth: u32,
    tolerant_root: bool,
    budget: &mut Budget,
    visit: &mut F,
) -> cudabom_core::Result<()>
where
    F: FnMut(ScannedFile) -> cudabom_core::Result<()>,
{
    budget.check_depth(depth)?;
    let kind = detect::detect_kind(&bytes);
    // Nested archives (depth > 0) and directory-walked roots tolerate malformed
    // members; a directly-named bad target still fails loudly. See
    // `tolerate_malformed` for the full contract.
    let tolerate = tolerant_root || depth > 0;
    match kind {
        FileKind::Zip => tolerate_malformed(
            zip_archive::expand_zip(&bytes, &location, depth, budget, visit),
            tolerate,
        ),
        FileKind::Gzip => tolerate_malformed(
            tarball::expand_gzip(&bytes, &location, depth, budget, visit),
            tolerate,
        ),
        FileKind::Tar => tolerate_malformed(
            tarball::expand_tar(bytes, &location, depth, budget, visit),
            tolerate,
        ),
        FileKind::Ar => {
            // Expand the member objects (so a statically linked component is
            // identified from its members), then surface the `.a` itself, whose
            // whole-file hash can match a known static library in the DB. The
            // member expansion borrows the buffer so the file surfacing can take
            // it by value without cloning.
            let expanded = tolerate_malformed(
                ar_archive::expand_ar(&bytes, &location, depth, budget, visit),
                tolerate,
            );
            expanded?;
            visit(ScannedFile {
                location,
                kind,
                bytes,
            })
        }
        // A leaf (ELF, PTX, unknown, ...) is surfaced as-is for the visitor.
        _ => visit(ScannedFile {
            location,
            kind,
            bytes,
        }),
    }
}

/// Collapse a nested-archive expansion result so a malformed or unreadable
/// archive is tolerated (it simply yields no members) while a resource-limit
/// breach still aborts the whole scan.
///
/// `tolerate` is true for an archive encountered inside another artifact, or
/// one reached while walking a directory tree; such an archive yields nothing
/// instead of aborting the scan. A malformed archive named explicitly as the
/// sole scan target (`tolerate == false`) still surfaces its error so a
/// directly-named bad file is reported loudly. A decompression bomb, oversize
/// member, excessive nesting, or entry-count flood is a resource-exhaustion
/// attack and always aborts. The visitor's own errors (not extraction errors)
/// also propagate so a caller can abort deliberately.
fn tolerate_malformed(
    result: cudabom_core::Result<()>,
    tolerate: bool,
) -> cudabom_core::Result<()> {
    match result {
        Err(e @ cudabom_core::Error::LimitExceeded(_)) => Err(e),
        Err(cudabom_core::Error::Malformed(_)) if tolerate => Ok(()),
        other => other,
    }
}
