//! Safe `ar` (Unix archive / `.a` static library) member extraction.
//!
//! A `.a` static library is a flat `ar` archive whose members are relocatable
//! ELF objects (`.o`). NVIDIA ships CUDA components in both dynamic (`.so`) and
//! static (`.a`) form, e.g. `libcudart_static.a`, and a statically linked
//! application compiles those objects *in*. Surfacing the members lets cudabom
//! hash and fingerprint them, so statically linked CUDA is identified rather
//! than left as one opaque blob.
//!
//! Parsing uses the `object` crate's archive reader, which transparently skips
//! the symbol-table and extended-name pseudo-members (the `/` and `//` special
//! entries) and yields only real object members. Each member is size-checked
//! and accounted against the shared budget, exactly like a tar entry. Nothing
//! is written to disk or executed.

use cudabom_core::{Budget, Error, Location, Result};
use object::read::archive::ArchiveFile;

use crate::sanitize::{join_logical, sanitize_entry_path};
use crate::walk::hex_sha256;
use crate::{expand_bytes, ScannedFile};

/// Iterate an `ar` archive, surfacing each real member as a scannable file.
pub(crate) fn expand_ar<F>(
    bytes: &[u8],
    parent: &Location,
    depth: u32,
    budget: &mut Budget,
    visit: &mut F,
) -> Result<()>
where
    F: FnMut(ScannedFile) -> Result<()>,
{
    let archive = ArchiveFile::parse(bytes)
        .map_err(|e| Error::malformed(format!("invalid ar archive: {e}")))?;

    let mut seen: u64 = 0;
    for member in archive.members() {
        let member = member.map_err(|e| Error::malformed(format!("ar member error: {e}")))?;

        seen += 1;
        budget.check_entry_count(seen)?;

        // Member bytes are stored uncompressed inside the archive, so only the
        // per-file size cap applies (ratio check uses compressed == 0).
        let data = member
            .data(bytes)
            .map_err(|e| Error::malformed(format!("ar member data error: {e}")))?;
        let len = data.len() as u64;
        budget.limits().check_member(len, 0)?;
        budget.consume(len)?;

        // Member names come from the archive header. `ar` names are flat (no
        // path separators in well-formed inputs); an unsafe name is skipped,
        // matching the tarball and zip expanders rather than being renamed.
        let raw = String::from_utf8_lossy(member.name()).into_owned();
        let Ok(safe) = sanitize_entry_path(&raw) else {
            continue;
        };

        let buf = data.to_vec();
        let location = Location {
            path: join_logical(&parent.path, &safe),
            sha256: Some(hex_sha256(&buf)),
            layer_digest: parent.layer_digest.clone(),
        };

        expand_bytes(buf, location, depth + 1, false, budget, visit)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cudabom_core::Limits;

    /// Build a minimal GNU `ar` archive from `(name, data)` members. The format
    /// (System V / GNU) is: the global header `!<arch>\n`, then per member a
    /// 60-byte header (16-byte name field terminated by `/`, then
    /// date/uid/gid/mode/size fields and the `` `\n `` terminator), the data,
    /// and a `\n` pad byte when the data length is odd.
    fn build_ar(members: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = b"!<arch>\n".to_vec();
        for (name, data) in members {
            let name_field = format!("{name}/");
            let header = format!(
                "{:<16}{:<12}{:<6}{:<6}{:<8}{:<10}`\n",
                name_field,
                "0",      // date
                "0",      // uid
                "0",      // gid
                "100644", // mode
                data.len()
            );
            out.extend_from_slice(header.as_bytes());
            out.extend_from_slice(data);
            if data.len() % 2 == 1 {
                out.push(b'\n'); // 2-byte alignment
            }
        }
        out
    }

    fn parent() -> Location {
        Location {
            path: "lib.a".to_string(),
            sha256: None,
            layer_digest: None,
        }
    }

    #[test]
    fn surfaces_each_member_with_parent_prefixed_path() {
        let a = build_ar(&[("foo.o", b"FOODATA"), ("bar.o", b"BARDATA!!")]);
        let mut budget = Limits::default().budget();
        let mut seen = Vec::new();
        expand_ar(&a, &parent(), 0, &mut budget, &mut |f: ScannedFile| {
            seen.push((f.location.path, f.bytes));
            Ok(())
        })
        .unwrap();
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[0].0, "lib.a/foo.o");
        assert_eq!(seen[0].1, b"FOODATA");
        assert_eq!(seen[1].0, "lib.a/bar.o");
        assert_eq!(seen[1].1, b"BARDATA!!");
    }

    #[test]
    fn member_sha256_is_recorded() {
        let a = build_ar(&[("m.o", b"abc")]);
        let mut budget = Limits::default().budget();
        let mut seen_sha = None;
        expand_ar(&a, &parent(), 0, &mut budget, &mut |f: ScannedFile| {
            seen_sha = f.location.sha256.clone();
            Ok(())
        })
        .unwrap();
        // sha256("abc")
        assert_eq!(
            seen_sha.as_deref(),
            Some("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );
    }

    #[test]
    fn malformed_archive_is_an_error_not_a_panic() {
        // Starts like an ar archive but the member header is garbage.
        let bytes = b"!<arch>\nnot a valid member header at all".to_vec();
        let mut budget = Limits::default().budget();
        let res = expand_ar(&bytes, &parent(), 0, &mut budget, &mut |_| Ok(()));
        assert!(res.is_err());
    }

    #[test]
    fn oversized_member_is_rejected() {
        let big = vec![0u8; 64];
        let a = build_ar(&[("big.o", &big)]);
        let limits = Limits {
            max_file_bytes: 16, // smaller than the member
            ..Default::default()
        };
        let mut budget = limits.budget();
        let res = expand_ar(&a, &parent(), 0, &mut budget, &mut |_| Ok(()));
        assert!(matches!(res, Err(cudabom_core::Error::LimitExceeded(_))));
    }
}
