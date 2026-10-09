//! Malicious-archive test suite.
//!
//! These tests construct hostile archives in memory and assert that cudabom's
//! extractor rejects or safely neutralizes each one. This is the acceptance bar
//! for safe extraction: decompression bombs, oversize members, deep nesting, and
//! too many entries must fail with a `LimitExceeded` error, and symlink/absolute/
//! traversal entries must never escape the virtual root. cudabom never writes
//! members to disk, so an unsafe *entry name* (absolute, `..`, drive) cannot
//! escape; such an entry is skipped (not surfaced) while its benign siblings are
//! still scanned, so one hostile name cannot blind the scanner to a whole tree.

use std::io::Write;

use cudabom_core::{Error, Limits};
use cudabom_extract::{scan_target, ScannedFile};

/// Run the extractor over a single in-memory blob written to a temp file,
/// collecting the logical paths visited. Uses the given limits.
fn scan_blob(bytes: &[u8], limits: &Limits) -> cudabom_core::Result<Vec<String>> {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("input.bin");
    std::fs::write(&path, bytes).unwrap();

    let mut paths = Vec::new();
    scan_target(&path, limits, |f: ScannedFile| {
        paths.push(f.location.path);
        Ok(())
    })?;
    Ok(paths)
}

/// Build a ZIP archive from (name, contents) pairs using stored (no)
/// compression so declared sizes are exact.
fn build_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut cursor = std::io::Cursor::new(Vec::new());
    {
        let mut zw = zip::ZipWriter::new(&mut cursor);
        let opts: zip::write::FileOptions<'_, ()> =
            zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored);
        for (name, data) in entries {
            zw.start_file(*name, opts).unwrap();
            zw.write_all(data).unwrap();
        }
        zw.finish().unwrap();
    }
    cursor.into_inner()
}

/// Build a ZIP with a single deflated entry whose uncompressed content is
/// `size` bytes of zeros (a high-ratio, small-on-disk bomb).
fn build_zip_bomb(name: &str, size: usize) -> Vec<u8> {
    let mut cursor = std::io::Cursor::new(Vec::new());
    {
        let mut zw = zip::ZipWriter::new(&mut cursor);
        let opts: zip::write::FileOptions<'_, ()> =
            zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        zw.start_file(name, opts).unwrap();
        zw.write_all(&vec![0u8; size]).unwrap();
        zw.finish().unwrap();
    }
    cursor.into_inner()
}

#[test]
fn zip_slip_traversal_entry_is_skipped_siblings_survive() {
    // Classic zip-slip: an entry that tries to climb out of the root. cudabom
    // never writes members to disk, so a traversal name cannot escape; the
    // unsafe entry is skipped (not surfaced) while benign siblings are still
    // scanned. One hostile name must not blind the scanner to the rest of a
    // real tree (e.g. a container image that ships such a test fixture).
    let zip = build_zip(&[
        ("../../etc/passwd", b"pwned"),
        ("pkg/real.so", b"\x7fELF-ish"),
    ]);
    let paths = scan_blob(&zip, &Limits::default()).unwrap();
    assert_eq!(
        paths,
        vec!["input.bin/pkg/real.so".to_string()],
        "traversal entry must be skipped, benign sibling surfaced"
    );
}

#[test]
fn zip_absolute_path_entry_is_skipped_siblings_survive() {
    let zip = build_zip(&[("/etc/cron.d/evil", b"x"), ("ok/lib.so", b"data")]);
    let paths = scan_blob(&zip, &Limits::default()).unwrap();
    assert_eq!(
        paths,
        vec!["input.bin/ok/lib.so".to_string()],
        "absolute-path entry must be skipped, benign sibling surfaced"
    );
}

#[test]
fn nested_malformed_archive_does_not_abort_sibling_scan() {
    // A directory containing (a) a truncated/garbage ".tar.gz" and (b) a real
    // file. The corrupt nested archive must be tolerated (yield nothing) while
    // the sibling is still scanned: one bad archive in a container/wheel tree
    // cannot blind the scanner to everything else.
    let dir = tempfile::tempdir().unwrap();
    // Gzip magic header followed by garbage: detected as gzip, fails to inflate.
    std::fs::write(
        dir.path().join("broken.tar.gz"),
        [0x1f, 0x8b, 0x08, 0x00, 0xff, 0xff],
    )
    .unwrap();
    std::fs::write(dir.path().join("real.so"), b"\x7fELF payload").unwrap();

    let mut paths = Vec::new();
    scan_target(dir.path(), &Limits::default(), |f: ScannedFile| {
        paths.push(f.location.path);
        Ok(())
    })
    .expect("a corrupt nested archive must not abort the directory scan");
    assert!(
        paths.iter().any(|p| p.ends_with("real.so")),
        "sibling real file should be scanned despite the broken archive; got {paths:?}"
    );
}

#[test]
fn nested_zip_with_unsafe_entry_scans_siblings() {
    // A directory holding a zip that mixes a hostile entry name with a benign
    // one. The hostile entry is skipped; the benign member is still surfaced,
    // and the scan completes without error.
    let dir = tempfile::tempdir().unwrap();
    let zip = build_zip(&[("../escape.so", b"nope"), ("inner/good.so", b"ok")]);
    std::fs::write(dir.path().join("bundle.zip"), &zip).unwrap();

    let mut paths = Vec::new();
    scan_target(dir.path(), &Limits::default(), |f: ScannedFile| {
        paths.push(f.location.path);
        Ok(())
    })
    .expect("unsafe nested entry must be skipped, not fatal");
    assert!(
        paths.iter().any(|p| p.ends_with("inner/good.so")),
        "benign member should be surfaced; got {paths:?}"
    );
    assert!(
        !paths.iter().any(|p| p.contains("escape")),
        "unsafe entry must not be surfaced; got {paths:?}"
    );
}

#[test]
fn benign_zip_is_extracted() {
    // A normal wheel-like zip yields its members with sanitized paths.
    let zip = build_zip(&[
        ("pkg/__init__.py", b"# hi"),
        ("pkg-1.0.dist-info/RECORD", b"records"),
    ]);
    let mut paths = scan_blob(&zip, &Limits::default()).unwrap();
    paths.sort();
    assert_eq!(
        paths,
        vec![
            "input.bin/pkg-1.0.dist-info/RECORD".to_string(),
            "input.bin/pkg/__init__.py".to_string(),
        ]
    );
}

#[test]
fn zip_member_over_per_file_cap_is_rejected() {
    // A 5 KiB member against a 1 KiB per-file cap must be rejected.
    let zip = build_zip(&[("big.bin", &vec![7u8; 5 * 1024])]);
    let limits = Limits {
        max_file_bytes: 1024,
        ..Limits::default()
    };
    let err = scan_blob(&zip, &limits).unwrap_err();
    assert!(matches!(err, Error::LimitExceeded(_)), "got {err:?}");
}

#[test]
fn zip_decompression_bomb_is_rejected() {
    // 1 MiB of zeros deflates to almost nothing: a very high ratio. With a low
    // ratio cap and a per-file cap above the payload, the ratio guard fires.
    let zip = build_zip_bomb("bomb", 1024 * 1024);
    let limits = Limits {
        max_file_bytes: 8 * 1024 * 1024,
        max_decompression_ratio: 10,
        ..Limits::default()
    };
    let err = scan_blob(&zip, &limits).unwrap_err();
    assert!(matches!(err, Error::LimitExceeded(_)), "got {err:?}");
}

#[test]
fn zip_aggregate_total_cap_is_rejected() {
    // Several members each within the per-file cap, but together over the
    // aggregate total budget.
    let zip = build_zip(&[
        ("a", &vec![1u8; 400]),
        ("b", &vec![2u8; 400]),
        ("c", &vec![3u8; 400]),
    ]);
    let limits = Limits {
        max_file_bytes: 1000,
        max_total_bytes: 1000, // 3 x 400 = 1200 > 1000
        ..Limits::default()
    };
    let err = scan_blob(&zip, &limits).unwrap_err();
    assert!(matches!(err, Error::LimitExceeded(_)), "got {err:?}");
}

#[test]
fn zip_too_many_entries_is_rejected() {
    let entries: Vec<(String, Vec<u8>)> =
        (0..50).map(|i| (format!("f{i}"), vec![0u8; 1])).collect();
    let refs: Vec<(&str, &[u8])> = entries
        .iter()
        .map(|(n, d)| (n.as_str(), d.as_slice()))
        .collect();
    let zip = build_zip(&refs);
    let limits = Limits {
        max_entries_per_archive: 10,
        ..Limits::default()
    };
    let err = scan_blob(&zip, &limits).unwrap_err();
    assert!(matches!(err, Error::LimitExceeded(_)), "got {err:?}");
}

#[test]
fn gzip_bomb_is_rejected() {
    // A gzip stream that inflates to 1 MiB, against a small per-file cap.
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(&vec![0u8; 1024 * 1024]).unwrap();
    let gz = encoder.finish().unwrap();

    let limits = Limits {
        max_file_bytes: 64 * 1024, // 64 KiB cap; inflated is 1 MiB
        ..Limits::default()
    };
    let err = scan_blob(&gz, &limits).unwrap_err();
    assert!(matches!(err, Error::LimitExceeded(_)), "got {err:?}");
}

#[test]
fn tar_symlink_entry_is_skipped_not_followed() {
    // A tar containing a symlink that points outside the root plus one regular
    // file. The symlink must be skipped (never surfaced, never followed); the
    // regular file is extracted normally.
    let mut builder = tar::Builder::new(Vec::new());

    let mut link_header = tar::Header::new_gnu();
    link_header.set_entry_type(tar::EntryType::Symlink);
    link_header.set_size(0);
    link_header.set_mode(0o777);
    link_header.set_link_name("../../../../etc/passwd").unwrap();
    builder
        .append_data(&mut link_header, "escape", std::io::empty())
        .unwrap();

    let content = b"real file";
    let mut file_header = tar::Header::new_gnu();
    file_header.set_size(content.len() as u64);
    file_header.set_mode(0o644);
    file_header.set_entry_type(tar::EntryType::Regular);
    builder
        .append_data(&mut file_header, "dir/real.txt", &content[..])
        .unwrap();

    let tar_bytes = builder.into_inner().unwrap();

    let paths = scan_blob(&tar_bytes, &Limits::default()).unwrap();
    // Only the regular file is surfaced; the symlink is neither followed nor
    // reported.
    assert_eq!(paths, vec!["input.bin/dir/real.txt".to_string()]);
}

#[test]
fn deeply_nested_zip_hits_depth_cap() {
    // Wrap a zip inside a zip inside a zip ... beyond the depth cap. Each layer
    // increments depth; the extractor must stop with LimitExceeded.
    let mut inner = build_zip(&[("leaf.txt", b"deep")]);
    for i in 0..8 {
        inner = build_zip(&[(&format!("layer{i}.zip"), &inner)]);
    }
    let limits = Limits {
        max_depth: 3,
        ..Limits::default()
    };
    let err = scan_blob(&inner, &limits).unwrap_err();
    assert!(matches!(err, Error::LimitExceeded(_)), "got {err:?}");
}

#[test]
fn nested_zip_within_depth_is_expanded() {
    // A zip containing a zip containing a file, well within the depth cap, is
    // fully expanded to the leaf.
    let inner = build_zip(&[("leaf.txt", b"hello")]);
    let outer = build_zip(&[("inner.zip", &inner)]);
    let paths = scan_blob(&outer, &Limits::default()).unwrap();
    assert_eq!(paths, vec!["input.bin/inner.zip/leaf.txt".to_string()]);
}
