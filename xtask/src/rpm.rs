//! Shared parsing of YUM/DNF `repodata` for the NVIDIA RPM distros in the
//! `compute/cuda/repos/<distro>/<arch>/` channel.
//!
//! An RPM repo publishes `repodata/repomd.xml`, which points at a gzipped
//! `primary.xml` listing every package with its `<name>`, `<version>`,
//! `<location href>`, `<checksum type="sha256">`, and `rpm:provides`. This
//! module resolves that chain and extracts the runtime CUDA library packages
//! in the same [`crate::apt::DebPackage`] shape the manifest synthesizer
//! already consumes, so APT and RPM feed one pipeline. Only first-party fields
//! are read; nothing is inferred.
//!
//! The `primary.xml` format is simple and regular, so it is scanned directly
//! (like the APT stanza parser) rather than pulling in an XML-parser
//! dependency, keeping xtask's footprint minimal.

use std::io::Read;

use anyhow::{Context, Result};
use cudabom_identify::resolve_component;
use flate2::read::GzDecoder;

use crate::apt::{manifest_key_for, DebPackage};

/// Find the `primary.xml[.gz]` location in a `repomd.xml` body.
///
/// `repomd.xml` lists several metadata files; the one we want is
/// `<data type="primary"><location href="repodata/<hash>-primary.xml.gz"/>`.
pub(crate) fn primary_href(repomd_xml: &str) -> Option<String> {
    // Narrow to the <data type="primary"> ... </data> block, then read its
    // <location href="...">. Scoping to the block avoids matching primary_db.
    let start = repomd_xml.find("<data type=\"primary\">")?;
    let rest = &repomd_xml[start..];
    let end = rest
        .find("</data>")
        .map_or(rest.len(), |e| e + "</data>".len());
    let block = &rest[..end];
    let loc = block.find("<location href=\"")? + "<location href=\"".len();
    let after = &block[loc..];
    let close = after.find('"')?;
    Some(after[..close].to_string())
}

/// Decompress a gzipped `primary.xml` payload into a string.
pub(crate) fn gunzip_to_string(bytes: &[u8]) -> Result<String> {
    let mut out = String::new();
    GzDecoder::new(bytes)
        .read_to_string(&mut out)
        .context("decompressing primary.xml.gz")?;
    Ok(out)
}

/// Parse the runtime CUDA library packages out of a `primary.xml` body.
///
/// A `<package type="rpm">` is kept when it is a runtime CUDA library: it
/// publishes an `rpm:provides` entry for a versioned `.so`, its source stem
/// resolves to a known component profile, and it is not a `-devel` package.
/// Fields are read straight from the XML; nothing is inferred.
pub(crate) fn parse_cuda_library_packages(primary_xml: &str) -> Vec<DebPackage> {
    let mut out = Vec::new();
    let mut cursor = 0;
    while let Some(rel) = primary_xml[cursor..].find("<package type=\"rpm\">") {
        let start = cursor + rel;
        let block_rest = &primary_xml[start..];
        let end = block_rest
            .find("</package>")
            .map_or(block_rest.len(), |e| e + "</package>".len());
        let block = &block_rest[..end];
        cursor = start + end;

        if let Some(pkg) = parse_one(block) {
            out.push(pkg);
        }
    }
    out.sort_by(|a, b| a.source.cmp(&b.source));
    out.dedup_by(|a, b| a.source == b.source);
    out
}

/// Parse one `<package type="rpm">...</package>` block, returning the package
/// when it is an attributable runtime CUDA library.
fn parse_one(block: &str) -> Option<DebPackage> {
    let name = xml_text(block, "<name>", "</name>")?;
    // `-devel` packages ship headers and symlinks, no runtime library.
    if name.contains("-devel-") || name.ends_with("-devel") {
        return None;
    }
    // A runtime library publishes a versioned `.so` in rpm:provides.
    if !block.contains(".so") {
        return None;
    }
    let source = source_stem(&name);
    resolve_component(&manifest_key_for(&source))?;

    let ver = attr(block, "<version ", "ver")?;
    let filename = attr(block, "<location ", "href")?;
    let sha256 = sha256_checksum(block)?;
    let size = attr(block, "<size ", "package").and_then(|s| s.parse::<u64>().ok());

    Some(DebPackage {
        source,
        version: ver,
        filename,
        sha256: sha256.to_ascii_lowercase(),
        size,
    })
}

/// Strip the trailing `-<major>-<minor>` CUDA toolkit segment from an RPM
/// package name to recover its source stem (`cuda-cudart-11-7` ->
/// `cuda-cudart`, `libcublas-13-4` -> `libcublas`). Names without that segment
/// are returned unchanged.
fn source_stem(name: &str) -> String {
    let parts: Vec<&str> = name.rsplitn(3, '-').collect();
    // parts = [minor, major, head] when the suffix is `-<major>-<minor>`.
    if parts.len() == 3
        && parts[0].chars().all(|c| c.is_ascii_digit())
        && parts[1].chars().all(|c| c.is_ascii_digit())
    {
        parts[2].to_string()
    } else {
        name.to_string()
    }
}

/// Read `<tag>text</tag>` text content.
fn xml_text(block: &str, open: &str, close: &str) -> Option<String> {
    let start = block.find(open)? + open.len();
    let after = &block[start..];
    let end = after.find(close)?;
    Some(after[..end].trim().to_string())
}

/// Read an attribute value from a self-closing tag that starts with `open`
/// (e.g. `<version ` + `ver` -> the `ver="..."` value in that tag).
fn attr(block: &str, open: &str, key: &str) -> Option<String> {
    let start = block.find(open)?;
    let after = &block[start..];
    let tag_end = after.find('>')?;
    let tag = &after[..tag_end];
    let kstart = tag.find(&format!("{key}=\""))? + key.len() + 2;
    let kafter = &tag[kstart..];
    let kend = kafter.find('"')?;
    Some(kafter[..kend].to_string())
}

/// Read the `<checksum type="sha256" ...>HASH</checksum>` value.
fn sha256_checksum(block: &str) -> Option<String> {
    let marker = "<checksum type=\"sha256\"";
    let start = block.find(marker)?;
    let after = &block[start..];
    let gt = after.find('>')? + 1;
    let rest = &after[gt..];
    let end = rest.find('<')?;
    Some(rest[..end].trim().to_string())
}

/// Build the `repodata/repomd.xml` URL for a distro/arch base.
pub(crate) fn repomd_url(base: &str) -> String {
    format!("{}/repodata/repomd.xml", base.trim_end_matches('/'))
}

#[cfg(test)]
mod tests {
    use super::*;

    const REPOMD: &str = r#"<?xml version="1.0"?>
<repomd>
  <data type="primary">
    <checksum type="sha256">abc</checksum>
    <location href="repodata/deadbeef-primary.xml.gz"/>
  </data>
  <data type="primary_db">
    <location href="repodata/other-primary.sqlite.bz2"/>
  </data>
</repomd>"#;

    const PRIMARY: &str = r#"<metadata>
<package type="rpm">
  <name>libcublas-13-4</name>
  <arch>x86_64</arch>
  <version epoch="0" ver="13.7.0.27" rel="1"/>
  <checksum type="sha256" pkgid="YES">ABCDEF1234</checksum>
  <size package="410241818" installed="1" archive="1"/>
  <location href="libcublas-13-4-13.7.0.27-1.x86_64.rpm"/>
  <format>
    <rpm:sourcerpm>libcublas-13-4-13.7.0.27-1.src.rpm</rpm:sourcerpm>
    <rpm:provides>
      <rpm:entry name="libcublas.so.13()(64bit)"/>
    </rpm:provides>
  </format>
</package>
<package type="rpm">
  <name>libcublas-devel-13-4</name>
  <version epoch="0" ver="13.7.0.27" rel="1"/>
  <checksum type="sha256">999</checksum>
  <location href="libcublas-devel-13-4-13.7.0.27-1.x86_64.rpm"/>
  <format><rpm:provides><rpm:entry name="libcublas.so"/></rpm:provides></format>
</package>
<package type="rpm">
  <name>nsight-compute-2024.1</name>
  <version epoch="0" ver="2024.1" rel="1"/>
  <checksum type="sha256">777</checksum>
  <location href="nsight-compute-2024.1.x86_64.rpm"/>
  <format></format>
</package>
</metadata>"#;

    #[test]
    fn finds_primary_href() {
        assert_eq!(
            primary_href(REPOMD).as_deref(),
            Some("repodata/deadbeef-primary.xml.gz")
        );
    }

    #[test]
    fn source_stem_strips_toolkit_segment() {
        assert_eq!(source_stem("cuda-cudart-11-7"), "cuda-cudart");
        assert_eq!(source_stem("libcublas-13-4"), "libcublas");
        assert_eq!(source_stem("collectx-bringup"), "collectx-bringup");
    }

    #[test]
    fn parses_only_runtime_cuda_libraries() {
        let pkgs = parse_cuda_library_packages(PRIMARY);
        // libcublas-13-4 kept; -devel dropped; nsight (no .so, no profile) dropped.
        let sources: Vec<&str> = pkgs.iter().map(|p| p.source.as_str()).collect();
        assert_eq!(sources, vec!["libcublas"]);
        assert_eq!(pkgs[0].version, "13.7.0.27");
        assert_eq!(pkgs[0].sha256, "abcdef1234");
        assert_eq!(pkgs[0].size, Some(410_241_818));
        assert!(pkgs[0]
            .filename
            .ends_with("libcublas-13-4-13.7.0.27-1.x86_64.rpm"));
    }
}
