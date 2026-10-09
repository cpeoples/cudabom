//! `cargo xtask bundle`: package the committed data into a release asset.
//!
//! `cudabom update` installs a `cudabom-data-<tag>.tar.gz` bundle from a GitHub
//! Release. This task builds that asset (and its `.tar.gz.sha256` sidecar) from
//! the repository's committed, reviewed data so the release workflow has a
//! single, deterministic command to run. Nothing here touches the network.
//!
//! Bundle layout (matches what the CLI unpacks):
//!
//! ```text
//! cudabom-data-<tag>/
//!   fingerprints/<product>/*.json   (cuda, cudnn, nccl, ...)
//!   advisories/index.json           (when present)
//!   VERSION                         (the tag)
//! ```

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use cudabom_fetch::hex_sha256;

use crate::flag;

/// `bundle --tag <tag> [--out <dir>] [--fingerprints <dir>] [--advisories <file>]`
pub(crate) fn build(args: &[String]) -> Result<()> {
    let tag = flag(args, "--tag").context("bundle requires --tag <release-tag>")?;
    let out_dir = PathBuf::from(flag(args, "--out").unwrap_or_else(|| "dist".to_string()));
    let fingerprints = PathBuf::from(
        flag(args, "--fingerprints")
            .unwrap_or_else(|| cudabom_core::paths::FINGERPRINTS_DIR.into()),
    );
    let advisories = PathBuf::from(
        flag(args, "--advisories").unwrap_or_else(|| cudabom_core::paths::ADVISORY_INDEX.into()),
    );

    if !fingerprints.is_dir() {
        bail!("fingerprint directory {} not found", fingerprints.display());
    }

    // Collect the files to include as (archive-relative path, bytes). The
    // archive-relative path is prefixed with the `cudabom-data-<tag>/` wrapper
    // the CLI strips on unpack.
    let wrapper = format!("cudabom-data-{tag}");
    let mut files: Vec<(String, Vec<u8>)> = Vec::new();

    // Fingerprint shards, collected recursively so every per-product
    // subdirectory (`fingerprints/cuda`, `fingerprints/cudnn`, ...) is bundled.
    // Each shard's path *relative to the fingerprints root* is preserved in the
    // archive, so the CLI unpacks the same tree its DB loader reads.
    let mut shards: Vec<PathBuf> = Vec::new();
    collect_shards_recursive(&fingerprints, &mut shards)
        .with_context(|| format!("reading {}", fingerprints.display()))?;
    shards.sort();
    if shards.is_empty() {
        bail!("no fingerprint shards found in {}", fingerprints.display());
    }
    for shard in &shards {
        let rel = shard
            .strip_prefix(&fingerprints)
            .unwrap_or(shard)
            .to_string_lossy()
            .replace('\\', "/");
        let bytes = std::fs::read(shard).with_context(|| format!("reading {}", shard.display()))?;
        files.push((format!("{wrapper}/fingerprints/{rel}"), bytes));
    }

    // Advisory index, when present (it is optional until an index is committed).
    if advisories.is_file() {
        let bytes = std::fs::read(&advisories)
            .with_context(|| format!("reading {}", advisories.display()))?;
        files.push((format!("{wrapper}/advisories/index.json"), bytes));
    } else {
        eprintln!(
            "xtask: note: {} not found; bundling fingerprints only",
            advisories.display()
        );
    }

    // A VERSION stamp so `cudabom version` can report the installed bundle.
    files.push((
        format!("{wrapper}/VERSION"),
        format!("{tag}\n").into_bytes(),
    ));

    // Deterministic order.
    files.sort_by(|a, b| a.0.cmp(&b.0));

    std::fs::create_dir_all(&out_dir).with_context(|| format!("creating {}", out_dir.display()))?;
    let asset = out_dir.join(format!("cudabom-data-{tag}.tar.gz"));
    let archive = build_targz(&files).context("building tar.gz")?;
    std::fs::write(&asset, &archive).with_context(|| format!("writing {}", asset.display()))?;

    // The `.sha256` sidecar the CLI verifies against. Format: `<hex>  <name>`.
    let digest = hex_sha256(&archive);
    let sidecar = out_dir.join(format!("cudabom-data-{tag}.tar.gz.sha256"));
    let asset_name = asset
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("cudabom-data.tar.gz");
    std::fs::write(&sidecar, format!("{digest}  {asset_name}\n"))
        .with_context(|| format!("writing {}", sidecar.display()))?;

    eprintln!(
        "xtask: wrote {} ({} file(s), {} bytes) and {}",
        asset.display(),
        files.len(),
        archive.len(),
        sidecar.display()
    );
    Ok(())
}

/// Recursively collect every `*.json` shard under `dir` into `out`.
///
/// Bundles the whole fingerprints tree (all per-product subdirectories) so the
/// published data asset carries every product's shards, not just the cuda tree.
fn collect_shards_recursive(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            let _ = collect_shards_recursive(&path, out);
        } else if path.extension().and_then(|s| s.to_str()) == Some("json") {
            out.push(path);
        }
    }
    Ok(())
}

/// Build a gzip-compressed tar archive from (path, bytes) entries.
fn build_targz(entries: &[(String, Vec<u8>)]) -> Result<Vec<u8>> {
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    {
        let mut builder = tar::Builder::new(&mut gz);
        for (path, bytes) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o644);
            // A fixed mtime keeps the archive byte-reproducible across builds.
            header.set_mtime(0);
            header.set_cksum();
            builder
                .append_data(&mut header, Path::new(path), bytes.as_slice())
                .with_context(|| format!("appending {path}"))?;
        }
        builder.finish().context("finishing tar")?;
    }
    let inner = gz.finish().context("finishing gzip")?;
    Ok(inner)
}
