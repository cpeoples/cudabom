//! Data-bundle fetch for `cudabom update`.
//!
//! cudabom ships as a single binary (crates.io, a Snap, a release archive) that
//! carries no fingerprint database or advisory index. Those are the committed,
//! reviewed data in the public repository, published per release as a single
//! signed-and-hashed **data bundle** (`cudabom-data-<tag>.tar.gz`) alongside a
//! `.tar.gz.sha256` sidecar as a GitHub Release asset.
//!
//! `cudabom update` downloads that asset for a tag (default: the latest
//! release), verifies it against the sidecar digest, and unpacks it into the
//! per-user data directory a scan reads from. This is the same integrity model
//! as `db update`: content-addressed by digest, unpacked with hard limits and
//! path-traversal rejection, nothing written outside the target directory.
//!
//! The bundle layout mirrors the repository's committed data so the unpacked
//! tree is self-describing:
//!
//! ```text
//! cudabom-data-<tag>/
//!   fingerprints/cuda/redistrib_<ver>.json
//!   advisories/index.json
//!   VERSION                # the release tag, for `cudabom version`
//! ```

use std::path::{Path, PathBuf};

use cudabom_fetch::RetryPolicy;

use crate::fetch::{FetchError, UnpackLimits};

/// Default GitHub owner/repo the data bundle is published from.
pub const DEFAULT_DATA_OWNER: &str = "cpeoples";
pub const DEFAULT_DATA_REPO: &str = "cudabom";

/// Where and how to fetch a data bundle release asset.
#[derive(Debug, Clone)]
pub struct DataSource {
    /// Base for the GitHub REST API (release lookup).
    pub api_base: String,
    /// Base for release asset downloads (`github.com/.../releases/download`).
    pub download_base: String,
    /// Repository owner.
    pub owner: String,
    /// Repository name.
    pub repo: String,
    /// The release tag to fetch, or `None` for the latest release.
    pub tag: Option<String>,
    /// Retry/backoff policy for every request.
    pub retry: RetryPolicy,
}

impl DataSource {
    /// The default source: the public cudabom repository's latest release.
    #[must_use]
    pub fn default_public() -> Self {
        Self {
            api_base: "https://api.github.com".to_string(),
            download_base: "https://github.com".to_string(),
            owner: DEFAULT_DATA_OWNER.to_string(),
            repo: DEFAULT_DATA_REPO.to_string(),
            tag: None,
            retry: RetryPolicy::default(),
        }
    }

    /// The REST API URL that resolves the latest release (used when no tag is
    /// pinned) to discover its tag name.
    #[must_use]
    pub fn latest_release_url(&self) -> String {
        format!(
            "{}/repos/{}/{}/releases/latest",
            self.api_base.trim_end_matches('/'),
            self.owner,
            self.repo
        )
    }

    /// The download URL for the bundle asset at `tag`.
    #[must_use]
    pub fn bundle_url(&self, tag: &str) -> String {
        format!(
            "{}/{}/{}/releases/download/{}/{}",
            self.download_base.trim_end_matches('/'),
            self.owner,
            self.repo,
            tag,
            bundle_asset_name(tag)
        )
    }

    /// The download URL for the bundle's `.sha256` sidecar at `tag`.
    #[must_use]
    pub fn sidecar_url(&self, tag: &str) -> String {
        format!("{}.sha256", self.bundle_url(tag))
    }
}

/// The canonical bundle asset file name for a release `tag`.
#[must_use]
pub fn bundle_asset_name(tag: &str) -> String {
    format!("cudabom-data-{tag}.tar.gz")
}

/// The outcome of a successful update: which tag was installed and where.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Installed {
    /// The release tag that was installed.
    pub tag: String,
    /// The directory the bundle was unpacked into.
    pub dir: PathBuf,
    /// The number of files written.
    pub files: usize,
}

/// Fetch, verify, and unpack the data bundle for `source` into `dest`.
///
/// Resolves the latest release tag when `source.tag` is `None`, downloads the
/// bundle and its `.sha256` sidecar, verifies the digest, and unpacks the
/// archive into `dest` (creating it if needed). The leading
/// `cudabom-data-<tag>/` wrapper directory is stripped so the tree lands
/// directly under `dest`.
///
/// # Errors
/// Returns [`FetchError`] on any network, integrity, or unpack failure.
pub fn update_data(source: &DataSource, dest: &Path) -> Result<Installed, FetchError> {
    let tag = match &source.tag {
        Some(t) => t.clone(),
        None => resolve_latest_tag(source)?,
    };

    let bundle = crate::fetch::http_get_bytes(&source.bundle_url(&tag), source.retry)?;

    // The sidecar is mandatory for the bundle: unlike the per-file CSAF
    // sidecars (secondary to a pinned commit), the release asset has no other
    // integrity anchor, so a missing or mismatching digest is fatal.
    let sidecar = crate::fetch::http_get_bytes(&source.sidecar_url(&tag), source.retry)?;
    let expected = crate::unpack::parse_sha256_sidecar(&sidecar).ok_or_else(|| {
        FetchError::Archive(format!(
            "release {tag}: {}.sha256 did not contain a sha256 digest",
            bundle_asset_name(&tag)
        ))
    })?;
    crate::fetch::verify_sha256(&bundle, &expected)?;

    let files = unpack_bundle(&bundle, dest, &UnpackLimits::default())?;
    Ok(Installed {
        tag,
        dir: dest.to_path_buf(),
        files,
    })
}

/// One entry of the GitHub "latest release" API response we care about.
#[derive(Debug, serde::Deserialize)]
struct LatestRelease {
    #[serde(default)]
    tag_name: String,
}

/// Resolve the latest release's tag via the REST API.
fn resolve_latest_tag(source: &DataSource) -> Result<String, FetchError> {
    let bytes = crate::fetch::http_get_bytes(&source.latest_release_url(), source.retry)?;
    let release: LatestRelease =
        serde_json::from_slice(&bytes).map_err(|e| FetchError::Archive(e.to_string()))?;
    if release.tag_name.trim().is_empty() {
        return Err(FetchError::Archive(
            "latest release had no tag_name; pin one with --tag".to_string(),
        ));
    }
    Ok(release.tag_name)
}

/// Safely unpack a gzip-tar data bundle into `dest`, stripping the leading
/// `cudabom-data-<tag>/` wrapper directory. Returns the number of files written.
///
/// Extraction is bounded by `limits` and rejects unsafe paths (absolute paths,
/// `..` traversal); each file is written under `dest` only.
fn unpack_bundle(gzip_tar: &[u8], dest: &Path, limits: &UnpackLimits) -> Result<usize, FetchError> {
    std::fs::create_dir_all(dest)
        .map_err(|e| FetchError::Archive(format!("creating {}: {e}", dest.display())))?;

    let mut written: usize = 0;
    crate::unpack::extract_gzip_tar(
        gzip_tar,
        limits,
        // Directories are recreated implicitly when their files are written;
        // the empty inner path is the wrapper directory itself.
        |inner, is_dir| !is_dir && !inner.is_empty(),
        |inner, bytes| {
            let out_path = dest.join(inner);
            // Defense in depth: the joined path must stay within dest.
            if !out_path.starts_with(dest) {
                return Ok(());
            }
            if let Some(parent) = out_path.parent() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    FetchError::Archive(format!("creating {}: {e}", parent.display()))
                })?;
            }
            std::fs::write(&out_path, &bytes)
                .map_err(|e| FetchError::Archive(format!("writing {}: {e}", out_path.display())))?;
            written += 1;
            Ok(())
        },
    )?;

    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundle_asset_name_uses_the_tag() {
        assert_eq!(bundle_asset_name("v1.2.3"), "cudabom-data-v1.2.3.tar.gz");
    }

    #[test]
    fn urls_are_shaped_correctly() {
        let s = DataSource::default_public();
        assert_eq!(
            s.latest_release_url(),
            "https://api.github.com/repos/cpeoples/cudabom/releases/latest"
        );
        assert_eq!(
            s.bundle_url("v1.0.0"),
            "https://github.com/cpeoples/cudabom/releases/download/v1.0.0/cudabom-data-v1.0.0.tar.gz"
        );
        assert_eq!(
            s.sidecar_url("v1.0.0"),
            "https://github.com/cpeoples/cudabom/releases/download/v1.0.0/cudabom-data-v1.0.0.tar.gz.sha256"
        );
    }

    /// Build a gzip-tar archive in memory from (path, contents) pairs.
    fn make_targz(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        {
            let mut builder = tar::Builder::new(&mut gz);
            for (path, contents) in entries {
                let mut header = tar::Header::new_gnu();
                header.set_size(contents.len() as u64);
                header.set_mode(0o644);
                header.set_cksum();
                builder.append_data(&mut header, path, *contents).unwrap();
            }
            builder.finish().unwrap();
        }
        gz.finish().unwrap()
    }

    #[test]
    fn unpack_writes_files_under_dest_stripping_the_wrapper() {
        let dir = tempfile::tempdir().unwrap();
        let archive = make_targz(&[
            (
                "cudabom-data-v1/advisories/index.json",
                br#"{"schema_version":1}"#,
            ),
            (
                "cudabom-data-v1/fingerprints/cuda/redistrib_12.4.1.json",
                br#"{"schema_version":1}"#,
            ),
            (
                "cudabom-data-v1/fingerprints/cudnn/redistrib_9.27.0.json",
                br#"{"schema_version":1}"#,
            ),
            ("cudabom-data-v1/VERSION", b"v1"),
        ]);
        let written = unpack_bundle(&archive, dir.path(), &UnpackLimits::default()).unwrap();
        assert_eq!(written, 4);
        assert!(dir.path().join("advisories/index.json").exists());
        assert!(dir
            .path()
            .join("fingerprints/cuda/redistrib_12.4.1.json")
            .exists());
        // Sibling-product shards unpack to their own subdirectory, preserving
        // the multi-tree layout the DB loader reads recursively.
        assert!(dir
            .path()
            .join("fingerprints/cudnn/redistrib_9.27.0.json")
            .exists());
        assert_eq!(
            std::fs::read_to_string(dir.path().join("VERSION")).unwrap(),
            "v1"
        );
    }

    #[test]
    fn unpack_enforces_total_size_limit() {
        let dir = tempfile::tempdir().unwrap();
        let big = vec![b'x'; 1024];
        let archive = make_targz(&[
            ("cudabom-data-v1/a.json", &big),
            ("cudabom-data-v1/b.json", &big),
        ]);
        let limits = UnpackLimits {
            max_entries: 100,
            max_file_bytes: 10_000,
            max_total_bytes: 1500,
        };
        assert!(matches!(
            unpack_bundle(&archive, dir.path(), &limits),
            Err(FetchError::LimitExceeded(_))
        ));
    }
}
