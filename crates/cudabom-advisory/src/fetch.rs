//! Network fetch for `cudabom db update`.
//!
//! This is the only network-using code in cudabom. NVIDIA publishes CSAF
//! bulletins in `github.com/NVIDIA/product-security` but provides no CSAF
//! discovery manifest (`provider-metadata.json` / ROLIE feed), so cudabom
//! synthesizes the manifest itself from the repository's structure.
//!
//! Two fetch strategies feed the same offline [`crate::ingest`] pipeline:
//!
//! - **Manifest (default):** one call to GitHub's Git Trees API lists every file
//!   in the repository at a pinned commit; cudabom filters that inventory to the
//!   CSAF documents by path convention and fetches only those over
//!   `raw.githubusercontent.com`. This is the "manifest" the user asked for
//!   (we build it from the tree listing) and it enables fetching only CSAF
//!   (not the markdown/CVE siblings).
//! - **Tarball (fallback / air-gap mirror):** one request downloads the whole
//!   repository tarball for the pinned commit, which is then unpacked in memory.
//!   Useful for mirrors and offline capture.
//!
//! Integrity model: the pinned *commit SHA* is content-addressed over the entire
//! tree, so pinning the revision is itself the strongest guarantee. NVIDIA also
//! publishes a per-file `<name>.json.sha256`; the manifest path verifies each
//! CSAF file against it when present. The tarball path accepts an optional
//! `expected_sha256` of the whole archive.
//!
//! CSAF path convention (verified against the upstream layout):
//! `‹year›/‹bulletin-id›/‹bulletin-id›.json`, where the file stem equals its
//! parent directory name. This distinguishes the CSAF document from the
//! `CVE-*.json` records and any top-level `*.json`.

use cudabom_fetch::{GetOptions, RetryPolicy};

use serde::Deserialize;

/// Default upstream: NVIDIA's product-security repository on GitHub.
pub const DEFAULT_OWNER: &str = "NVIDIA";
pub const DEFAULT_REPO: &str = "product-security";

/// A pinned default revision (commit SHA) of the upstream repository. Pinning a
/// commit, never a branch, keeps `db update` reproducible and prevents the
/// source from moving underneath a build. This is a placeholder to be set to a
/// reviewed commit when a revision is chosen; `--rev` overrides it.
pub const DEFAULT_REV: &str = "";

/// How to fetch: synthesize a manifest from the Git tree, or pull the whole
/// repository tarball.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchMode {
    /// List CSAF files via the Git Trees API and fetch only those.
    Manifest,
    /// Download and unpack the whole-repository tarball.
    Tarball,
}

/// Where and how to fetch CSAF advisories.
#[derive(Debug, Clone)]
pub struct FetchSource {
    /// Fetch strategy.
    pub mode: FetchMode,
    /// Base for the codeload tarball endpoint (Tarball mode).
    pub codeload_base: String,
    /// Base for the GitHub REST API (Manifest mode, tree listing).
    pub api_base: String,
    /// Base for raw file content (Manifest mode, per-file fetch).
    pub raw_base: String,
    /// Repository owner.
    pub owner: String,
    /// Repository name.
    pub repo: String,
    /// Commit SHA (or ref) to fetch.
    pub rev: String,
    /// Optional expected sha256 (hex) of the tarball (Tarball mode).
    pub expected_sha256: Option<String>,
    /// Retry/backoff policy for every network request.
    pub retry: RetryPolicy,
}

impl FetchSource {
    /// The default source: the pinned NVIDIA product-security revision, using
    /// the manifest strategy.
    #[must_use]
    pub fn default_nvidia() -> Self {
        Self {
            mode: FetchMode::Manifest,
            codeload_base: "https://codeload.github.com".to_string(),
            api_base: "https://api.github.com".to_string(),
            raw_base: "https://raw.githubusercontent.com".to_string(),
            owner: DEFAULT_OWNER.to_string(),
            repo: DEFAULT_REPO.to_string(),
            rev: DEFAULT_REV.to_string(),
            expected_sha256: None,
            retry: RetryPolicy::default(),
        }
    }

    /// The `codeload` tarball URL for this source's owner/repo/rev.
    #[must_use]
    pub fn tarball_url(&self) -> String {
        format!(
            "{}/{}/{}/tar.gz/{}",
            self.codeload_base.trim_end_matches('/'),
            self.owner,
            self.repo,
            self.rev
        )
    }

    /// The Git Trees API URL that lists the whole repository at `rev`.
    #[must_use]
    pub fn tree_url(&self) -> String {
        format!(
            "{}/repos/{}/{}/git/trees/{}?recursive=1",
            self.api_base.trim_end_matches('/'),
            self.owner,
            self.repo,
            self.rev
        )
    }

    /// The raw-content URL for one repository file `path` at `rev`.
    #[must_use]
    pub fn raw_url(&self, path: &str) -> String {
        format!(
            "{}/{}/{}/{}/{}",
            self.raw_base.trim_end_matches('/'),
            self.owner,
            self.repo,
            self.rev,
            path
        )
    }
}

/// Limits for safe archive unpacking.
#[derive(Debug, Clone, Copy)]
pub struct UnpackLimits {
    /// Maximum number of entries to read.
    pub max_entries: usize,
    /// Maximum bytes for any single extracted file.
    pub max_file_bytes: u64,
    /// Maximum total extracted bytes across all files.
    pub max_total_bytes: u64,
}

impl Default for UnpackLimits {
    fn default() -> Self {
        Self {
            max_entries: 100_000,
            max_file_bytes: 16 * 1024 * 1024,
            max_total_bytes: 512 * 1024 * 1024,
        }
    }
}

/// Errors from the fetch/unpack path.
#[derive(Debug)]
pub enum FetchError {
    /// The HTTP request failed.
    Http(String),
    /// The archive integrity check failed.
    Integrity { expected: String, actual: String },
    /// The archive could not be read or was malformed.
    Archive(String),
    /// A limit was exceeded while unpacking.
    LimitExceeded(String),
}

impl std::fmt::Display for FetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Http(m) => write!(f, "fetch failed: {m}"),
            Self::Integrity { expected, actual } => write!(
                f,
                "archive integrity check failed: expected sha256 {expected}, got {actual}"
            ),
            Self::Archive(m) => write!(f, "archive error: {m}"),
            Self::LimitExceeded(m) => write!(f, "unpack limit exceeded: {m}"),
        }
    }
}

impl std::error::Error for FetchError {}

/// Download the whole-repository tarball for `source` over HTTPS (Tarball mode).
///
/// # Errors
/// Returns [`FetchError::Http`] on any network or HTTP-status failure, and
/// [`FetchError::Integrity`] if an `expected_sha256` is set and does not match.
pub fn download(source: &FetchSource) -> Result<Vec<u8>, FetchError> {
    if source.rev.trim().is_empty() {
        return Err(FetchError::Http(
            "no revision pinned; pass --rev <commit-sha> (the default revision is unset)"
                .to_string(),
        ));
    }
    // Verify the whole-archive digest as part of the download when provided.
    let options = GetOptions {
        retry: source.retry,
        expected_sha256: source.expected_sha256.clone(),
        user_agent: USER_AGENT.to_string(),
        headers: Vec::new(),
    };
    http_get(&source.tarball_url(), &options)
}

/// User-Agent sent on every advisory/data HTTP request. Single-sourced from the
/// shared network layer so it cannot drift from other fetchers.
pub(crate) const USER_AGENT: &str = cudabom_fetch::DEFAULT_USER_AGENT;

/// Perform a verified, retrying HTTPS GET via the shared [`cudabom_fetch`]
/// primitive, mapping its error into [`FetchError`].
pub(crate) fn http_get(url: &str, options: &GetOptions) -> Result<Vec<u8>, FetchError> {
    cudabom_fetch::get(url, options).map_err(|e| match e {
        cudabom_fetch::FetchError::Integrity { expected, actual } => {
            FetchError::Integrity { expected, actual }
        }
        other => FetchError::Http(format!("{url}: {other}")),
    })
}

/// Perform a retrying HTTPS GET with `retry`, returning the response body bytes.
pub(crate) fn http_get_bytes(url: &str, retry: RetryPolicy) -> Result<Vec<u8>, FetchError> {
    http_get(
        url,
        &GetOptions {
            retry,
            expected_sha256: None,
            user_agent: USER_AGENT.to_string(),
            headers: Vec::new(),
        },
    )
}

// --- Manifest (Git Trees API) path -------------------------------------------

/// One entry of the Git Trees API response.
#[derive(Debug, Deserialize)]
struct TreeResponse {
    #[serde(default)]
    tree: Vec<TreeEntry>,
    #[serde(default)]
    truncated: bool,
}

#[derive(Debug, Deserialize)]
struct TreeEntry {
    #[serde(default)]
    path: String,
    #[serde(default, rename = "type")]
    entry_type: String,
}

/// List the CSAF document paths in the repository at `source.rev`, using the Git
/// Trees API. This is the synthesized manifest: one request enumerates the whole
/// tree, then it is filtered to CSAF documents by [`is_csaf_path`].
///
/// # Errors
/// Returns [`FetchError::Http`] on request failure or [`FetchError::Archive`]
/// if the response is not the expected JSON shape or was truncated by GitHub.
pub fn list_csaf_paths(source: &FetchSource) -> Result<Vec<String>, FetchError> {
    if source.rev.trim().is_empty() {
        return Err(FetchError::Http(
            "no revision pinned; pass --rev <commit-sha>".to_string(),
        ));
    }
    let bytes = http_get_bytes(&source.tree_url(), source.retry)?;
    let parsed: TreeResponse =
        serde_json::from_slice(&bytes).map_err(|e| FetchError::Archive(e.to_string()))?;

    if parsed.truncated {
        // The repo is larger than one tree page. Rather than silently ingest a
        // partial set, fail loudly so the caller falls back to the tarball.
        return Err(FetchError::Archive(
            "git tree listing was truncated by the server; use --mode tarball".to_string(),
        ));
    }

    let mut paths: Vec<String> = parsed
        .tree
        .into_iter()
        .filter(|e| e.entry_type == "blob")
        .map(|e| e.path)
        .filter(|p| is_csaf_path(p))
        .collect();
    paths.sort();
    Ok(paths)
}

/// Fetch one repository file's bytes over `raw.githubusercontent.com`, verifying
/// it against its published `<path>.sha256` sibling when that is available.
///
/// # Errors
/// Returns [`FetchError::Http`] on request failure and [`FetchError::Integrity`]
/// when a sibling checksum is present and does not match.
pub fn fetch_file(source: &FetchSource, path: &str) -> Result<Vec<u8>, FetchError> {
    let bytes = http_get_bytes(&source.raw_url(path), source.retry)?;

    // NVIDIA publishes a `<path>.sha256` next to each CSAF file. Fetch it
    // best-effort; if present, it must match. Its absence is not fatal (the
    // pinned commit SHA already covers integrity).
    let sha_url = source.raw_url(&format!("{path}.sha256"));
    if let Ok(sha_bytes) = http_get_bytes(&sha_url, source.retry) {
        if let Some(expected) = crate::unpack::parse_sha256_sidecar(&sha_bytes) {
            verify_sha256(&bytes, &expected)?;
        }
    }
    Ok(bytes)
}

/// The result of fetching a single file with sidecar verification, keeping an
/// integrity mismatch distinct from success so a caller can skip-and-report one
/// bad file rather than aborting a whole index build.
#[derive(Debug)]
pub enum FileOutcome {
    /// The file was fetched and (if a sidecar was present) verified.
    Fetched(Vec<u8>),
    /// A `.sha256` sidecar was present but did not match the fetched content.
    /// The pinned commit SHA still anchors integrity; this reports the specific
    /// upstream inconsistency so it is auditable rather than silently trusted.
    IntegrityMismatch { expected: String, actual: String },
}

/// Fetch one repository file, verifying its `<path>.sha256` sidecar when present
/// but returning [`FileOutcome::IntegrityMismatch`] instead of an error when the
/// sidecar is present and does not match.
///
/// Rationale: the pinned commit SHA is the primary, content-addressed integrity
/// anchor over the whole tree. A per-file sidecar is a secondary check, and
/// upstream occasionally re-publishes a document without regenerating its
/// sidecar. Aborting an entire refresh over one stale sidecar is too brittle, so
/// callers skip and loudly report the offending file instead.
///
/// # Errors
/// Returns [`FetchError::Http`] on request failure (a mismatch is *not* an
/// error here; it is reported via the returned [`FileOutcome`]).
pub fn fetch_file_checked(source: &FetchSource, path: &str) -> Result<FileOutcome, FetchError> {
    let bytes = http_get_bytes(&source.raw_url(path), source.retry)?;

    let sha_url = source.raw_url(&format!("{path}.sha256"));
    if let Ok(sha_bytes) = http_get_bytes(&sha_url, source.retry) {
        if let Some(expected) = crate::unpack::parse_sha256_sidecar(&sha_bytes) {
            let actual = cudabom_fetch::hex_sha256(&bytes);
            if !actual.eq_ignore_ascii_case(&expected) {
                return Ok(FileOutcome::IntegrityMismatch { expected, actual });
            }
        }
    }
    Ok(FileOutcome::Fetched(bytes))
}

/// True if `path` is a CSAF document by the NVIDIA repo convention:
/// `‹year›/‹id›/‹id›.json`, i.e. a `*.json` whose file stem equals its parent
/// directory name. This excludes `CVE-*.json` records and top-level `*.json`.
#[must_use]
pub fn is_csaf_path(path: &str) -> bool {
    let p = std::path::Path::new(path);
    // Must be a .json file.
    if p.extension().and_then(|s| s.to_str()) != Some("json") {
        return false;
    }
    let Some(stem) = p.file_stem().and_then(|s| s.to_str()) else {
        return false;
    };
    // CVE records are also .json but are not CSAF.
    if stem
        .get(..4)
        .is_some_and(|p| p.eq_ignore_ascii_case("CVE-"))
    {
        return false;
    }
    let Some(parent) = p
        .parent()
        .and_then(std::path::Path::file_name)
        .and_then(|s| s.to_str())
    else {
        return false;
    };
    // The CSAF document's stem matches its bulletin directory name.
    stem == parent
}

/// Verify the sha256 (hex) of `bytes` against `expected`.
///
/// # Errors
/// Returns [`FetchError::Integrity`] if the digests differ.
pub fn verify_sha256(bytes: &[u8], expected: &str) -> Result<(), FetchError> {
    cudabom_fetch::verify_sha256(bytes, expected).map_err(|e| match e {
        cudabom_fetch::FetchError::Integrity { expected, actual } => {
            FetchError::Integrity { expected, actual }
        }
        other => FetchError::Http(other.to_string()),
    })
}

/// Safely unpack a gzip-compressed tar archive, returning the raw bytes of every
/// CSAF document entry (`‹year›/‹id›/‹id›.json`). Markdown, CVE records, and
/// checksums are ignored. The codeload tarball wraps everything in a top-level
/// `‹repo›-‹sha›/` directory, which is stripped before applying the CSAF path
/// convention.
///
/// Extraction is bounded by `limits` and rejects unsafe paths (absolute paths,
/// `..` traversal). Nothing is written to disk.
///
/// # Errors
/// Returns [`FetchError::Archive`] on a malformed archive and
/// [`FetchError::LimitExceeded`] when a limit is hit.
pub fn unpack_csaf(gzip_tar: &[u8], limits: &UnpackLimits) -> Result<Vec<Vec<u8>>, FetchError> {
    let mut documents = Vec::new();
    crate::unpack::extract_gzip_tar(
        gzip_tar,
        limits,
        // Keep only CSAF documents (by the NVIDIA repo convention) once the
        // codeload wrapper directory has been stripped.
        |inner, _is_dir| is_csaf_path(inner),
        |_inner, bytes| {
            documents.push(bytes);
            Ok(())
        },
    )?;
    Ok(documents)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tarball_url_is_codeload_shaped() {
        let mut s = FetchSource::default_nvidia();
        s.rev = "abc123".to_string();
        assert_eq!(
            s.tarball_url(),
            "https://codeload.github.com/NVIDIA/product-security/tar.gz/abc123"
        );
    }

    #[test]
    fn tree_url_is_recursive_trees_api() {
        let mut s = FetchSource::default_nvidia();
        s.rev = "abc123".to_string();
        assert_eq!(
            s.tree_url(),
            "https://api.github.com/repos/NVIDIA/product-security/git/trees/abc123?recursive=1"
        );
    }

    #[test]
    fn raw_url_points_at_raw_host() {
        let mut s = FetchSource::default_nvidia();
        s.rev = "abc123".to_string();
        assert_eq!(
            s.raw_url("2025/5730/5730.json"),
            "https://raw.githubusercontent.com/NVIDIA/product-security/abc123/2025/5730/5730.json"
        );
    }

    #[test]
    fn csaf_path_convention_matches_only_the_bulletin_document() {
        // The CSAF document: stem == parent dir name.
        assert!(is_csaf_path("2025/5730/5730.json"));
        assert!(is_csaf_path("2026/6001/6001.json"));
        // CVE records live beside it but are not CSAF.
        assert!(!is_csaf_path("2025/5730/CVE-2025-33208.json"));
        assert!(!is_csaf_path("2025/5730/cve-2025-33208.json"));
        // Markdown and checksums are not CSAF.
        assert!(!is_csaf_path("2025/5730/5730.md"));
        assert!(!is_csaf_path("2025/5730/5730.json.sha256"));
        // Top-level or mismatched files are excluded.
        assert!(!is_csaf_path("2025/README.json"));
        assert!(!is_csaf_path("product-map.json"));
    }

    #[test]
    fn list_csaf_paths_filters_and_sorts_tree_json() {
        let body = br#"{
            "sha": "abc",
            "truncated": false,
            "tree": [
                {"path": "2025/5734/5734.json", "type": "blob"},
                {"path": "2025/5730/5730.json", "type": "blob"},
                {"path": "2025/5730/CVE-2025-33208.json", "type": "blob"},
                {"path": "2025/5730/5730.md", "type": "blob"},
                {"path": "2025/5730", "type": "tree"}
            ]
        }"#;
        let parsed: TreeResponse = serde_json::from_slice(body).unwrap();
        assert!(!parsed.truncated);
        let mut paths: Vec<String> = parsed
            .tree
            .into_iter()
            .filter(|e| e.entry_type == "blob")
            .map(|e| e.path)
            .filter(|p| is_csaf_path(p))
            .collect();
        paths.sort();
        assert_eq!(paths, vec!["2025/5730/5730.json", "2025/5734/5734.json"]);
    }

    #[test]
    fn verify_sha256_accepts_matching_and_rejects_mismatch() {
        let data = b"hello";
        let digest = cudabom_fetch::hex_sha256(data);
        assert!(verify_sha256(data, &digest).is_ok());
        // Case-insensitive.
        assert!(verify_sha256(data, &digest.to_uppercase()).is_ok());
        assert!(matches!(
            verify_sha256(data, "00"),
            Err(FetchError::Integrity { .. })
        ));
    }

    #[test]
    fn download_without_revision_is_an_error() {
        let s = FetchSource::default_nvidia(); // DEFAULT_REV is empty
        assert!(matches!(download(&s), Err(FetchError::Http(_))));
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
    fn unpack_returns_only_csaf_documents() {
        // Entries mirror the codeload layout: wrapper dir + repo tree.
        let archive = make_targz(&[
            ("product-security-abc/2025/5730/5730.json", br#"{"a":1}"#),
            ("product-security-abc/2025/5730/5730.md", b"not json"),
            (
                "product-security-abc/2025/5730/CVE-2025-1.json",
                br#"{"cve":1}"#,
            ),
            ("product-security-abc/2025/5734/5734.json", br#"{"b":2}"#),
            ("product-security-abc/README.md", b"top-level"),
        ]);
        let docs = unpack_csaf(&archive, &UnpackLimits::default()).unwrap();
        assert_eq!(docs.len(), 2);
        assert_eq!(docs[0], br#"{"a":1}"#);
        assert_eq!(docs[1], br#"{"b":2}"#);
    }

    #[test]
    fn unpack_enforces_total_size_limit() {
        let big = vec![b'x'; 1024];
        let archive = make_targz(&[
            ("product-security-abc/2025/1/1.json", &big),
            ("product-security-abc/2025/2/2.json", &big),
        ]);
        let limits = UnpackLimits {
            max_entries: 100,
            max_file_bytes: 10_000,
            max_total_bytes: 1500, // less than 2*1024
        };
        assert!(matches!(
            unpack_csaf(&archive, &limits),
            Err(FetchError::LimitExceeded(_))
        ));
    }

    #[test]
    fn unpack_enforces_per_file_limit() {
        let big = vec![b'x'; 2048];
        let archive = make_targz(&[("product-security-abc/2025/1/1.json", &big)]);
        let limits = UnpackLimits {
            max_entries: 100,
            max_file_bytes: 1024,
            max_total_bytes: 1_000_000,
        };
        assert!(matches!(
            unpack_csaf(&archive, &limits),
            Err(FetchError::LimitExceeded(_))
        ));
    }
}
