//! NVIDIA NGC SBOM/VEX fetch (the only networked path in `reconcile`).
//!
//! NGC publishes a CycloneDX SBOM and VEX per container image tag at:
//!
//! - `GET {base}/v2/org/{org}/repos/{repo}/images/{tag}/sbom`
//! - `GET {base}/v2/org/{org}/repos/{repo}/images/{tag}/vex`
//!
//! Both require an NGC API key (`Authorization: Bearer <key>`); without one the
//! endpoints return 401. This module is therefore strictly opt-in: nothing here
//! runs unless the user passes `--ngc-image` *and* supplies a key. Retries and
//! backoff are inherited from [`cudabom_fetch`], the same primitive `db update`
//! and `corpus fetch` use.

use cudabom_fetch::{get, FetchError, GetOptions, RetryPolicy};

/// The default NGC API base. Overridable in tests via [`fetch_declared_with`].
const NGC_API_BASE: &str = "https://api.ngc.nvidia.com";

/// A parsed NGC image coordinate: `org/repository:tag`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NgcImage {
    pub(crate) org: String,
    pub(crate) repo: String,
    pub(crate) tag: String,
}

impl NgcImage {
    /// Parse `org/repository:tag`. The repository may itself contain slashes
    /// (NGC allows nested repos), so the org is the first segment and the tag
    /// is whatever follows the final colon.
    pub(crate) fn parse(spec: &str) -> Result<Self, String> {
        let (path, tag) = spec
            .rsplit_once(':')
            .ok_or_else(|| format!("expected org/repository:tag, got {spec:?}"))?;
        let (org, repo) = path
            .split_once('/')
            .ok_or_else(|| format!("expected org/repository:tag, got {spec:?}"))?;
        if org.is_empty() || repo.is_empty() || tag.is_empty() {
            return Err(format!("expected org/repository:tag, got {spec:?}"));
        }
        Ok(Self {
            org: org.to_string(),
            repo: repo.to_string(),
            tag: tag.to_string(),
        })
    }

    fn sbom_url(&self, base: &str) -> String {
        format!(
            "{base}/v2/org/{}/repos/{}/images/{}/sbom",
            self.org, self.repo, self.tag
        )
    }

    fn vex_url(&self, base: &str) -> String {
        format!(
            "{base}/v2/org/{}/repos/{}/images/{}/vex",
            self.org, self.repo, self.tag
        )
    }
}

/// The fetched declared documents (each is CycloneDX JSON bytes).
pub(crate) struct FetchedDeclared {
    pub(crate) sbom: Vec<u8>,
    pub(crate) vex: Option<Vec<u8>>,
}

/// Fetch the SBOM (required) and VEX (best-effort) for `image` from NGC using
/// `api_key`. The SBOM is mandatory; a missing VEX (404) is tolerated because
/// not every image publishes one.
pub(crate) fn fetch_declared(image: &NgcImage, api_key: &str) -> Result<FetchedDeclared, String> {
    fetch_declared_with(image, api_key, NGC_API_BASE)
}

/// The base-URL-injected core, so tests can point at a local server.
pub(crate) fn fetch_declared_with(
    image: &NgcImage,
    api_key: &str,
    base: &str,
) -> Result<FetchedDeclared, String> {
    let options = GetOptions {
        retry: RetryPolicy::default(),
        expected_sha256: None,
        user_agent: format!("cudabom/{}", env!("CARGO_PKG_VERSION")),
        headers: vec![("Authorization".to_string(), format!("Bearer {api_key}"))],
    };

    let sbom = get(&image.sbom_url(base), &options)
        .map_err(|e| format!("fetching NGC SBOM: {}", describe(&e)))?;

    let vex = match get(&image.vex_url(base), &options) {
        Ok(bytes) => Some(bytes),
        // A 404 means this image has no published VEX; that is not an error.
        Err(FetchError::Status(404)) => None,
        Err(e) => return Err(format!("fetching NGC VEX: {}", describe(&e))),
    };

    Ok(FetchedDeclared { sbom, vex })
}

/// A user-facing description of a fetch error, with an auth hint for 401/403.
fn describe(err: &FetchError) -> String {
    match err {
        FetchError::Status(401 | 403) => {
            "authentication failed (check the NGC API key and its permissions)".to_string()
        }
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_image_coordinates() {
        let img = NgcImage::parse("nvidia/pytorch:26.01-py3").unwrap();
        assert_eq!(img.org, "nvidia");
        assert_eq!(img.repo, "pytorch");
        assert_eq!(img.tag, "26.01-py3");
    }

    #[test]
    fn parses_nested_repository() {
        let img = NgcImage::parse("nvidia/team/pytorch:latest").unwrap();
        assert_eq!(img.org, "nvidia");
        assert_eq!(img.repo, "team/pytorch");
        assert_eq!(img.tag, "latest");
    }

    #[test]
    fn rejects_malformed_coordinates() {
        assert!(NgcImage::parse("pytorch").is_err());
        assert!(NgcImage::parse("nvidia/pytorch").is_err());
        assert!(NgcImage::parse(":tag").is_err());
        assert!(NgcImage::parse("nvidia/:tag").is_err());
    }

    #[test]
    fn builds_expected_urls() {
        let img = NgcImage::parse("nvidia/pytorch:26.01-py3").unwrap();
        assert_eq!(
            img.sbom_url("https://api.ngc.nvidia.com"),
            "https://api.ngc.nvidia.com/v2/org/nvidia/repos/pytorch/images/26.01-py3/sbom"
        );
        assert_eq!(
            img.vex_url("https://api.ngc.nvidia.com"),
            "https://api.ngc.nvidia.com/v2/org/nvidia/repos/pytorch/images/26.01-py3/vex"
        );
    }
}
