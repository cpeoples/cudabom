//! Single source of truth for the NVIDIA download hosts cudabom pulls from.
//!
//! Every redistributable URL (CUDA redist tarballs, the per-distro CUDA package
//! repos, and the Jetson/L4T APT pool) is composed here from one base host, so
//! repointing at a mirror or a moved host is a single change (or a single env
//! var) rather than editing literals scattered across the discovery tasks.
//!
//! The default host is NVIDIA's canonical `developer.download.nvidia.com`. Set
//! `CUDABOM_DOWNLOAD_BASE` to override it at runtime (e.g. an internal mirror);
//! the value is the scheme + host + optional path prefix that replaces
//! `https://developer.download.nvidia.com`, with any trailing slash trimmed.
//!
//! Integrity does not depend on the host: every fetched archive is verified
//! against NVIDIA's own published SHA-256, so a mirror that serves altered
//! bytes fails the digest check rather than being trusted.

/// NVIDIA's canonical compute-download host (no trailing slash).
const DEFAULT_DEVELOPER_DOWNLOAD: &str = "https://developer.download.nvidia.com";

/// NVIDIA's canonical Jetson/L4T APT host (no trailing slash).
const DEFAULT_REPO_DOWNLOAD: &str = "https://repo.download.nvidia.com";

/// Environment variable that overrides [`DEFAULT_DEVELOPER_DOWNLOAD`].
const DEVELOPER_DOWNLOAD_ENV: &str = "CUDABOM_DOWNLOAD_BASE";

/// Environment variable that overrides [`DEFAULT_REPO_DOWNLOAD`].
const REPO_DOWNLOAD_ENV: &str = "CUDABOM_REPO_DOWNLOAD_BASE";

/// Read `name` from the environment, trim a trailing slash, and fall back to
/// `default` when it is unset or empty.
fn host_from_env(name: &str, default: &str) -> String {
    match std::env::var(name) {
        Ok(v) if !v.trim().is_empty() => v.trim().trim_end_matches('/').to_string(),
        _ => default.to_string(),
    }
}

/// The compute-download host, honoring [`DEVELOPER_DOWNLOAD_ENV`].
pub(crate) fn developer_download() -> String {
    host_from_env(DEVELOPER_DOWNLOAD_ENV, DEFAULT_DEVELOPER_DOWNLOAD)
}

/// The Jetson/L4T APT host, honoring [`REPO_DOWNLOAD_ENV`].
pub(crate) fn repo_download() -> String {
    host_from_env(REPO_DOWNLOAD_ENV, DEFAULT_REPO_DOWNLOAD)
}

/// Base URL of a redist product tree: `<host>/compute/<product>/redist/`.
///
/// `cuda` is NVIDIA's toolkit tree; the siblings (`cudnn`, `nccl`, ...) use the
/// same shape under their own product segment.
pub(crate) fn redist_base(product: &str) -> String {
    format!("{}/compute/{product}/redist/", developer_download())
}

/// Base URL of a per-distro CUDA package repo:
/// `<host>/compute/cuda/repos/<distro>/<arch>/`.
pub(crate) fn cuda_repos_base(distro: &str, arch: &str) -> String {
    format!(
        "{}/compute/cuda/repos/{distro}/{arch}/",
        developer_download()
    )
}

/// Base URL of the Jetson/L4T APT repository root: `<host>/jetson`.
///
/// The per-release package index lives at
/// `<base>/common/dists/<release>/main/binary-arm64/Packages`, and pool paths
/// in that index are relative to `<base>/common`.
pub(crate) fn jetson_base() -> String {
    format!("{}/jetson", repo_download())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redist_base_composes_product_tree() {
        assert_eq!(
            redist_base("cudnn"),
            "https://developer.download.nvidia.com/compute/cudnn/redist/"
        );
    }

    #[test]
    fn cuda_repos_base_composes_distro_arch() {
        assert_eq!(
            cuda_repos_base("ubuntu2404", "x86_64"),
            "https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2404/x86_64/"
        );
    }

    #[test]
    fn jetson_base_is_repo_host() {
        assert_eq!(jetson_base(), "https://repo.download.nvidia.com/jetson");
    }
}
