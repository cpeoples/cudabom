//! Shared parsing of Debian APT `Packages` indices for the NVIDIA package
//! channels that ship CUDA libraries as `.deb`s (the Jetson/L4T pool and the
//! per-distro `compute/cuda/repos/<distro>/<arch>/` repos).
//!
//! Both channels publish the same index format, so the stanza parser, the
//! `Source` -> manifest-key normalization, and the version cleanup live here
//! once and are reused by `jetson` and `cuda_repos`. Only first-party fields
//! are read; nothing about a package is inferred.

use std::collections::BTreeMap;

use cudabom_identify::resolve_component;

/// One runtime CUDA library package parsed from an APT `Packages` stanza.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DebPackage {
    /// APT `Source` name (e.g. `libcublas`, `cuda-cudart`).
    pub source: String,
    /// Exact upstream version with the Debian revision stripped
    /// (`12.6.1.4-1` -> `12.6.1.4`).
    pub version: String,
    /// Pool path relative to the repository base (the `Filename` field).
    pub filename: String,
    /// NVIDIA's own sha256 of the `.deb`, lowercased.
    pub sha256: String,
    /// Size in bytes, when present.
    pub size: Option<u64>,
}

/// Map an APT `Source` name to the redist manifest key the profile table uses.
/// NVIDIA's package sources use hyphens where the redist manifest keys use
/// underscores (`cuda-cudart` -> `cuda_cudart`); the `lib*` sources already
/// match (`libcublas` -> `libcublas`). Replacing `-` with `_` normalizes both.
pub(crate) fn manifest_key_for(source: &str) -> String {
    source.replace('-', "_")
}

/// Strip the Debian package revision from a version (`12.6.1.4-1` ->
/// `12.6.1.4`). The upstream version is everything before the last `-`.
pub(crate) fn strip_debian_revision(version: &str) -> String {
    match version.rsplit_once('-') {
        Some((upstream, _rev)) => upstream.to_string(),
        None => version.to_string(),
    }
}

/// Parse the runtime CUDA library packages out of an APT `Packages` index.
///
/// The index is a sequence of stanzas separated by blank lines, each a set of
/// `Field: value` lines. A stanza is kept when it is a runtime CUDA library:
/// it declares a `Provides:` of a versioned `.so`, its `Source` resolves to a
/// known component profile, and it is not a `-dev` package (headers/symlinks,
/// no runtime library). Only first-party fields are read; nothing is inferred.
pub(crate) fn parse_cuda_library_packages(index_text: &str) -> Vec<DebPackage> {
    let mut out = Vec::new();
    for stanza in index_text.split("\n\n") {
        let mut fields: BTreeMap<&str, &str> = BTreeMap::new();
        for line in stanza.lines() {
            // A leading space marks a continuation of the previous field (e.g. a
            // multi-line Description); none of those carry a field we read.
            if line.starts_with(' ') {
                continue;
            }
            if let Some((k, v)) = line.split_once(": ") {
                fields.insert(k, v.trim());
            }
        }

        let Some(package) = fields.get("Package") else {
            continue;
        };
        // The -dev packages ship headers and symlinks, no runtime library.
        if package.contains("-dev-") || package.ends_with("-dev") {
            continue;
        }
        let Some(provides) = fields.get("Provides") else {
            continue;
        };
        if !provides.contains(".so") {
            continue;
        }

        let Some(source) = fields.get("Source") else {
            continue;
        };
        // Keep only sources that resolve to a reviewed component, so we never
        // synthesize an entry cudabom cannot attribute.
        if resolve_component(&manifest_key_for(source)).is_none() {
            continue;
        }

        let (Some(version), Some(filename), Some(sha256)) = (
            fields.get("Version"),
            fields.get("Filename"),
            fields.get("SHA256"),
        ) else {
            continue;
        };

        out.push(DebPackage {
            source: (*source).to_string(),
            version: strip_debian_revision(version),
            filename: (*filename).to_string(),
            sha256: sha256.to_ascii_lowercase(),
            size: fields.get("Size").and_then(|s| s.parse::<u64>().ok()),
        });
    }
    out.sort_by(|a, b| a.source.cmp(&b.source));
    out.dedup_by(|a, b| a.source == b.source);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "Package: libcublas-12-6\n\
Source: libcublas\n\
Version: 12.6.4.1-1\n\
Provides: libcublas.so.12 (= 12.6.4.1)\n\
Filename: pool/main/libcublas/libcublas-12-6_12.6.4.1-1_arm64.deb\n\
Size: 12345\n\
SHA256: ABCDEF\n\
\n\
Package: libcublas-dev-12-6\n\
Source: libcublas-dev\n\
Version: 12.6.4.1-1\n\
Provides: libcublas.so (= 12.6.4.1)\n\
Filename: pool/main/libcublas/libcublas-dev-12-6_12.6.4.1-1_arm64.deb\n\
SHA256: 999999\n\
\n\
Package: cuda-cudart-12-6\n\
Source: cuda-cudart\n\
Version: 12.6.68-1\n\
Provides: libcudart.so.12 (= 12.6.68)\n\
Filename: pool/main/c/cuda-cudart/cuda-cudart-12-6_12.6.68-1_arm64.deb\n\
SHA256: 123456\n";

    #[test]
    fn keeps_runtime_libs_drops_dev() {
        let pkgs = parse_cuda_library_packages(SAMPLE);
        let sources: Vec<&str> = pkgs.iter().map(|p| p.source.as_str()).collect();
        // libcublas-12-6 and cuda-cudart-12-6 are kept; the -dev package is
        // dropped (headers only), and the versions have the revision stripped.
        assert_eq!(sources, vec!["cuda-cudart", "libcublas"]);
        assert_eq!(pkgs[0].version, "12.6.68");
        assert_eq!(pkgs[0].sha256, "123456");
        assert_eq!(pkgs[1].size, Some(12345));
    }

    #[test]
    fn manifest_key_normalizes_hyphens() {
        assert_eq!(manifest_key_for("cuda-cudart"), "cuda_cudart");
        assert_eq!(manifest_key_for("libcublas"), "libcublas");
        assert_eq!(manifest_key_for("cuda-nvrtc"), "cuda_nvrtc");
    }

    #[test]
    fn strips_debian_revision() {
        assert_eq!(strip_debian_revision("12.6.1.4-1"), "12.6.1.4");
        assert_eq!(strip_debian_revision("9.3.0.75-1"), "9.3.0.75");
        assert_eq!(strip_debian_revision("1.2.3"), "1.2.3");
    }
}
