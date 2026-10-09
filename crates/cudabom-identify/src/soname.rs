//! SONAME grammar parsing.
//!
//! Linux shared libraries follow a documented naming convention:
//! `libNAME.so.MAJOR[.MINOR[.PATCH]]`. This is structural, not invented; the
//! version digits are literally part of the SONAME string. Parsing it lets
//! cudabom attribute a dependency to a library stem (`libcudart.so`) and read
//! the ABI major version directly from the name, without any fingerprint data.
//!
//! This never asserts a *product* identity on its own (a SONAME can be
//! spoofed); it produces the stem and version so the matcher can combine it
//! with fingerprint-DB knowledge and other evidence.

/// The parsed pieces of a SONAME.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SonameParts {
    /// The stem including the `.so`, e.g. `libcudart.so`.
    pub(crate) stem: String,
    /// The dotted version after `.so.`, e.g. `12` or `12.4.1`, if present.
    pub(crate) version: Option<String>,
}

/// Parse a SONAME (or a plain shared-library file name) into its stem and
/// version, following the `libNAME.so[.VERSION]` convention.
///
/// Returns `None` if the name does not contain `.so` at all (not a shared
/// library name). A name like `libcudart.so` with no version yields a stem and
/// `version: None`.
#[must_use]
pub(crate) fn parse_soname(name: &str) -> Option<SonameParts> {
    // Strip any directory prefix; a SONAME is a bare name but callers may pass
    // a path.
    let base = name.rsplit('/').next().unwrap_or(name);

    // Find the `.so` marker. Everything up to and including `.so` is the stem;
    // anything after `.so.` is the version.
    let idx = base.find(".so")?;
    let stem = &base[..idx + 3]; // include ".so"

    // After ".so" we expect either nothing or ".<version>".
    let rest = &base[idx + 3..];
    let version = rest.strip_prefix('.').and_then(|v| {
        // A version must be dot-separated digits; anything else is not a
        // standard SONAME version and is ignored rather than misread.
        if !v.is_empty()
            && v.split('.')
                .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()))
        {
            Some(v.to_string())
        } else {
            None
        }
    });

    Some(SonameParts {
        stem: stem.to_string(),
        version,
    })
}

/// The ABI major version (the first dotted component of the SONAME version).
#[must_use]
pub(crate) fn major_version(parts: &SonameParts) -> Option<u32> {
    parts
        .version
        .as_ref()?
        .split('.')
        .next()?
        .parse::<u32>()
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_versioned_soname() {
        let p = parse_soname("libcudart.so.12").unwrap();
        assert_eq!(p.stem, "libcudart.so");
        assert_eq!(p.version.as_deref(), Some("12"));
        assert_eq!(major_version(&p), Some(12));
    }

    #[test]
    fn parses_multi_component_version() {
        let p = parse_soname("libcublas.so.12.4.1").unwrap();
        assert_eq!(p.stem, "libcublas.so");
        assert_eq!(p.version.as_deref(), Some("12.4.1"));
        assert_eq!(major_version(&p), Some(12));
    }

    #[test]
    fn parses_unversioned_soname() {
        let p = parse_soname("libcudnn.so").unwrap();
        assert_eq!(p.stem, "libcudnn.so");
        assert_eq!(p.version, None);
        assert_eq!(major_version(&p), None);
    }

    #[test]
    fn strips_directory_prefix() {
        let p = parse_soname("/usr/lib/libnccl.so.2").unwrap();
        assert_eq!(p.stem, "libnccl.so");
        assert_eq!(p.version.as_deref(), Some("2"));
    }

    #[test]
    fn non_shared_library_name_is_none() {
        assert!(parse_soname("kernel.ptx").is_none());
        assert!(parse_soname("README.md").is_none());
    }

    #[test]
    fn non_numeric_version_is_ignored() {
        // A non-standard suffix after .so is not treated as a version.
        let p = parse_soname("libfoo.so.alpha").unwrap();
        assert_eq!(p.stem, "libfoo.so");
        assert_eq!(p.version, None);
    }
}
