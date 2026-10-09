//! `cargo xtask release-version <x.y.z>`: bump the release version in the one
//! place humans edit, atomically updating every site Cargo requires to agree.
//!
//! Cargo gives us *one* logical version (`[workspace.package] version`, inherited
//! by every crate via `version.workspace = true`), but it also requires each
//! internal path dependency in `[workspace.dependencies]` to repeat that version
//! so the tree publishes cleanly to crates.io later (`cudabom-core = { path =
//! "...", version = "x.y.z" }`). Those repeats are the classic foot-gun: miss one
//! on release and `cargo publish` fails (or worse, resolves an old version).
//!
//! This task is the single source of truth for *performing* a bump: it rewrites
//! `[workspace.package] version` and every internal `cudabom-* = { ..., version =
//! "..." }` pin in the root `Cargo.toml` to the same value, in one pass, and
//! verifies afterward that no internal version pin disagrees. It does not touch
//! crate-level manifests (they inherit) or `SCHEMA_VERSION` (the output contract,
//! intentionally decoupled from the release version).

use anyhow::{bail, Context, Result};

use crate::verbosity::status;

/// Root workspace manifest: the single file this task edits.
const MANIFEST: &str = "Cargo.toml";

/// `cargo xtask release-version <x.y.z> [--check]`
///
/// With `--check` (or no version), reports the current version and verifies all
/// internal pins agree, without writing. With a version argument, rewrites every
/// version site to that value.
pub(crate) fn run(args: &[String]) -> Result<()> {
    let check_only = crate::has_flag(args, "--check");
    let target = args.iter().find(|a| !a.starts_with("--"));

    let original =
        std::fs::read_to_string(MANIFEST).with_context(|| format!("reading {MANIFEST}"))?;
    let current = workspace_package_version(&original)
        .context("could not find [workspace.package] version in Cargo.toml")?;

    match target {
        None => {
            status!("xtask: current release version is {current}");
            verify_pins_agree(&original, &current)?;
            status!("xtask: all internal version pins agree with {current}");
            Ok(())
        }
        Some(_) if check_only => {
            // `--check` is a verify-only mode; ignore any accidental positional.
            verify_pins_agree(&original, &current)?;
            status!("xtask: version is {current}; all internal pins agree");
            Ok(())
        }
        Some(new_version) => {
            validate_semver(new_version)?;
            let updated = rewrite_versions(&original, new_version)?;
            std::fs::write(MANIFEST, &updated).with_context(|| format!("writing {MANIFEST}"))?;
            // Prove the write is internally consistent before returning success.
            verify_pins_agree(&updated, new_version)?;
            status!("xtask: release version bumped {current} -> {new_version}");
            status!("xtask: run `cargo update -w` to refresh Cargo.lock, then commit");
            Ok(())
        }
    }
}

/// Extract the value of `version = "..."` under the real `[workspace.package]`
/// section header. Scans line-by-line (so a mention of the section name inside a
/// comment never matches) and reads the first `version` key before the next
/// section header.
fn workspace_package_version(manifest: &str) -> Option<String> {
    let mut in_section = false;
    for line in manifest.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_section = trimmed == "[workspace.package]";
            continue;
        }
        if in_section {
            if let Some(rest) = trimmed.strip_prefix("version") {
                if let Some(v) = extract_quoted(rest) {
                    return Some(v);
                }
            }
        }
    }
    None
}

/// Rewrite the workspace package version and every internal `cudabom-*` path-dep
/// version pin to `new_version`.
fn rewrite_versions(manifest: &str, new_version: &str) -> Result<String> {
    let mut out = String::with_capacity(manifest.len());
    let mut in_workspace_package = false;
    let mut bumped_package = false;
    let mut bumped_pins = 0usize;

    for line in manifest.lines() {
        let trimmed = line.trim_start();
        // Track whether we're inside [workspace.package] (where the bare
        // `version = "..."` lives).
        if trimmed.starts_with('[') {
            in_workspace_package = trimmed.starts_with("[workspace.package]");
        }

        if in_workspace_package && trimmed.starts_with("version") && trimmed.contains('=') {
            out.push_str(&replace_quoted(line, new_version));
            out.push('\n');
            bumped_package = true;
            continue;
        }

        // Internal path-dep pin: `cudabom-foo = { path = "...", version = "..." }`.
        if trimmed.starts_with("cudabom-")
            && trimmed.contains("path")
            && trimmed.contains("version")
        {
            out.push_str(&replace_pin_version(line, new_version));
            out.push('\n');
            bumped_pins += 1;
            continue;
        }

        out.push_str(line);
        out.push('\n');
    }

    if !bumped_package {
        bail!("did not find [workspace.package] version to rewrite");
    }
    if bumped_pins == 0 {
        bail!("found no internal cudabom-* path-dep version pins to rewrite");
    }
    status!("xtask: rewrote package version + {bumped_pins} internal pin(s)");
    Ok(out)
}

/// Verify every internal `cudabom-*` path-dep pin equals `expected`.
fn verify_pins_agree(manifest: &str, expected: &str) -> Result<()> {
    for line in manifest.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("cudabom-")
            && trimmed.contains("path")
            && trimmed.contains("version")
        {
            let pin = pin_version(line)
                .with_context(|| format!("parsing version pin from: {}", line.trim()))?;
            if pin != expected {
                bail!(
                    "internal version pin disagrees: {} pins {pin}, expected {expected}",
                    trimmed.split('=').next().unwrap_or(trimmed).trim()
                );
            }
        }
    }
    Ok(())
}

/// Replace the first quoted string on a line with `value`, preserving the key
/// and any `=`/whitespace before the quote.
fn replace_quoted(line: &str, value: &str) -> String {
    match (line.find('"'), line.rfind('"')) {
        (Some(a), Some(b)) if b > a => format!("{}{value}{}", &line[..=a], &line[b..]),
        _ => line.to_string(),
    }
}

/// Replace only the `version = "..."` segment inside a path-dep line, leaving the
/// `path = "..."` untouched.
fn replace_pin_version(line: &str, value: &str) -> String {
    let Some(vpos) = line.find("version") else {
        return line.to_string();
    };
    let (head, tail) = line.split_at(vpos);
    // `tail` starts at `version`; replace the quoted value within it.
    format!("{head}{}", replace_quoted(tail, value))
}

/// Extract the `version = "..."` value from a path-dep line.
fn pin_version(line: &str) -> Option<String> {
    let vpos = line.find("version")?;
    extract_quoted(&line[vpos..])
}

/// Pull the first double-quoted substring out of `s`.
fn extract_quoted(s: &str) -> Option<String> {
    let a = s.find('"')?;
    let rest = &s[a + 1..];
    let b = rest.find('"')?;
    Some(rest[..b].to_string())
}

/// Reject anything that is not a plain `MAJOR.MINOR.PATCH` (optionally with a
/// `-pre`/`+build` suffix). Keeps the one bump path from writing a typo.
fn validate_semver(v: &str) -> Result<()> {
    let core = v.split(['-', '+']).next().unwrap_or(v);
    let parts: Vec<&str> = core.split('.').collect();
    let ok = parts.len() == 3
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()));
    if !ok {
        bail!("'{v}' is not a MAJOR.MINOR.PATCH version");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
[workspace.package]
version = "0.0.0"
edition = "2021"

[workspace.dependencies]
cudabom-core = { path = "crates/cudabom-core", version = "0.0.0" }
cudabom-fetch = { path = "crates/cudabom-fetch", version = "0.0.0" }
anyhow = "1"
serde = { version = "1", features = ["derive"] }
"#;

    #[test]
    fn reads_workspace_package_version() {
        assert_eq!(workspace_package_version(SAMPLE).as_deref(), Some("0.0.0"));
    }

    #[test]
    fn rewrites_package_and_pins_only() {
        let out = rewrite_versions(SAMPLE, "0.2.0").unwrap();
        assert_eq!(workspace_package_version(&out).as_deref(), Some("0.2.0"));
        // Both internal pins moved.
        assert!(
            out.contains(r#"cudabom-core = { path = "crates/cudabom-core", version = "0.2.0" }"#)
        );
        assert!(
            out.contains(r#"cudabom-fetch = { path = "crates/cudabom-fetch", version = "0.2.0" }"#)
        );
        // Third-party dep versions are untouched.
        assert!(out.contains(r#"anyhow = "1""#));
        assert!(out.contains(r#"serde = { version = "1", features = ["derive"] }"#));
        // The write is internally consistent.
        verify_pins_agree(&out, "0.2.0").unwrap();
    }

    #[test]
    fn verify_detects_a_disagreeing_pin() {
        let drifted = SAMPLE.replace(
            r#"cudabom-fetch = { path = "crates/cudabom-fetch", version = "0.0.0" }"#,
            r#"cudabom-fetch = { path = "crates/cudabom-fetch", version = "9.9.9" }"#,
        );
        assert!(verify_pins_agree(&drifted, "0.0.0").is_err());
    }

    #[test]
    fn validates_semver_shape() {
        assert!(validate_semver("1.2.3").is_ok());
        assert!(validate_semver("0.0.0").is_ok());
        assert!(validate_semver("1.2.3-rc.1").is_ok());
        assert!(validate_semver("1.2").is_err());
        assert!(validate_semver("1.2.x").is_err());
        assert!(validate_semver("v1.2.3").is_err());
    }

    #[test]
    fn committed_manifest_pins_all_agree() {
        // The real workspace Cargo.toml must always be internally consistent.
        // Tests run with CWD at the xtask crate dir, so resolve the workspace
        // root manifest relative to this source file.
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("xtask has a parent dir")
            .join(MANIFEST);
        let manifest = std::fs::read_to_string(&root)
            .unwrap_or_else(|e| panic!("reading {}: {e}", root.display()));
        let v = workspace_package_version(&manifest).expect("workspace package version");
        verify_pins_agree(&manifest, &v).unwrap();
    }
}
