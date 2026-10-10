//! `cudabom update`: fetch the published data bundle into the local data dir.
//!
//! Downloads the `cudabom-data-<tag>.tar.gz` release asset from the public
//! cudabom repository (default: the latest release), verifies it against the
//! `.tar.gz.sha256` sidecar, and unpacks it into the per-user data directory
//! that `scan`/`gate`/`vex`/etc. read by default. This is the only way a
//! binary-only install (crates.io, Snap, release archive) obtains the
//! fingerprint database and advisory index without cloning the repository.

use cudabom_advisory::{list_release_tags, update_data, DataSource, FetchError};

use crate::cli::UpdateArgs;
use crate::datadir;
use crate::exit::ExitStatus;
use crate::verbosity::{detail, status};

/// Cap on release tags listed after a missing-release error, newest first, to
/// keep output bounded.
const MAX_LISTED_TAGS: usize = 10;

pub(crate) fn run(args: &UpdateArgs) -> ExitStatus {
    // Resolve where to install: an explicit --data-dir, else the standard
    // per-user location.
    let dest = if let Some(dir) = args.data_dir.clone() {
        std::path::PathBuf::from(dir)
    } else if let Some(dir) = datadir::data_dir() {
        dir
    } else {
        eprintln!(
            "cudabom: could not determine a data directory (none of {} are set); \
             pass --data-dir <DIR>",
            datadir::resolution_sources()
        );
        return ExitStatus::Input;
    };

    let defaults = DataSource::default_public();
    let source = DataSource {
        api_base: args.api_url.clone().unwrap_or(defaults.api_base),
        download_base: args.download_url.clone().unwrap_or(defaults.download_base),
        owner: args.owner.clone().unwrap_or(defaults.owner),
        repo: args.repo.clone().unwrap_or(defaults.repo),
        tag: args.tag.clone(),
        retry: super::build_retry_policy(args.no_retry, args.max_retries, args.retry_base_ms),
    };

    match &source.tag {
        Some(tag) => status!("cudabom: fetching data bundle for release {tag}"),
        None => status!("cudabom: fetching data bundle for the latest release"),
    }

    match update_data(&source, &dest) {
        Ok(installed) => {
            status!(
                "cudabom: installed data bundle {} ({} file(s)) into {}",
                installed.tag,
                installed.files,
                installed.dir.display()
            );
            ExitStatus::Success
        }
        Err(err) => {
            report_update_error(&err, &source);
            ExitStatus::Input
        }
    }
}

/// Print an actionable error for a failed data-bundle update, keeping the raw
/// URL and HTTP status for `-v`.
fn report_update_error(err: &FetchError, source: &DataSource) {
    let owner = &source.owner;
    let repo = &source.repo;
    match (err.http_status(), source.tag.as_deref()) {
        // A missing release is actionable: name it, then list the tags that do
        // exist so the user can pin one.
        (Some(404), None) => {
            eprintln!("cudabom: no published data releases found for {owner}/{repo}.");
            report_available_tags(source);
        }
        (Some(404), Some(tag)) => {
            eprintln!("cudabom: release {tag} has no data bundle for {owner}/{repo}.");
            report_available_tags(source);
        }
        _ => eprintln!("cudabom: could not update the data bundle: {err}"),
    }
    detail!("cudabom: underlying error: {err}");
}

/// List available release tags (best effort) to accompany a 404. A failure to
/// list is non-fatal: the primary error has already been reported.
fn report_available_tags(source: &DataSource) {
    match list_release_tags(source) {
        Ok(tags) if !tags.is_empty() => {
            eprintln!("cudabom: available releases (newest first):");
            for tag in tags.iter().take(MAX_LISTED_TAGS) {
                eprintln!("  {tag}");
            }
            if tags.len() > MAX_LISTED_TAGS {
                eprintln!("  ... and {} more", tags.len() - MAX_LISTED_TAGS);
            }
            eprintln!("cudabom: install one with --tag <TAG>.");
        }
        Ok(_) => {
            eprintln!("cudabom: no releases are published yet; check back after one is cut.");
        }
        Err(err) => {
            eprintln!("cudabom: could not list available releases.");
            detail!("cudabom: listing releases failed: {err}");
        }
    }
}
