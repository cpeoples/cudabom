//! `cudabom update`: fetch the published data bundle into the local data dir.
//!
//! Downloads the `cudabom-data-<tag>.tar.gz` release asset from the public
//! cudabom repository (default: the latest release), verifies it against the
//! `.tar.gz.sha256` sidecar, and unpacks it into the per-user data directory
//! that `scan`/`gate`/`vex`/etc. read by default. This is the only way a
//! binary-only install (crates.io, Snap, release archive) obtains the
//! fingerprint database and advisory index without cloning the repository.

use cudabom_advisory::{update_data, DataSource};

use crate::cli::UpdateArgs;
use crate::datadir;
use crate::exit::ExitStatus;
use crate::verbosity::status;

pub(crate) fn run(args: &UpdateArgs) -> ExitStatus {
    // Resolve where to install: an explicit --data-dir, else the standard
    // per-user location.
    let dest = if let Some(dir) = args.data_dir.clone() {
        std::path::PathBuf::from(dir)
    } else if let Some(dir) = datadir::data_dir() {
        dir
    } else {
        eprintln!(
            "cudabom: could not determine a data directory (no CUDABOM_DATA_DIR, \
             SNAP_USER_DATA, XDG_DATA_HOME, or HOME); pass --data-dir <DIR>"
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
            eprintln!("cudabom: update failed: {err}");
            ExitStatus::Input
        }
    }
}
