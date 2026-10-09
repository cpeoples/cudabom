//! `cudabom version [--verbose]`.
//!
//! Prints the tool version and, with `--verbose`, the native schema version and
//! the installed data bundle (fingerprint DB + advisory index) that a scan
//! depends on. The data bundle is populated by `cudabom update`; when it is not
//! installed, that is reported plainly rather than faked.

use crate::cli::VersionArgs;
use crate::exit::ExitStatus;

/// The compiled-in tool version, from Cargo.
const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");

pub(crate) fn run(_args: &VersionArgs) -> ExitStatus {
    println!("cudabom {TOOL_VERSION}");

    if crate::verbosity::enabled(crate::verbosity::Level::Verbose) {
        println!("  native schema:   {}", cudabom_core::SCHEMA_VERSION);
        // The installed data bundle stamps its release tag in a VERSION file;
        // report it (and whether each artifact is present) so users can see
        // what `cudabom update` gave them.
        if let Some(dir) = crate::datadir::data_dir() {
            let bundle = std::fs::read_to_string(dir.join("VERSION"))
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty());
            match bundle {
                Some(tag) => println!("  data bundle:     {tag} ({})", dir.display()),
                None => println!(
                    "  data bundle:     not installed (run `cudabom update`) [{}]",
                    dir.display()
                ),
            }
            let db = if crate::datadir::default_db_dir().is_some() {
                "present"
            } else {
                "not built"
            };
            let adv = if crate::datadir::default_advisories_file().is_some() {
                "present"
            } else {
                "not built"
            };
            println!("  fingerprint db:  {db}");
            println!("  advisory index:  {adv}");
        } else {
            println!("  data bundle:     no data directory resolved");
            println!("  fingerprint db:  not built");
            println!("  advisory index:  not built");
        }
    }

    ExitStatus::Success
}
