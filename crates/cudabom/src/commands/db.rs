//! `cudabom db`: manage the local advisory database.
//!
//! - `db build` ingests local CSAF documents into a normalized advisory index.
//! - `db status` reports which products mapped and which did not.
//! - `db update` fetches CSAF from upstream (NVIDIA product-security) and feeds
//!   the same ingestion path. Because NVIDIA publishes no CSAF discovery
//!   manifest, cudabom synthesizes one from the repository tree (default) or
//!   downloads the whole-repository tarball.
//!
//! `db build`/`db status` are fully offline and deterministic; only `db update`
//! touches the network.

use cudabom_advisory::{ingest, update, FetchMode, FetchSource, Ingest, ProductMap};

use crate::cli::{DbArgs, DbBuildArgs, DbCommand, DbStatusArgs, DbUpdateArgs, FetchModeArg};
use crate::exit::ExitStatus;
use crate::verbosity::status;

pub(crate) fn run(args: &DbArgs) -> ExitStatus {
    match &args.command {
        DbCommand::Build(a) => build(a),
        DbCommand::Status(a) => status(a),
        DbCommand::Update(a) => update_cmd(a),
    }
}

fn build(args: &DbBuildArgs) -> ExitStatus {
    let map = match load_map(&args.map) {
        Ok(map) => map,
        Err(status) => return status,
    };
    let documents = match load_csaf(&args.from) {
        Ok(docs) => docs,
        Err(status) => return status,
    };

    let result = match ingest(&documents, &map, args.source_commit.clone()) {
        Ok(result) => result,
        Err(err) => {
            eprintln!("cudabom: {err}");
            return ExitStatus::Input;
        }
    };

    // Surface unmapped products on stderr so they are visible but do not
    // pollute the index written to stdout/file.
    report_unmapped(&result);

    let json = match result.index.to_json() {
        Ok(json) => json,
        Err(err) => {
            eprintln!("cudabom: {err}");
            return ExitStatus::Internal;
        }
    };

    if let Err(status) = super::emit(args.output.as_deref(), &json) {
        return status;
    }
    if let Some(path) = &args.output {
        status!(
            "cudabom: wrote {} advisory record(s) to {}",
            result.index.advisories.len(),
            path
        );
    }

    ExitStatus::Success
}

/// `db update`: fetch CSAF from upstream, verify, and build the index.
fn update_cmd(args: &DbUpdateArgs) -> ExitStatus {
    let map = match load_map(&args.map) {
        Ok(map) => map,
        Err(status) => return status,
    };

    let mode = match args.mode {
        FetchModeArg::Manifest => FetchMode::Manifest,
        FetchModeArg::Tarball => FetchMode::Tarball,
    };

    let defaults = FetchSource::default_nvidia();
    let retry = super::build_retry_policy(args.no_retry, args.max_retries, args.retry_base_ms);
    let source = FetchSource {
        mode,
        codeload_base: args.codeload_url.clone().unwrap_or(defaults.codeload_base),
        api_base: args.api_url.clone().unwrap_or(defaults.api_base),
        raw_base: args.raw_url.clone().unwrap_or(defaults.raw_base),
        owner: args.owner.clone().unwrap_or(defaults.owner),
        repo: args.repo.clone().unwrap_or(defaults.repo),
        rev: args.rev.clone(),
        expected_sha256: args.sha256.clone(),
        retry,
    };

    match source.mode {
        FetchMode::Manifest => {
            status!("cudabom: listing CSAF via {}", source.tree_url());
        }
        FetchMode::Tarball => {
            status!("cudabom: fetching {}", source.tarball_url());
        }
    }

    let result = match update(&source, &map) {
        Ok(result) => result,
        Err(err) => {
            eprintln!("cudabom: {err}");
            return ExitStatus::Input;
        }
    };

    report_unmapped(&result);
    report_integrity_skipped(&result);

    let json = match result.index.to_json() {
        Ok(json) => json,
        Err(err) => {
            eprintln!("cudabom: {err}");
            return ExitStatus::Internal;
        }
    };

    if let Err(status) = super::emit(args.output.as_deref(), &json) {
        return status;
    }
    if let Some(path) = &args.output {
        status!(
            "cudabom: wrote {} advisory record(s) to {} (rev {})",
            result.index.advisories.len(),
            path,
            source.rev
        );
    }

    ExitStatus::Success
}

fn status(args: &DbStatusArgs) -> ExitStatus {
    let map = match load_map(&args.map) {
        Ok(map) => map,
        Err(status) => return status,
    };
    let documents = match load_csaf(&args.from) {
        Ok(docs) => docs,
        Err(status) => return status,
    };

    let result = match ingest(&documents, &map, None) {
        Ok(result) => result,
        Err(err) => {
            eprintln!("cudabom: {err}");
            return ExitStatus::Input;
        }
    };

    println!("advisories mapped: {}", result.index.advisories.len());
    if result.unmapped.is_empty() {
        println!("unmapped products: none");
    } else {
        println!("unmapped products ({}):", result.unmapped.len());
        for product in &result.unmapped {
            println!("  {product}");
        }
        println!("\nadd these to the product map to include their advisories.");
    }
    ExitStatus::Success
}

fn report_unmapped(result: &Ingest) {
    if !result.unmapped.is_empty() {
        status!(
            "cudabom: {} unmapped product(s) (run `db status` to list them):",
            result.unmapped.len()
        );
        for product in &result.unmapped {
            status!("  {product}");
        }
    }
}

/// Report CSAF documents skipped because their upstream `.sha256` sidecar was
/// stale (present but mismatching). These are loud but non-fatal: the pinned
/// commit SHA still anchors integrity, and skipping one bad sidecar is better
/// than aborting an entire refresh.
fn report_integrity_skipped(result: &Ingest) {
    if !result.integrity_skipped.is_empty() {
        status!(
            "cudabom: {} CSAF document(s) skipped due to a stale upstream .sha256 sidecar:",
            result.integrity_skipped.len()
        );
        for entry in &result.integrity_skipped {
            status!("  {entry}");
        }
    }
}

fn load_map(path: &str) -> Result<ProductMap, ExitStatus> {
    let bytes = std::fs::read(path).map_err(|e| {
        eprintln!("cudabom: cannot read product map {path}: {e}");
        ExitStatus::Input
    })?;
    ProductMap::from_json(&bytes).map_err(|e| {
        eprintln!("cudabom: {e}");
        ExitStatus::Input
    })
}

/// Load CSAF documents from a file or a directory of `*.json` files.
fn load_csaf(path: &str) -> Result<Vec<Vec<u8>>, ExitStatus> {
    let p = std::path::Path::new(path);
    let meta = std::fs::metadata(p).map_err(|e| {
        eprintln!("cudabom: cannot access {path}: {e}");
        ExitStatus::Input
    })?;

    if meta.is_file() {
        let bytes = std::fs::read(p).map_err(|e| {
            eprintln!("cudabom: cannot read {path}: {e}");
            ExitStatus::Input
        })?;
        return Ok(vec![bytes]);
    }

    // Directory: read every top-level `*.json` file, in sorted order for
    // deterministic ingestion.
    let mut entries: Vec<std::path::PathBuf> = std::fs::read_dir(p)
        .map_err(|e| {
            eprintln!("cudabom: cannot read directory {path}: {e}");
            ExitStatus::Input
        })?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("json"))
        .collect();
    entries.sort();

    if entries.is_empty() {
        eprintln!("cudabom: no *.json CSAF documents found in {path}");
        return Err(ExitStatus::Input);
    }

    let mut documents = Vec::with_capacity(entries.len());
    for entry in entries {
        let bytes = std::fs::read(&entry).map_err(|e| {
            eprintln!("cudabom: cannot read {}: {e}", entry.display());
            ExitStatus::Input
        })?;
        documents.push(bytes);
    }
    Ok(documents)
}
