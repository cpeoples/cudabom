//! xtask: cudabom's workspace automation entry point.
//!
//! Run via the `cargo xtask <task>` alias (see `.cargo/config.toml`). Houses
//! developer/CI tasks that should not ship in the released binary: deriving the
//! fingerprint database from official NVIDIA redistributables, managing the
//! fingerprint corpus, and (later) fixtures/eval/benchmarks.
//!
//! Network access here uses the same verified, retrying `cudabom-fetch`
//! primitive as `db update`, so the corpus fetch inherits backoff and
//! rate-limit handling.

mod apt;
mod bundle;
mod corpus;
mod cuda_repos;
mod distribution_discover;
mod eval_distribution;
mod eval_groundtruth;
mod eval_tools;
mod fingerprints;
mod jetson;
mod product_map;
mod release_version;
mod rpm;
mod sources;
mod verbosity;

use std::process::ExitCode;

/// Tasks the xtask runner knows about.
const TASKS: &[(&str, &str)] = &[
    (
        "fixtures build",
        "compile CUDA C++ test fixtures (needs nvcc) (not yet implemented)",
    ),
    (
        "corpus lock",
        "derive fingerprints/corpus.<version>.lock.json from a redist manifest",
    ),
    (
        "corpus discover",
        "enumerate NVIDIA's redist manifests and lock any new releases",
    ),
    (
        "corpus fetch",
        "download + verify corpus archives into ./corpus (gitignored)",
    ),
    (
        "fingerprints build",
        "derive fingerprint shards from redist manifests (+ unpacked corpus)",
    ),
    (
        "fingerprints backfill",
        "enrich committed manifest-only shards with the binary layer (bounded batch)",
    ),
    (
        "product-map",
        "generate advisories/product-map.json from component profiles (--check/--write)",
    ),
    (
        "bundle",
        "package committed data into cudabom-data-<tag>.tar.gz (+ .sha256)",
    ),
    (
        "release-version",
        "bump the release version in Cargo.toml (the single place): <x.y.z> | --check",
    ),
    ("eval", "run corpus precision/recall evaluation"),
    (
        "distribution discover",
        "find new in-the-wild CUDA wheels on PyPI (metadata-only; --write pins them)",
    ),
    (
        "jetson discover",
        "synthesize redist-shaped manifests for Jetson (L4T/JetPack) CUDA .deb packages",
    ),
    (
        "cuda-repos discover",
        "synthesize redist-shaped manifests for per-distro CUDA .deb / .rpm packages (compute/cuda/repos)",
    ),
];

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    // Pull the global -v/-q flags out first so they can appear anywhere and do
    // not interfere with task keyword matching or per-task flag parsing.
    let args = verbosity::take_flags(args);
    let task = args.join(" ");
    if task.is_empty() {
        print_help();
        return ExitCode::SUCCESS;
    }

    let result = if task.starts_with("fingerprints build") {
        fingerprints::build(task_args(&args, "fingerprints build"))
    } else if task.starts_with("fingerprints backfill") {
        fingerprints::backfill(task_args(&args, "fingerprints backfill"))
    } else if task.starts_with("product-map") {
        product_map::run(task_args(&args, "product-map"))
    } else if task.starts_with("release-version") {
        release_version::run(task_args(&args, "release-version"))
    } else if task.starts_with("corpus lock") {
        corpus::lock(task_args(&args, "corpus lock"))
    } else if task.starts_with("corpus discover") {
        corpus::discover(task_args(&args, "corpus discover"))
    } else if task.starts_with("corpus fetch") {
        corpus::fetch(task_args(&args, "corpus fetch"))
    } else if task.starts_with("bundle") {
        bundle::build(task_args(&args, "bundle"))
    } else if task.starts_with("distribution discover") {
        distribution_discover::run(task_args(&args, "distribution discover"))
    } else if task.starts_with("jetson discover") {
        jetson::discover(task_args(&args, "jetson discover"))
    } else if task.starts_with("cuda-repos discover") {
        cuda_repos::discover(task_args(&args, "cuda-repos discover"))
    } else if task.starts_with("eval") {
        eval_groundtruth::run(task_args(&args, "eval"))
    } else {
        eprintln!("xtask: unknown task '{task}'.");
        eprintln!();
        print_help();
        return ExitCode::FAILURE;
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("xtask: {e:#}");
            ExitCode::FAILURE
        }
    }
}

/// The arguments following a (one- or two-word) task keyword. The offset is
/// derived from the keyword itself so it cannot drift from the `starts_with`
/// literal used to dispatch.
fn task_args<'a>(args: &'a [String], keyword: &str) -> &'a [String] {
    &args[keyword.split_whitespace().count()..]
}

/// Read the value following `name` in `args` (e.g. `--from <value>`).
pub(crate) fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

/// Collect every value following a repeated flag (e.g. `--platform a --platform
/// b`), in order. Returns an empty vector when the flag is absent; callers that
/// want a default substitute one for the empty case.
pub(crate) fn repeated_flag(args: &[String], name: &str) -> Vec<String> {
    args.iter()
        .zip(args.iter().skip(1))
        .filter(|(a, _)| a.as_str() == name)
        .map(|(_, v)| v.clone())
        .collect()
}

/// True if the boolean flag `name` is present in `args`.
pub(crate) fn has_flag(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

fn print_help() {
    println!("cargo xtask <task>");
    println!();
    println!("Tasks:");
    for (name, desc) in TASKS {
        println!("  {name:<22} {desc}");
    }
    println!();
    println!(
        "corpus lock   --manifest <redistrib.json> --out fingerprints/corpus.<release>.lock.json"
    );
    println!("              [--base-url <url>] [--platform linux-x86_64 ...] [--limit N]");
    println!(
        "corpus discover [--product <name>|all] [--base-url <url>] [--fixtures fixtures/redist]"
    );
    println!("              [--out fingerprints] [--fingerprints fingerprints/cuda]");
    println!("              [--platform ...] [--limit N] [--json] [--dry-run] [retry flags]");
    println!(
        "corpus fetch  [--lock fingerprints (dir of shards) | <file>] [--out corpus] [--dry-run]"
    );
    println!("              [--max-retries N] [--retry-base-ms MS] [--no-retry]");
    println!("fingerprints build [--from fixtures/redist] [--out fingerprints/cuda]");
    println!("              [--corpus corpus] [--jobs N] [--force] [--keep-downloads]");
    println!("fingerprints backfill [--limit N] [--jobs N] [--corpus corpus]");
    println!("              # enrich committed manifest-only shards with the binary layer");
    println!("product-map   [--check | --write] [--out advisories/product-map.json]");
    println!("release-version <x.y.z> | --check   # the one place to bump the release version");
    println!("bundle        --tag <tag> [--out dist] [--fingerprints fingerprints/cuda]");
    println!("              [--advisories advisories/index.json]");
    println!("eval          [--target <file>]... [--targets <dir>] [--out target]");
    println!("              [--db fingerprints] [--advisories advisories/index.json]");
    println!("              [--write-comparison]   # splice results into docs/comparison.md");
    println!(
        "              [--container-image <ref>]   # also measure a container row (needs docker)"
    );
    println!(
        "eval --distribution [--manifest eval/distribution.manifest.json] [--download] [--stream]"
    );
    println!("              [--tier a|b] [--kind wheel,conda,...] [--db ...] [--advisories ...]");
    println!(
        "distribution discover [--manifest eval/distribution.manifest.json] [--limit N] [--project <name>]"
    );
    println!(
        "              [--write] [--json]   # metadata-only PyPI crawl; --write pins new wheels"
    );
    println!(
        "jetson discover [--release r36.4 ...] [--base-url <url>] [--fixtures fixtures/redist/jetson]"
    );
    println!("              [--out fingerprints/jetson] [--json] [--dry-run] [retry flags]");
    println!(
        "cuda-repos discover [--distro ubuntu2404 ...] [--arch x86_64 ...] [--base-url <url>]"
    );
    println!(
        "              [--fixtures fixtures/redist/cuda-repos] [--out fingerprints/cuda-repos]"
    );
    println!("              [--limit N] [--json] [--dry-run] [retry flags]");
    println!();
    println!("Global: -v/--verbose (repeatable), -q/--quiet control diagnostic output.");
}
