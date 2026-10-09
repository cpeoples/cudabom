//! Command-line interface definition (clap derive).
//!
//! The full command surface is specified in spec Section 10. Each subcommand's
//! behavior lives in [`crate::commands`]; this module declares only the parsed
//! shape (names, flags, help text) that clap renders for `--help`.

use clap::{Parser, Subcommand};

/// Find the CUDA your SBOM missed.
///
/// cudabom proves which NVIDIA CUDA software is actually inside an artifact and
/// turns that evidence into SBOM, advisory, and VEX data.
#[derive(Debug, Parser)]
#[command(
    name = "cudabom",
    version,
    about,
    long_about = None,
    propagate_version = true
)]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Command,

    /// Increase diagnostic detail on stderr. Repeat for more (`-vv`). This is
    /// the single knob for verbosity across every subcommand; it never changes
    /// the machine-readable output written to stdout or `--output`.
    #[arg(
        short = 'v',
        long = "verbose",
        global = true,
        action = clap::ArgAction::Count,
        conflicts_with = "quiet"
    )]
    pub(crate) verbose: u8,

    /// Suppress non-essential diagnostics on stderr, leaving only errors. Like
    /// `--verbose`, this is global and does not affect stdout output.
    #[arg(short = 'q', long = "quiet", global = true)]
    pub(crate) quiet: bool,
}

/// Top-level subcommands. See spec Section 10 for the full flag set that lands
/// with each command.
#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Scan one or more targets for CUDA components.
    Scan(ScanArgs),

    /// Scan targets and evaluate a policy, failing the build on violations.
    Gate(GateArgs),

    /// Enrich an existing CycloneDX SBOM with discovered CUDA components.
    Enrich(EnrichArgs),

    /// Emit CycloneDX VEX for a target.
    Vex(VexArgs),

    /// Reconcile a declared CycloneDX SBOM/VEX (e.g. from NGC) against the CUDA
    /// components cudabom discovers in a target.
    Reconcile(ReconcileArgs),

    /// Explain why a finding was identified.
    Explain(ExplainArgs),

    /// Manage the local advisory database.
    Db(DbArgs),

    /// Fetch the published data bundle (fingerprint DB + advisory index) into
    /// the local data directory that scans read by default.
    Update(UpdateArgs),

    /// Print the JSON Schema of cudabom's native output.
    Schema,

    /// Print version information for the tool and its data.
    Version(VersionArgs),
}

/// Arguments for `cudabom scan`.
#[derive(Debug, clap::Args)]
pub(crate) struct ScanArgs {
    /// One or more targets to scan (files or directories).
    #[arg(value_name = "TARGET", required = true)]
    pub(crate) targets: Vec<String>,

    /// Output format.
    #[arg(long, value_enum, default_value_t = OutputFormat::Table)]
    pub(crate) format: OutputFormat,

    /// Write output to a file instead of stdout.
    #[arg(short = 'o', long, value_name = "FILE")]
    pub(crate) output: Option<String>,

    /// Path to a fingerprint database (JSON) used for identification. When
    /// omitted, an empty database is used, so only structural signals produce
    /// findings.
    #[arg(long, value_name = "FILE")]
    pub(crate) db: Option<String>,

    /// Path to a local advisory index (JSON) used to correlate findings against
    /// known NVIDIA security advisories. When omitted, no advisory correlation
    /// is performed. Absence of a match is never treated as proof of safety.
    #[arg(long, value_name = "FILE")]
    pub(crate) advisories: Option<String>,

    /// When to return a non-zero exit code. `scan` is a reporting command and
    /// defaults to `none` (exit 0 on success) so identifying CUDA does not fail
    /// a build; use `found` or `affected` to opt into CI failure, or `gate` for
    /// full policy enforcement.
    #[arg(long, value_enum, default_value_t = FailOn::None)]
    pub(crate) fail_on: FailOn,

    /// List every file walked in the `table` output, including the uninteresting
    /// ones (source headers, package metadata). By default the table shows only
    /// files that carry a signal (ELF, GPU code, archives, parse errors) and
    /// collapses the rest into a one-line summary. Only affects `--format table`.
    #[arg(long)]
    pub(crate) all_files: bool,
}

/// Arguments for `cudabom gate`. Runs the scan pipeline and evaluates a policy.
#[derive(Debug, clap::Args)]
pub(crate) struct GateArgs {
    /// One or more targets to scan (files or directories).
    #[arg(value_name = "TARGET", required = true)]
    pub(crate) targets: Vec<String>,

    /// Path to a policy file (JSON). When omitted, the built-in secure default
    /// is used: fail on any `affected` advisory verdict.
    #[arg(long, value_name = "FILE")]
    pub(crate) policy: Option<String>,

    /// Path to a fingerprint database (JSON) used for identification.
    #[arg(long, value_name = "FILE")]
    pub(crate) db: Option<String>,

    /// Path to a local advisory index (JSON) used to correlate findings.
    #[arg(long, value_name = "FILE")]
    pub(crate) advisories: Option<String>,

    /// Output format for the gate decision.
    #[arg(long, value_enum, default_value_t = GateFormat::Table)]
    pub(crate) format: GateFormat,
}

/// Output formats for `cudabom gate`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
#[value(rename_all = "kebab-case")]
pub(crate) enum GateFormat {
    Table,
    Json,
}

/// Arguments for `cudabom vex`. Runs the scan pipeline, correlates advisories,
/// and emits a CycloneDX 1.6 VEX document.
#[derive(Debug, clap::Args)]
pub(crate) struct VexArgs {
    /// One or more targets to scan (files or directories).
    #[arg(value_name = "TARGET", required = true)]
    pub(crate) targets: Vec<String>,

    /// Path to a fingerprint database (JSON) used for identification.
    #[arg(long, value_name = "FILE")]
    pub(crate) db: Option<String>,

    /// Path to a local advisory index (JSON). VEX statements come from the
    /// resulting advisory verdicts; without it, the VEX document has an
    /// SBOM but no vulnerability statements.
    #[arg(long, value_name = "FILE")]
    pub(crate) advisories: Option<String>,

    /// Write output to a file instead of stdout.
    #[arg(short = 'o', long, value_name = "FILE")]
    pub(crate) output: Option<String>,
}

/// Arguments for `cudabom reconcile`. Scans targets, reads a declared CycloneDX
/// SBOM and/or VEX, and reports where the declaration and cudabom's discoveries
/// agree, and where they do not.
#[derive(Debug, clap::Args)]
pub(crate) struct ReconcileArgs {
    /// One or more targets to scan (files or directories).
    #[arg(value_name = "TARGET", required = true)]
    pub(crate) targets: Vec<String>,

    /// A declared CycloneDX SBOM (JSON) to reconcile against, e.g. the SBOM NGC
    /// publishes for an image. May be combined with `--vex`.
    #[arg(long, value_name = "FILE")]
    pub(crate) sbom: Option<String>,

    /// A declared CycloneDX VEX (JSON) to reconcile against, e.g. the VEX NGC
    /// publishes for an image. VEX statements are attached to matched
    /// components.
    #[arg(long, value_name = "FILE")]
    pub(crate) vex: Option<String>,

    /// Fetch the declared SBOM and VEX from NVIDIA NGC for this image, given as
    /// `org/repository:tag` (e.g. `nvidia/pytorch:26.01-py3`). Requires an NGC
    /// API key in `--ngc-api-key` or the `NGC_API_KEY` environment variable.
    /// This is the only networked path; `--sbom`/`--vex` files stay offline.
    #[arg(long, value_name = "ORG/REPO:TAG")]
    pub(crate) ngc_image: Option<String>,

    /// NGC API key for `--ngc-image`. Falls back to the `NGC_API_KEY`
    /// environment variable, which is preferred so the key stays out of shell
    /// history and process listings.
    #[arg(long, value_name = "KEY")]
    pub(crate) ngc_api_key: Option<String>,

    /// Path to a fingerprint database (JSON) used for identification.
    #[arg(long, value_name = "FILE")]
    pub(crate) db: Option<String>,

    /// Output format.
    #[arg(long, value_enum, default_value_t = OutputFormat::Table)]
    pub(crate) format: OutputFormat,

    /// Write output to a file instead of stdout.
    #[arg(short = 'o', long, value_name = "FILE")]
    pub(crate) output: Option<String>,
}
#[derive(Debug, clap::Args)]
pub(crate) struct EnrichArgs {
    /// The existing CycloneDX SBOM (JSON) to enrich.
    #[arg(long, value_name = "FILE")]
    pub(crate) sbom: String,

    /// One or more targets to scan for CUDA components to add.
    #[arg(value_name = "TARGET", required = true)]
    pub(crate) targets: Vec<String>,

    /// Path to a fingerprint database (JSON) used for identification.
    #[arg(long, value_name = "FILE")]
    pub(crate) db: Option<String>,

    /// Write the enriched SBOM to a file instead of stdout.
    #[arg(short = 'o', long, value_name = "FILE")]
    pub(crate) output: Option<String>,
}

/// Arguments for `cudabom explain`. Scans targets and prints the full evidence
/// chain for a single finding.
#[derive(Debug, clap::Args)]
pub(crate) struct ExplainArgs {
    /// The finding id to explain. When omitted, all findings are listed with
    /// their ids so one can be chosen.
    #[arg(long, value_name = "FINDING_ID")]
    pub(crate) id: Option<String>,

    /// One or more targets to scan (files or directories).
    #[arg(value_name = "TARGET", required = true)]
    pub(crate) targets: Vec<String>,

    /// Path to a fingerprint database (JSON) used for identification.
    #[arg(long, value_name = "FILE")]
    pub(crate) db: Option<String>,

    /// Output format.
    #[arg(long, value_enum, default_value_t = ExplainFormat::Text)]
    pub(crate) format: ExplainFormat,
}

/// Output formats for `cudabom explain`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
#[value(rename_all = "kebab-case")]
pub(crate) enum ExplainFormat {
    Text,
    Json,
}

/// Arguments for `cudabom version`.
///
/// Verbosity is controlled by the global `-v/--verbose` flag: a plain `version`
/// prints just the tool version, while `-v` adds the native schema and the
/// installed data bundle. There is deliberately no command-local flag, so the
/// one global knob governs detail everywhere.
#[derive(Debug, clap::Args)]
pub(crate) struct VersionArgs {}

/// Arguments for `cudabom update`.
#[derive(Debug, clap::Args)]
pub(crate) struct UpdateArgs {
    /// Release tag to install (e.g. `v1.2.3`). When omitted, the latest
    /// release is resolved and installed.
    #[arg(long, value_name = "TAG")]
    pub(crate) tag: Option<String>,

    /// Install into this directory instead of the resolved per-user data
    /// directory (`$CUDABOM_DATA_DIR`, `$SNAP_USER_DATA/cudabom`,
    /// `$XDG_DATA_HOME/cudabom`, or `~/.local/share/cudabom`).
    #[arg(long, value_name = "DIR")]
    pub(crate) data_dir: Option<String>,

    /// Repository owner the bundle is published from (defaults to the cudabom
    /// project).
    #[arg(long, value_name = "OWNER")]
    pub(crate) owner: Option<String>,

    /// Repository name (defaults to the cudabom project).
    #[arg(long, value_name = "REPO")]
    pub(crate) repo: Option<String>,

    /// Override the GitHub REST API base (release lookup), e.g. a mirror.
    #[arg(long, value_name = "URL")]
    pub(crate) api_url: Option<String>,

    /// Override the release-asset download base URL.
    #[arg(long, value_name = "URL")]
    pub(crate) download_url: Option<String>,

    /// Maximum download attempts per request (including the first). Default 5.
    #[arg(long, value_name = "N")]
    pub(crate) max_retries: Option<u32>,

    /// Base backoff in milliseconds for the first retry. Default 500.
    #[arg(long, value_name = "MS")]
    pub(crate) retry_base_ms: Option<u64>,

    /// Disable retries entirely (single attempt per request).
    #[arg(long)]
    pub(crate) no_retry: bool,
}

/// Arguments for `cudabom db`.
#[derive(Debug, clap::Args)]
pub(crate) struct DbArgs {
    #[command(subcommand)]
    pub(crate) command: DbCommand,
}

/// `cudabom db` subcommands.
#[derive(Debug, clap::Subcommand)]
pub(crate) enum DbCommand {
    /// Build a normalized advisory index from local CSAF documents.
    Build(DbBuildArgs),

    /// Report mapped and unmapped products from local CSAF documents.
    Status(DbStatusArgs),

    /// Fetch CSAF from upstream over the network and rebuild the index.
    Update(DbUpdateArgs),
}

/// Arguments for `cudabom db update`.
#[derive(Debug, clap::Args)]
pub(crate) struct DbUpdateArgs {
    /// Path to the product map (JSON) used to resolve CSAF products.
    #[arg(long, value_name = "FILE")]
    pub(crate) map: String,

    /// Upstream commit SHA (or ref) to fetch. Required until a default pinned
    /// revision is set in the build.
    #[arg(long, value_name = "COMMIT")]
    pub(crate) rev: String,

    /// Fetch strategy. `manifest` lists CSAF files via the Git Trees API and
    /// fetches only those; `tarball` downloads the whole repository archive.
    #[arg(long, value_enum, default_value_t = FetchModeArg::Manifest)]
    pub(crate) mode: FetchModeArg,

    /// Override the GitHub REST API base (manifest mode), e.g. a mirror.
    #[arg(long, value_name = "URL")]
    pub(crate) api_url: Option<String>,

    /// Override the raw-content base (manifest mode).
    #[arg(long, value_name = "URL")]
    pub(crate) raw_url: Option<String>,

    /// Override the codeload base URL (tarball mode).
    #[arg(long, value_name = "URL")]
    pub(crate) codeload_url: Option<String>,

    /// Repository owner (defaults to the upstream NVIDIA org).
    #[arg(long, value_name = "OWNER")]
    pub(crate) owner: Option<String>,

    /// Repository name (defaults to the upstream product-security repo).
    #[arg(long, value_name = "REPO")]
    pub(crate) repo: Option<String>,

    /// Expected sha256 (hex) of the downloaded archive (tarball mode).
    #[arg(long, value_name = "SHA256")]
    pub(crate) sha256: Option<String>,

    /// Maximum download attempts per request (including the first). Default 5.
    #[arg(long, value_name = "N")]
    pub(crate) max_retries: Option<u32>,

    /// Base backoff in milliseconds for the first retry. Default 500.
    #[arg(long, value_name = "MS")]
    pub(crate) retry_base_ms: Option<u64>,

    /// Disable retries entirely (single attempt per request).
    #[arg(long)]
    pub(crate) no_retry: bool,

    /// Write the index to this file. When omitted, printed to stdout.
    #[arg(short = 'o', long, value_name = "FILE")]
    pub(crate) output: Option<String>,
}

/// Fetch strategy for `db update`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum FetchModeArg {
    /// List CSAF files via the Git Trees API and fetch only those.
    Manifest,
    /// Download and unpack the whole-repository tarball.
    Tarball,
}

/// Arguments for `cudabom db build`.
#[derive(Debug, clap::Args)]
pub(crate) struct DbBuildArgs {
    /// Path to a CSAF document, or a directory of `*.json` CSAF documents.
    #[arg(long, value_name = "PATH")]
    pub(crate) from: String,

    /// Path to the product map (JSON) used to resolve CSAF products to cudabom
    /// component names.
    #[arg(long, value_name = "FILE")]
    pub(crate) map: String,

    /// Optional upstream commit/revision to record in the index for provenance.
    #[arg(long, value_name = "COMMIT")]
    pub(crate) source_commit: Option<String>,

    /// Write the index to this file. When omitted, the index is printed to
    /// stdout.
    #[arg(short = 'o', long, value_name = "FILE")]
    pub(crate) output: Option<String>,
}

/// Arguments for `cudabom db status`.
#[derive(Debug, clap::Args)]
pub(crate) struct DbStatusArgs {
    /// Path to a CSAF document, or a directory of `*.json` CSAF documents.
    #[arg(long, value_name = "PATH")]
    pub(crate) from: String,

    /// Path to the product map (JSON).
    #[arg(long, value_name = "FILE")]
    pub(crate) map: String,
}

/// Output formats accepted by `--format` (spec Section 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
#[value(rename_all = "kebab-case")]
pub(crate) enum OutputFormat {
    Table,
    Json,
    Cyclonedx,
    Sarif,
    Markdown,
}

/// The threshold at which `scan` returns a non-zero (Findings) exit code. `scan`
/// is a reporting command, so it defaults to `None` (always exit 0 on success);
/// CI opts in explicitly. Real policy enforcement lives in `gate`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
#[value(rename_all = "kebab-case")]
pub(crate) enum FailOn {
    /// Never fail on results (always exit 0 on success). The default.
    None,
    /// Fail when any CUDA component is identified (regardless of advisories).
    Found,
    /// Fail only when an identified component is `affected` by an advisory.
    Affected,
}
