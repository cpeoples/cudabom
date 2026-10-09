//! Subcommand implementations.
//!
//! Each command lives in its own module and returns an [`crate::exit::ExitStatus`]
//! so the entry point can map outcomes onto the documented exit codes without
//! any command calling `std::process::exit` directly.

pub(crate) mod composition;
pub(crate) mod db;
pub(crate) mod enrich;
pub(crate) mod explain;
pub(crate) mod gate;
pub(crate) mod ngc;
pub(crate) mod pipeline;
pub(crate) mod reconcile;
pub(crate) mod scan;
pub(crate) mod schema;
pub(crate) mod update;
pub(crate) mod version;
pub(crate) mod vex;

/// Unwrap an input-loading result, printing the error as a `cudabom:`
/// diagnostic and converting it to [`crate::exit::ExitStatus::Input`] on
/// failure. Lets a command use `?` instead of repeating the
/// match-print-return boilerplate for each loaded input (database, advisory
/// index, policy).
pub(crate) fn or_input_error<T>(result: anyhow::Result<T>) -> Result<T, crate::exit::ExitStatus> {
    result.map_err(|err| {
        eprintln!("cudabom: {err}");
        crate::exit::ExitStatus::Input
    })
}

/// Build a download retry policy from the shared `--no-retry` / `--max-retries`
/// / `--retry-base-ms` flags, layering any tuning overrides on the conservative
/// default. Shared by the `db update` and `update` commands.
pub(crate) fn build_retry_policy(
    no_retry: bool,
    max_retries: Option<u32>,
    retry_base_ms: Option<u64>,
) -> cudabom_fetch::RetryPolicy {
    if no_retry {
        return cudabom_fetch::RetryPolicy::none();
    }
    let mut policy = cudabom_fetch::RetryPolicy::default();
    if let Some(n) = max_retries {
        policy.max_attempts = n.max(1);
    }
    if let Some(ms) = retry_base_ms {
        policy.base = std::time::Duration::from_millis(ms);
    }
    policy
}

/// Write `text` to the `--output` file, or print it to stdout with a trailing
/// newline. The single "emit result" tail shared by every command that honors
/// `--output`, so file-vs-stdout behavior cannot drift between them.
pub(crate) fn emit(output: Option<&str>, text: &str) -> Result<(), crate::exit::ExitStatus> {
    let Some(path) = output else {
        println!("{text}");
        return Ok(());
    };
    std::fs::write(path, text).map_err(|e| {
        eprintln!("cudabom: writing {path}: {e}");
        crate::exit::ExitStatus::Internal
    })
}
