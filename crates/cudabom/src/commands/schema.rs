//! `cudabom schema`.
//!
//! Prints the JSON Schema for cudabom's native output format so downstream
//! consumers can validate `--format json`. It currently advertises only the
//! schema version; a full model-derived schema is intentionally deferred rather
//! than hand-maintained, since a hand-written schema would drift from the
//! `cudabom-core` types it is meant to describe.

use crate::exit::ExitStatus;

pub(crate) fn run() -> ExitStatus {
    // Advertise the schema version without hand-describing the full model: a
    // hand-maintained schema would drift from `cudabom-core`. The `$id` carries
    // the version so consumers can branch on it.
    let schema = serde_json::json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": format!(
            "https://cpeoples.github.io/cudabom/schema/{}/cudabom.schema.json",
            cudabom_core::SCHEMA_VERSION
        ),
        "title": "cudabom native output",
        "description": "Version-only schema: validates the schemaVersion field. A full model-derived schema is published separately to avoid hand-maintained drift.",
        "type": "object",
        "properties": {
            "schemaVersion": {
                "type": "string",
                "const": cudabom_core::SCHEMA_VERSION
            }
        },
        "required": ["schemaVersion"]
    });

    // Pretty-print deterministically.
    match serde_json::to_string_pretty(&schema) {
        Ok(text) => {
            println!("{text}");
            ExitStatus::Success
        }
        Err(err) => {
            eprintln!("error: failed to render schema: {err}");
            ExitStatus::Internal
        }
    }
}
