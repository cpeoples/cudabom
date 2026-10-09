# CLI reference

The full, always-current flag set is generated from `cudabom --help` for every
subcommand and published on the documentation site under
[CLI reference](https://cpeoples.github.io/cudabom/cli/). Run `cudabom <command>
--help` locally for the same text. This page is the orientation map: what each
command is for and how they fit together.

## Commands

| Command | What it does |
|---|---|
| `scan` | Identify the CUDA components inside one or more targets and (with `--advisories`) correlate them to NVIDIA bulletins. The default reporting command. |
| `gate` | Run the scan, then evaluate a [policy](policy.md) and fail the build on violations. Use when you need more than a single threshold. |
| `enrich` | Add the CUDA components a target contains to an existing CycloneDX SBOM, preserving the input and skipping components it already lists. |
| `vex` | Emit a CycloneDX 1.6 VEX document: an SBOM of the identified components plus the advisory verdicts as VEX statements. |
| `reconcile` | Compare what a declared SBOM/VEX claims (e.g. an NGC image's) against what cudabom discovers, reporting matches, mismatches, and gaps. |
| `explain` | Print the full evidence chain behind a single finding, so a reviewer can see exactly why it was identified. |
| `db` | Manage the local advisory index: `build` (offline, from CSAF files), `status` (mapped vs. unmapped products), `update` (fetch CSAF over the network). |
| `update` | Install or refresh the published data bundle (fingerprint database + advisory index) into the per-user data directory. |
| `schema` | Print the JSON Schema for cudabom's native `--format json` output. |
| `version` | Print the tool version; `-v` adds the native schema version and the installed data bundle. |

## Output formats

`scan` and `reconcile` accept `--format table` (human, the default), `json`
(native), `cyclonedx` (SBOM), `sarif` (code scanning), or `markdown` (PR
comment). `gate` reports `table` or `json`; `explain` reports `text` or `json`.
Any command that writes a report takes `-o/--output <file>` to write to a file
instead of stdout.

## Global flags

`-v/--verbose` (repeatable, `-vv`) raises diagnostic detail on stderr, and
`-q/--quiet` leaves only errors. Neither changes the machine-readable output on
stdout or `--output`, so a report stays byte-identical regardless of verbosity.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success. A plain `scan` exits `0` even when it identifies CUDA or finds affected advisories; opt into failure with `--fail-on`. |
| `1` | A `gate` policy violation, or a `scan --fail-on` threshold was met. |
| `2` | Usage error (bad arguments). |
| `3` | Input error (an unreadable target, SBOM, policy, database, or index). |
| `4` | Internal error. |

## Networking

A scan makes no network calls. Only three paths reach the network, and each is
explicit: `cudabom update`, `cudabom db update`, and `cudabom reconcile
--ngc-image`. Everything else reads local, verified data, which is what makes
cudabom safe to run in an air-gapped pipeline (see
[CI/CD integration](ci/README.md)).
