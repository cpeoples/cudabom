# Threat model

cudabom consumes attacker-controlled files: wheels, shared libraries,
executables, and container images pulled from untrusted sources. Resisting
hostile input without crashing or escaping is a primary requirement.

## Trust boundary

Everything cudabom scans is untrusted. cudabom itself, its fingerprint database,
and its advisory index are trusted (the index is verified on `db update`).

## Enforced properties

- **No execution.** cudabom never executes, loads (`dlopen`), or JIT-compiles
  anything it scans. It only reads and parses bytes.
- **No network** except the explicit refresh/fetch commands (`cudabom db
  update`, `cudabom update`, and `reconcile --ngc-image`). A scan makes
  no network connections; the security verdict never depends on a reachable
  website.
- **Safe extraction.** No path traversal, no symlink following outside the
  virtual root, no absolute paths, no writing to disk unless a temp dir is
  strictly required (prefer in-memory/streaming).
- **Bounded work.** Configurable hard limits cap nesting depth, total bytes,
  per-file bytes, decompression ratio, entries per archive, and per-file parse
  time. These live in one tunable place: the `Limits` struct in
  `crates/cudabom-core/src/config.rs`.
- **Panic-free parsers.** Malformed input yields an error, never a crash. Every
  parser has a fuzz target under `fuzz/` and short fuzz jobs run in CI.
- **No unsafe.** `#![forbid(unsafe_code)]` in all crates; any exception is
  justified in `DECISIONS.md`.

## Attack scenarios and mitigations

| Scenario | Mitigation |
|---|---|
| Zip/tar bomb | per-file and total byte caps; decompression-ratio cap |
| Deeply nested archive | nesting-depth cap |
| Path traversal (`../../etc`) | skip the entry (never written, so no escape); keep scanning siblings |
| Symlink escape | do not follow symlinks outside the virtual root |
| Malformed ELF/fatbin crashing the parser | panic-free parsing; fuzzing |
| Hostile CSAF/SBOM input | validated parsing; bounded sizes |

## Supply chain of cudabom itself

SHA-pinned GitHub Actions on hardened runners, `cargo-audit` and `cargo-deny`
gates, CodeQL, OpenSSF Scorecard, and releases signed with SLSA Build Level 3
provenance and Sigstore. See [`../SECURITY.md`](../SECURITY.md).
