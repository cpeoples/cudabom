# Contributing to cudabom

Thanks for your interest in cudabom. This document covers the development
environment, the quality gates every change must pass, and how to add the two
things contributors most often add: a fingerprint and an output format.

## Development environment

cudabom is a Rust workspace. The toolchain is pinned in
[`rust-toolchain.toml`](rust-toolchain.toml); `rustup` will install it
automatically on first build.

```bash
git clone https://github.com/cpeoples/cudabom.git
cd cudabom
cargo build --workspace
cargo test --workspace
```

Install the pre-commit hooks so formatting and lints match CI before you push:

```bash
pipx install pre-commit   # or: pip install pre-commit
pre-commit install
```

## Quality gates

Every pull request must pass the same checks CI runs. Run them locally:

```bash
cargo fmt --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo deny check          # cargo install cargo-deny
```

Notes:

- All crates build under `#![forbid(unsafe_code)]`. If you have a narrowly
  justified need for `unsafe`, it must be approved and recorded in
  [`DECISIONS.md`](DECISIONS.md) before the lint is relaxed for that spot.
- Parsers must be panic-free on malformed input: return an error, never crash.
  New parsers need a fuzz target under `fuzz/`.
- Output must be deterministic (stable ordering) so snapshots and diffs are
  meaningful.
- Use [Conventional Commits](https://www.conventionalcommits.org/) and keep
  commits small and reviewable.

## Configuration lives in one place

This project centralizes its tunables so there are no scattered magic values:

- Dependency versions and lint policy: the root [`Cargo.toml`](Cargo.toml)
  (`[workspace.dependencies]`, `[workspace.lints]`).
- Formatting: [`rustfmt.toml`](rustfmt.toml). Clippy thresholds:
  [`clippy.toml`](clippy.toml).
- Supply-chain policy: [`deny.toml`](deny.toml).
- Runtime safety limits (nesting, byte caps, decompression ratio, timeouts):
  the `Limits` struct in `crates/cudabom-core/src/config.rs`.

When you need a new knob, add it to the appropriate config surface rather than
hard-coding a constant at the call site.

## How to add a fingerprint

cudabom identifies CUDA components from *derived* data (hashes, symbol sets,
version patterns, build-ids), never from committed NVIDIA binaries.

1. Obtain an official NVIDIA redistributable (e.g. an `nvidia-*` wheel from
   PyPI, a conda package, or a CUDA redist archive). Record its exact source
   URL, package name, version, platform, architecture, checksum, and the date
   you collected it.
2. Derive the fingerprint data with the builder (`cargo xtask fingerprints
   build`) and add the resulting entry under `fingerprints/`.
3. Record provenance in `docs/fingerprints/` for the entry you added.
4. Do NOT commit the NVIDIA binary. Respect NVIDIA's license terms.

See [`docs/fingerprints/README.md`](docs/fingerprints/README.md) for the full
process and licensing constraints.

## How to add an output format

Renderers live in `crates/cudabom-report` (table, JSON, SARIF, Markdown) and
`crates/cudabom-sbom` (CycloneDX, VEX). Add the format, register it in the CLI's
`--format` enum, and add an `insta` snapshot test covering it.

## Reporting bugs and security issues

- Functional bugs: open a GitHub issue with a minimal reproducer.
- Security vulnerabilities: see [`SECURITY.md`](SECURITY.md) and use a private
  advisory, not a public issue.

## AI-assistance disclosure

LLM tooling may assist with scaffolding, refactoring, test generation, and
documentation. All of it is reviewed, edited, and tested by a human before being
committed, and every change runs the full test, lint, and supply-chain gate.
