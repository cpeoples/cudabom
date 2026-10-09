# fuzz

libFuzzer (cargo-fuzz) targets for the parser boundaries cudabom exposes to
hostile input. Each parser must be panic-free on malformed input; these targets
check that and run as short jobs in CI.

Standalone crate, excluded from the root workspace (see the root `Cargo.toml`
`exclude`), so it can depend on `libfuzzer-sys` and build under nightly.

## Targets

One per parser boundary that consumes untrusted bytes:

| Target            | Boundary                              | Entry point                          |
| ----------------- | ------------------------------------- | ------------------------------------ |
| `fuzz_elf`        | ELF fact extraction                   | `cudabom_elf::parse` / `find_embedded_elf` |
| `fuzz_pe`         | PE fact extraction                    | `cudabom_pe::parse`                  |
| `fuzz_fatbin`     | fatbin container / cubin / PTX header | `cudabom_fatbin::{inspect, parse_ptx, find_embedded_fatbins}` |
| `fuzz_csaf`       | CSAF advisory input                   | `cudabom_advisory::ingest`           |
| `fuzz_cyclonedx`  | CycloneDX SBOM / VEX input            | `cudabom_sbom::DeclaredBom::from_json` |
| `fuzz_detect`     | archive/binary classifier (wheel-zip and OCI dispatch gate) | `cudabom_extract::detect_kind` |

## Running

```sh
cargo install cargo-fuzz
cargo +nightly fuzz run fuzz_elf -- -runs=1000000
```

CI runs each target for a short, bounded number of iterations on every push.
Longer campaigns are run manually.

Fuzz corpora and crash artifacts are gitignored (see `../.gitignore`:
`fuzz/corpus/`, `fuzz/artifacts/`, `fuzz/target/`).
