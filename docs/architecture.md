# Architecture

cudabom is a Cargo workspace. Each crate owns one stage of the pipeline and
depends only on what that stage needs, so the ELF parser does not drag in the
archive stack and the reporting layer does not depend on the advisory database.

## Crates

| Crate | Responsibility |
|---|---|
| `cudabom` | clap front end, output selection, exit codes |
| `cudabom-core` | shared types (Artifact, Location, Component, Evidence, Confidence, Finding) and tunable safety `Limits` |
| `cudabom-extract` | safe, streaming walkers for wheels, sdists, archives, directories, and container images |
| `cudabom-elf` | ELF facts: SONAME, NEEDED, symbols, symbol versions, build-id, sections, notes, rodata strings |
| `cudabom-fatbin` | fatbin/cubin/PTX parsing |
| `cudabom-identify` | fingerprint DB + matchers turning facts into CUDA identities with confidence |
| `cudabom-advisory` | NVIDIA CSAF ingestion, normalization, local index, matching |
| `cudabom-sbom` | CycloneDX 1.6 emit/enrich/merge, PEP 770 reader, VEX |
| `cudabom-report` | terminal table, native JSON, SARIF, Markdown renderers |
| `cudabom-policy` | policy-file evaluation for `gate` |
| `xtask` | fixture builds, fingerprint-DB builder, corpus evaluation (not shipped) |

## Pipeline

```
input
  -> extract (safe, streaming, bounded by Limits)
  -> per-file facts (ELF, fatbin, rodata strings)
  -> identify (evidence -> component identity + confidence)
  -> reconcile with declared SBOMs (PEP 770 / input SBOM)
  -> correlate advisories (local index)
  -> render outputs / evaluate policy
```

Per-file facts are cached by content hash so re-scans and multi-layer container
images are fast.

## Design invariants

- Never execute, load, or JIT anything scanned.
- No network except the explicit refresh/fetch commands (`cudabom db update`,
  `cudabom update`, and `reconcile --ngc-image`).
- Parsers are panic-free on malformed input and are fuzzed.
- Output is deterministic (stable ordering).
- `#![forbid(unsafe_code)]` across all crates.

See [`evidence-model.md`](evidence-model.md) and [`threat-model.md`](threat-model.md).
