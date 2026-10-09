# Evaluation corpus manifest

`groundtruth.manifest.json` is a **reviewable, text-only** list of real NVIDIA
redistributable archives used to measure cudabom head-to-head against other
tools (Syft, Trivy, blint) on **known-identity** binaries. It is a
`CorpusLock`: each entry records the component, exact version, platform, source
URL, and NVIDIA's own SHA-256. **No binaries are committed**; the archives it
points at are downloaded on demand into the gitignored `corpus/` directory.

## Running the ground-truth evaluation

```sh
cargo build --release                 # build the cudabom binary the harness runs
cargo xtask eval --download           # fetch + verify + unpack, then evaluate
```

`cargo xtask eval` (with the manifest present, or `--download`) will:

1. Download and SHA-256-verify every archive into `corpus/eval/` (idempotent).
2. Unpack each archive and resolve its **primary library** (`libcudart.so.*`,
   `cudart64_*.dll`, …).
3. Run cudabom on each binary and classify the result against ground truth:
   `exact` / `version-mismatch` / `MISS` / `ERROR`.
4. Run the installed competitors (Syft/Trivy/blint) over the same binaries for
   a head-to-head tally, including **CVE correlation** (`cudabom correlates a
   CVE` vs `Trivy correlates a CVE`) on the identical loose binaries.
5. Write `target/eval-groundtruth.json` (with per-binary `cve_matches`) and
   print a readable summary, calling out every miss or crash explicitly.

Flags: `--manifest <file>` (default `eval/groundtruth.manifest.json`),
`--corpus <dir>` (default `corpus/eval`), `--db`, `--advisories`, `--out`.

Competitors are optional: a missing tool is reported, never fatal.

## Why known-identity binaries

A tool's quality is only measurable against truth. Because every archive's
component and exact version are known first-party (from NVIDIA's redist
manifest), the harness can distinguish a correct identification from a confident
wrong one, and surface the file types or platforms a tool misses.

## The distribution eval (in-the-wild forms)

Where `groundtruth.manifest.json` tests pristine NVIDIA archives,
`distribution.manifest.json` tests the forms CUDA actually ships in to users:
**PyPI wheels** (`nvidia-*-cuXX` and third-party frameworks that vendor CUDA),
**conda packages**, **container images** (pinned by digest), and **synthetic
adversarial copies** (stripped/renamed, static-only, UPX-packed, offset-embedded).
Each entry is content-pinned so the run is reproducible; downloads land in the
gitignored `corpus/distribution/`.

```sh
# Tier A (wheels/conda/synthetic, a few GB, fits a 14 GB CI runner):
cargo xtask eval --distribution --tier a --download --stream

# Tier B (full set incl. fat container images; stream reclaims each artifact):
cargo xtask eval --distribution --tier b --download --stream
```

`--tier a|b` scopes the set, `--kind wheel,conda,...` filters explicitly, and
`--stream` reclaims each artifact's download/unpacked tree (and `docker rmi`s a
pulled image) as soon as it is scored, so peak disk is one artifact rather than
the whole set. Results are written to `target/eval-distribution.json`.

### Keeping it fresh: `distribution discover`

`cargo xtask distribution discover` crawls PyPI's JSON API for a reviewed set of
CUDA-bearing projects and proposes new, content-pinned manifest entries. It is
**metadata only** (URL/size/sha256 come from the API, no wheel is downloaded),
so it is cheap enough to run nightly. `--write` appends new entries to
`distribution.manifest.json` for review; the `distribution-discover` workflow
runs it nightly and opens a PR. Seed it once locally with a broad crawl
(`cargo xtask distribution discover --limit 5 --write`), then let the nightly
pick up new releases and stragglers.

## Background: how these forms behave (validation notes)

The behaviors below were established while building the distribution eval and
are also locked by unit/CLI tests:

- **PyPI wheels (`nvidia-*-cu12`).** A wheel is a ZIP of relocated, renamed
  libraries (`nvidia/cuda_runtime/lib/libcudart.so.12`). The bundled `.so` and
  the `libcudart_static.a` members are **byte-identical to the redist archive**
  (same SHA-256), so cudabom identifies `cudart <ver> (exact)` straight through
  the ZIP with no wheel-specific code; only DB version coverage is required.
  For comparison, Syft reports nothing for the bundled `.so`; Trivy reports the
  package only from the wheel's `*.dist-info` metadata, never from the binary.
- **Embedded fatbins (e.g. PyTorch `libtorch_cuda.so`).** A ~900 MB library
  with CUDA statically linked and 256+ embedded fatbins is detected via the
  fatbin wrapper magic; the aggregated capability reports the real cubin SM
  targets (`[50, 60, 70, 75, 80, 86, 90]` for torch 2.6). Its dynamic CUDA
  dependencies (cudart/cublas/cufft/curand/cusparse/cudnn) are surfaced as
  `unknown` NEEDED edges. (This path was previously broken by a byte-reversed
  magic constant; see CHANGELOG.)
- **Repackaged / UPX-packed DLLs.** UPX preserves `.rsrc`, so a packed
  `cudart64_12.dll` still yields `cudart <ver> (likely)` from the PE version
  resource, with the `UPX0`/`UPX1` sections visible as packing evidence. When
  the version resource is destroyed, cudabom degrades **honestly** to a
  versionless `cudart (likely)` rather than fabricating a version.
