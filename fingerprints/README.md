# fingerprints

Versioned, reviewable fingerprint data for CUDA components: **derived data
only** (sha256 hashes, exported/internal symbol sets, version-string patterns,
build-ids). No NVIDIA binaries are ever committed here.

## Layout

Fingerprint data is **sharded**, one file per upstream source, so that refreshes
produce small, reviewable diffs and per-file growth stays bounded:

```
fingerprints/
  cuda/
    redistrib_<version>.json   # derived 1:1 from NVIDIA's redistrib_<version>.json
  <product>/                   # cudnn, nccl, cutensor, ..., nvcomp
    redistrib_<version>.json
  jetson/                      # Tegra (L4T/JetPack) shards, synthesized source
    redistrib_<release>.json
  corpus.<version>.lock.json   # one per-release lockfile per CUDA release
```

Each shard under `cuda/` is derived from exactly one NVIDIA CUDA redistributable
manifest (`redistrib_<version>.json`), so the shard's name *is* its provenance.
Sibling products (cuDNN, NCCL, nvCOMP, ...) derive the same way under their own
subdirectory. The `jetson/` shards are the one exception to the 1:1 manifest
rule: their source manifest is synthesized from NVIDIA's signed Jetson APT
`Packages` index (see `../docs/sources.md`), then derived identically.
At scan time, `cudabom-identify`'s directory loader
(`FingerprintDb::from_dir`) reads every shard in sorted order and merges them
into one in-memory database, deduplicating and unioning the per-hash version
sets.

A shard also carries first-party release metadata copied verbatim from the
manifest: `release.label` (e.g. `12.4.1`) and `release.date` (e.g.
`2024-04-03`, NVIDIA's `release_date`). There is no per-file publish date in the
redist manifest, so this single per-release date is the only grounded date
recorded; it is never synthesized from HTTP headers or guessed. When the loader
merges shards it folds these into a `release_dates` map so a scan can date a
finding by the release that shipped it.

Corpus lockfiles are **sharded per CUDA release** (`corpus.<version>.lock.json`),
so each release's fetch plan is reviewed and grown independently and diffs stay
small. `cargo xtask corpus fetch --lock <dir>` accepts a directory and merges
every `corpus.*.lock.json` shard in it (de-duplicated), so a full-corpus fetch
reads them all at once; passing a single file still works for a subset run.

## What a shard contains

For each mapped component, a shard records:

- `soname_stems`: the versioned-library base names the component publishes
  (reviewed, never guessed; see the profile table in `cudabom-identify`).
- `file_hashes`: **archive** sha256 -> version(s) (manifest layer), and, when
  a corpus is available, **per-file** `.so` sha256 -> version(s) (binary layer).
  The value is a *set* of versions: NVIDIA re-ships a byte-identical library
  under more than one component version across releases (relabeled, not
  rebuilt), so a hash can legitimately identify several versions and all are
  recorded.
- `build_ids`: GNU build-id -> version(s), derived from real unpacked `.so`
  files (binary layer); the strongest non-hash identifier. A set for the same
  reason as `file_hashes`.
- `version_markers`: reserved for rodata version strings.
- `description` / `license`: NVIDIA's own human-readable description (e.g.
  `CUDA Runtime (cudart)`) and license (`CUDA Toolkit`) for the component, taken
  verbatim from the redist manifest during derivation. Surfaced in `scan` and
  `reconcile` output. First-party, never guessed.
- `release_versions`: each observed component version -> the CUDA toolkit
  release label(s) that shipped it (from the redist manifest's `release_label`).
  This first-party link lets toolkit-level advisories (keyed to a CUDA release)
  correlate against an individually scanned library (keyed to its own version).

A shard also carries, at the top level, a `release` block (`label` + `date`, see
above) and a `provenance` block recording the exact inputs it was derived from:
`manifest_sha256` (the redist manifest bytes), `corpus_sha256` (the sorted set of
corpus archives whose binaries contributed), and `tool_version`. Because the
build is a pure function of these inputs, a rebuild compares the current inputs
against a shard's recorded provenance and **skips re-deriving an unchanged
release** (`fingerprints build` prints `up to date, skipped`). This keeps a
nightly refresh cheap: only new or changed releases are re-unpacked and
re-parsed. Pass `--force` to rebuild every shard regardless.

## The corpus: real archives for binary derivation

The binary layer needs real `.so` bytes, but NVIDIA binaries are never committed.
The bridge is a committed, reviewable **lockfile** (`corpus.<version>.lock.json`),
like `Cargo.lock`: it lists each archive's `component`, `version`, `platform`,
`url`, and `sha256` (NVIDIA's own digest from the redist manifest, nothing
invented).

```
# Derive a per-release lockfile from a redist manifest (URLs + NVIDIA digests):
cargo xtask corpus lock --manifest fixtures/redist/redistrib_<version>.json \
  --out fingerprints/corpus.<version>.lock.json

# Fetch + verify archives into ./corpus (gitignored), retrying with backoff.
# --lock accepts a directory of shards (full corpus) or a single file (subset):
cargo xtask corpus fetch --lock fingerprints   # honors --max-retries / --retry-base-ms / --no-retry

# Derive shards, folding in binary signals from the unpacked corpus.
# --jobs N parallelizes derivation (default 4); unchanged releases are skipped;
# use --force to rebuild all:
cargo xtask fingerprints build --corpus corpus --jobs 4
```

### Discovering new releases automatically

NVIDIA publishes no machine-readable release list, but its redist root serves an
auto-generated directory index. `corpus discover` reads it and locks any release
not already committed, with no hardcoded version list:

```
# Show what NVIDIA publishes vs. what is committed (no network writes):
cargo xtask corpus discover --json --dry-run

# Lock a bounded batch of new releases (saves manifests + per-release lockfiles):
cargo xtask corpus discover --limit 4
```

The nightly `.github/workflows/fingerprint-refresh.yml` runs discover (bounded
batch) -> `corpus fetch` -> `fingerprints build --jobs N`, drops the large
gitignored corpus to keep the runner's disk bounded, and opens a review PR when
shards change, mirroring the advisory index's `advisory-refresh.yml`. Coverage
fills in progressively across nights; a human reviews each batch before scans
trust it.

### Verify on a subset first

Before fetching every release (hundreds of megabytes), validate the pipeline end
to end on one archive. This is a first-class, repeatable control, not a
hand-edited lockfile:

```
# Lock just the first entry, then preview the fetch plan (no network, no disk):
cargo xtask corpus lock --manifest fixtures/redist/redistrib_<version>.json --limit 1
cargo xtask corpus fetch --dry-run

# When the plan looks right, run it for real and build the shard:
cargo xtask corpus fetch
cargo xtask fingerprints build --corpus corpus
```

Confirm the resulting shard carries real build-ids and hashes for the unpacked
`.so`, then widen the lockfile (drop `--limit`) and run the full set.


`corpus fetch` verifies every download against the lockfile digest (via the
shared `cudabom-fetch` primitive, so it inherits retry / exponential backoff /
`Retry-After` handling), is idempotent (skips archives already present with a
matching digest), and writes only into the gitignored `corpus/` tree. Unpacking
`.tar.xz` uses the system `tar`, `.zip` uses `unzip`, and `.deb` (Jetson)
unpacks its inner `data.tar` the same way; that shelling-out lives only in
`xtask` (dev/CI tooling), so the shipped binary carries no lzma dependency.

## Provenance and the no-binaries rule

Every entry is derived from official NVIDIA data and reviewed before it is
committed. Downloaded binaries and evaluation corpora live in gitignored scratch
dirs (`downloads/` here, plus `/.fingerprint-cache/` and `/corpus/` at the repo
root) and are never part of the repository. Provenance notes live under
[`../docs/fingerprints/README.md`](../docs/fingerprints/README.md).
