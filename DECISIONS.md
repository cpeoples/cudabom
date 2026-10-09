# Decisions

A running log of non-obvious engineering decisions: what was chosen, the
alternatives considered, and why. Newest entries at the top. Each entry is
dated. This is the project's memory; when a choice is reversed, add a new entry
rather than editing the old one.

---

## 2026-10-02 - Findings surface the full candidate version set; math-library backfill

### A strong-signal match exposes every candidate version, not just the lowest

The 2026-09-30 decision stored a hash/build-id -> **set** of versions in the DB
(because NVIDIA ships byte-identical libraries under several labels) but still
reported only the lowest as a representative in `Component.version`, leaving the
rest reachable solely through `release_versions` for advisory correlation.
Backfilling the full math-library binary layer showed how common the sharing
really is: a single `npp` build-id covers up to **13** toolkit versions (avg
~4.7 across npp, cublas, cufft, cufile, nvrtc, cusolver, cusparse, nvjpeg,
curand), with **zero cross-component collisions**, so *which* component is
identified is never ambiguous, only the exact micro version. Reporting one
silent representative was quietly misleading and produced false
`version-mismatch` rows in the groundtruth eval for any binary that was not the
lowest in its set.

Decision: `Component` gains `candidate_versions: Vec<String>` (serde `default` +
skip-when-empty, so older JSON loads unchanged). When a hash or build-id maps to
more than one release, `version` keeps the lowest (deterministic representative)
and `candidate_versions` carries the complete sorted set, making the ambiguity
explicit. Confidence stays `Exact`: the **binary** match is exact; only the
version label is shared. The file-hash path still pins a single version (archive
hashes stay unique per release), so the candidate set appears only when a shared
build-id is the sole signal: e.g. a stripped or renamed library with no
matching hash. The `scan` table renders `version (+N more)`; the groundtruth
eval counts a match when ground truth is the representative **or** anywhere in
the candidate set. Alternatives rejected: downgrading these to `Likely` (the
bytes *are* an exact match; only the label is ambiguous, and `Likely` is for
structural/SONAME evidence); formatting the set into the `version` string itself
(breaks machine consumers and the eval's exact-version comparison).

### Backfill is platform-scopable; `fingerprints backfill --platform`

The binary layer is platform-specific (build-ids differ per architecture) and a
CUDA lock spans four Linux architectures x ~14 components, so a full backfill
pulls far more than the dominant real-world target needs. Decision: `backfill`
accepts `--platform` and passes it straight through to `corpus fetch`, so a run
can scope to `linux-x86_64` (what the PyPI wheels ship) and cut download volume
~4x without changing correctness for that platform. Omitting the flag keeps the
all-platform behavior. This is what makes grinding the back catalog tractable
locally and keeps the nightly cheap.

### CUDA 11.0.3-11.4.1 have no fingerprintable corpus (upstream boundary)

Investigating the "manifest-only old releases" showed their `redistrib_*.json`,
both our fixtures and NVIDIA's live upstream, contain **only** datacenter
components (`fabricmanager`, `libnvidia_nscq`); NVIDIA did not publish the
full-toolkit redist (cudart, cublas, ...) until 11.4.2. There is nothing to
lock, fetch, or fingerprint for the earlier releases, so their lack of a corpus
lock is correct. Recorded as a known data-source boundary rather than a gap to
chase.

---

## 2026-10-01 - Advisory reference links, and source parsing left out of scope

### Advisories carry reference URLs (NVD + CSAF), surfaced in every report

Scan output named each CVE but gave no link to read it. Decision: the advisory
model gains an additive `references: Vec<String>` (schema stays at 1: the field
defaults to empty and is omitted when empty, so older indexes load unchanged).
CSAF ingestion populates it from `vulnerabilities[].references[].url` **plus** a
deterministically derived canonical NVD page (`https://nvd.nist.gov/vuln/detail/
<CVE>`) for any CVE id. The NVD URL is derived, never invented: it is a fixed
function of the id, so the "never assert more than the evidence supports"
principle holds. The links flow through the matcher and the neutral report input
into **all** renderers: the table (`references:` line), native JSON (array),
SARIF (result `helpUri` + `properties.references`), and Markdown (host-labeled
links). The composition section stays compact (ids only) by design. Regenerating
`advisories/index.json` from the same pinned commit was verified **additive-only**
(all 74 records gained references; no other field changed), so no advisory claim
was altered. Alternatives rejected: storing links only (loses the guaranteed
NVD anchor when CSAF carried none); deriving the NVD URL at render time only
(then JSON/SBOM consumers wouldn't see it).

### Source and manifest parsing is deliberately out of scope

cudabom scans **compiled, packaged artifacts** and does not parse source
(`.cu`/`.cpp`/headers) or dependency manifests (`requirements.txt`, `Cargo.toml`,
conda envs). This is a scope decision, now stated plainly in the README so it
reads as intentional rather than missing. Rationale: the project's thesis is
evidence over declaration: source expresses *intent* while the artifact carries
the *truth*, and the highest-value cases (statically linked, vendored, or renamed
CUDA) have no source footprint. Source/lockfile analysis is also
environment-dependent, which would break deterministic output, and that space is
already served by SCA tooling. The model-consistent extension is ingesting more
*declaration* formats for `reconcile` to check against evidence (PEP 770 /
CycloneDX are already read), never inferring dependencies from source.

---

## 2026-09-30 - Fingerprint autonomy, version sets, and parallel derivation

### Version sets, not single versions, for hash/build-id -> version

Expanding the corpus past two releases surfaced a modeling error: NVIDIA ships
some libraries **byte-identical across multiple toolkit releases**, relabeling
the component version without rebuilding. The v1 schema mapped a file hash /
build-id to *one* version, so the shard merge treated the recurrence as a
"conflict", kept the first, and silently discarded the others, under-reporting
which versions a scanned binary could be. Decision: schema v2 maps a hash /
build-id to a **set of versions** (sorted, de-duplicated), and the merge unions
them. An identical binary under several versions is a fact to record, not a
collision to resolve, so the `MergeConflict` path for this case is gone. The
`Component.version` field (single-valued, model-wide) reports the lowest version
as a deterministic representative; advisory correlation still fans out through
`release_versions`, so nothing is lost for matching. Alternatives rejected:
keeping one version with an "alias" note (still discards data); relaxing the
no-conflict test (leaves the data-loss bug in place).

### Discover releases first-party from NVIDIA's directory index

NVIDIA publishes no machine-readable list of CUDA redist releases, but its
redist root serves an **auto-generated HTML directory index**. Decision:
`corpus discover` reads that index and extracts the `redistrib_<version>.json`
names directly, rather than maintaining a hardcoded version list (a maintenance
burden that defeats autonomy) or probing/guessing versions (fragile). This is
the same philosophy as `advisory-refresh` synthesizing a CSAF manifest from
NVIDIA's git tree: the set of inputs is read from the source of truth. Discovery
diffs the published set against committed shards (`redistrib_<ver>.json`) so only
genuinely new releases are acted on.

### Nightly fingerprint refresh mirrors advisory refresh; PR-gated

`fingerprint-refresh.yml` gives the fingerprint database the autonomy the
advisory index already had: nightly discover -> fetch -> derive -> open a review
PR. Two deliberate constraints. First, **bounded batches**: each run adds at most
`BATCH` new releases and deletes the (tens-of-GB, gitignored) corpus afterward,
so a hosted runner's disk only ever holds one batch; coverage fills in over
several nights instead of one enormous job. Second, **human-in-the-loop**: like
advisories, it opens a PR rather than committing to `main`, so a reviewer sees
new components / build-ids / version sets before scans trust them. Auto-merge
was rejected as removing the only review gate on data scans depend on.

### Parallel derivation: bounded pool + self-cleaning scratch dirs

Derivation was sequential and dominated by large libraries (cuBLAS et al.).
Decision: derive archives across a **bounded worker pool** (`std::thread::scope`,
default 4, capped at cores, `--jobs N`): bounded rather than one-thread-per-
archive because each worker holds a large `.so` in memory while hashing it, so
unbounded parallelism (e.g. rayon's default) risks OOM on a small machine or CI
runner. Measured ~3x speedup at `--jobs 4`. Each worker extracts into a scratch
directory wrapped in an RAII guard that removes the tree on drop (even on
error), fixing a real leak where extracted trees accumulated in the system temp
directory across runs. std-only; no new dependency for either concern.

### One global verbosity knob

Diagnostics were unconditional `eprintln!` and the only `--verbose` was on
`version`. Decision: a single global `-v/--verbose` (repeatable) and `-q/--quiet`
set a process-wide level gating stderr status output, in both the CLI and xtask
(each carries its own tiny level since they share no library). A lightweight
atomic + macros was chosen over a logging framework (`tracing`/`log`): the need
is a three-way level, not structured logging, and staying dependency-free keeps
the shipped binary lean. stdout / `--output` (the machine-readable result) is
never affected by verbosity.

---

## 2026-09-30 - Data distribution: `cudabom update` and the data bundle

### Ship the binary and the data separately; pull data from GitHub Releases

cudabom's binary carries no fingerprint database or advisory index: those are
the committed, reviewed data in the repository, and a binary-only install
(crates.io, Snap under strict confinement, a release archive) previously had no
way to obtain them without cloning. Decision: publish the data per release as a
single **data bundle** (`cudabom-data-<tag>.tar.gz` + `.sha256` sidecar) as a
GitHub Release asset, and add `cudabom update` to fetch, verify, and install it
into a per-user data directory.

Integrity mirrors `db update`: the bundle is downloaded over HTTPS from GitHub,
verified against its sidecar digest (mandatory here: unlike the per-file CSAF
sidecars, the asset has no other anchor), and unpacked with the same hard limits
and path-traversal rejection as the CSAF tarball path. The bundle is a gzip tar
(reusing the existing `flate2`/`tar` deps) rather than adding a `zstd`
dependency for a handful of small JSON files.

### Data-directory resolution and default wiring

Resolution order (first present wins): `CUDABOM_DATA_DIR` (override/tests),
`SNAP_USER_DATA/cudabom` (writable inside a confined Snap where `$HOME` is not),
`XDG_DATA_HOME/cudabom`, then `~/.local/share/cudabom`. Resolution is a pure
function of the environment (no new `dirs` crate), so it is trivially testable.
`scan`/`gate`/`vex`/`enrich`/`reconcile`/`explain` now default `--db` and
`--advisories` to this directory: `--db` accepts a directory of shards (merged
via `FingerprintDb::from_dir`) as well as a single file, so a fresh install
"just works" and an explicit flag still overrides. `version --verbose` reads the
bundle's `VERSION` stamp to report exactly what is installed.

### Building the bundle deterministically (`cargo xtask bundle`)

The release asset is produced by `cargo xtask bundle --tag <tag>` from the
committed data, with a fixed archive mtime so the output is byte-reproducible.
The release workflow runs it, Sigstore-signs the bundle, and attaches it. The
nightly advisory-refresh PR flow is unchanged and feeds the next release's
bundle through the normal commit path, keeping one coherent pipeline: refresh
committed data → release packages it → `cudabom update` pulls it.

---

## 2026-09-30 - Advisory enrichment: published date, description, CVSS score

### Capture the CSAF metadata we already parse but were discarding

The CSAF ingestion resolved product/version status but recorded only the
advisory id, title, and free-text aggregate severity. The bulletins already
carry three more first-party fields that make a finding actionable, so the
normalized `Advisory` now keeps them:

- `published` from `document.tracking.initial_release_date` (recorded verbatim,
  date or full RFC 3339 timestamp), supporting age-based triage and sorting. We
  deliberately record only the initial release date, not `current_release_date`,
  to keep the index stable across re-issues (a later revision would otherwise
  churn every advisory's date).
- `description` from the vulnerability `notes`, preferring a `description` note,
  then `summary`, then `general`, then the first note with text: a human
  summary beyond the id/title.
- `cvss_score`: the highest CVSS **base** score across the vulnerability's
  `scores[]` (reading `cvss_v4`/`cvss_v3`/`cvss_v2` `baseScore`), a numeric
  complement to the free-text severity for gating. Because a score is an `f64`,
  the advisory/index types drop `Eq` (keeping `PartialEq`); nothing relied on
  `Eq`.

All three are optional and absent-when-not-published (never guessed). They are
copied onto each `Match` so the CLI surfaces them without re-holding the index,
and appear in `scan` JSON and as a compact metadata line in the table. This is
pure enrichment: matching/verdict logic is unchanged.

---

## 2026-09-30 - Release dates, incremental builds, and sharded corpus fetch

### Record NVIDIA's per-release date; do not synthesize per-file dates

The redist manifest carries a single top-level `release_date` (e.g.
`2024-04-03`) for the whole release, already parsed into `RedistManifest`.
Decision: persist it first-party as a shard-level `release` block (`label` +
`date`), mirroring how `release_label` already flows. There is deliberately **no
per-file publish date**: the manifest does not carry one, and deriving it from
HTTP `Last-Modified` headers at fetch time would be non-reproducible and
non-first-party: exactly the guessing the project forbids. Distribution
(Ubuntu/Debian) dating lives in a different source (the APT `Packages`
metadata) and is left to a future, separate layer rather than blurred into the
redist-derived shard. The directory loader folds each shard's date into a
merged `release_dates` map so a scan can date a finding by the release that
shipped it (via the existing `release_versions` link).

### Content-addressed incremental builds (skip unchanged releases)

A `fingerprints build` over the full corpus re-unpacks every `.tar.xz` and
re-parses every ELF on each run, which wastes CPU in a nightly job when nothing
changed. The build is a pure function of `(manifest bytes, contributing corpus
archive bytes, tool version)`, so the correct skip signal is content, not
mtime. Decision: stamp each shard with a `provenance` block recording those
input digests; before deriving, recompute them and skip when they match an
existing shard's provenance (`up to date, skipped`). `--force` overrides.
Alternatives rejected: mtime comparison (fragile across clones/CI checkouts,
and a `git checkout` rewrites mtimes) and diffing the remote redist directory
listing (an extra network dependency that still would not detect a re-published
archive with changed bytes). Content hashing catches a changed *or* re-published
input and re-derives only that release.

### Corpus lockfiles sharded per release; fetch reads a directory

Corpus lockfiles are now consistently named `corpus.<version>.lock.json`, one
per CUDA release (the old default-named `corpus.lock.json` for 11.4.2 was
renamed for consistency). Lockfiles are tiny and always committed (only the
downloaded archives are gitignored), so sharding costs nothing and keeps diffs
small and per-release reviewable. `corpus fetch --lock` accepts either a single
shard file (subset run) or a directory, in which case it merges every
`corpus.*.lock.json` (de-duplicated): the full-corpus case. This mirrors the
existing `FingerprintDb::from_dir` shard-merge convention, so one mental model
covers both the fingerprint shards and the corpus lockfiles. An aggregate
single lockfile was rejected: it would grow unboundedly and every refresh would
touch one file, producing large diffs and merge friction.

---

## 2026-09-30 - First-party component descriptions and licenses

### Carry the manifest's description and license, and surface them

The redist manifest states a human-readable name (`CUDA Runtime (cudart)`) and a
license (`CUDA Toolkit`) for every component, which the derivation previously
discarded (the shard's `name` holds only the canonical short name). Decision:
keep both as first-party `description` and `license` fields on
`ComponentFingerprint`, populated verbatim from the manifest at
`xtask fingerprints build` time (never guessed; `None` when no manifest provided
one). The binary layer leaves them empty and the merge fills them from the
manifest layer (first-seen wins).

Surfacing them keeps `Finding`/`Component` lean: descriptions are static
reference data about an identity, not per-scan facts, so they are looked up at
output time from the loaded DB rather than stamped onto every finding. The
pipeline builds a small `catalog` (name -> description/license) for the
components actually found; `scan` emits it (JSON `catalog`, plus a table line)
and `reconcile` attaches the description to matched and discovered-only
components.

---

## 2026-09-30 - Declared-vs-discovered reconciliation (NGC SBOM/VEX)

### The validation: compare a declaration against independent discovery

NVIDIA NGC publishes a CycloneDX SBOM and VEX per container image. cudabom
independently proves what CUDA software an artifact contains. The new `cudabom
reconcile` command diffs the two into three buckets: **matched** (both, with any
declared VEX statements attached), **declared_only** (declared but not found),
and **discovered_only** (found but not declared: the high-value case, where a
declaration under-reports what is actually shipped). This turns cudabom's
identity engine into a check on third-party SBOM completeness.

### Read path is separate from the emit path

cudabom's CycloneDX emitter is serialize-only and uses `&'static str` for fixed
fields, so it cannot round-trip as a reader. Rather than contort the emitter,
the ingest model (`cudabom_sbom::DeclaredBom`) is a deliberate, permissive
*deserialize* counterpart that reads only `components` and `vulnerabilities`
(with `analysis.state` + `affects`) and ignores unknown fields, tolerating any
CycloneDX spec version and NGC's full surface.

### Comparison is by canonical identity, not spelling

Third parties name CUDA components inconsistently (`cuda-cudart`, `libcublas`,
`libcublas-12-4`, `libcudart.so.12`, `pkg:generic/cuda-cudart@...`).
`cudabom_identify::canonicalize_declared_name` normalizes all of these to the
same canonical vocabulary the fingerprint DB uses, grounded in the reviewed
component-profile table, so declared and discovered inventories line up by
identity. Declared entries that do not resolve to a known CUDA component are
counted (`non_cuda_declared`) but never treated as CUDA findings.

### NGC fetch is opt-in and key-gated; reconcile is offline by default

The NGC SBOM/VEX endpoints require an API key (401 otherwise). So the *fetch*
path (`--ngc-image org/repo:tag` + `--ngc-api-key`/`NGC_API_KEY`) is strictly
opt-in and is the only networked path; the `--sbom`/`--vex` file inputs stay
fully offline and are how the logic is tested (committed `fixtures/ngc/`). The
fetch reuses the shared `cudabom-fetch` primitive (retry/backoff), extended with
an optional request-headers field for the `Authorization: Bearer` header; a
missing VEX (404) is tolerated since not every image publishes one.

---

## 2026-09-30 - Advisory verdicts on the composition tree; toolkit correlation

### Per-node advisory verdicts in the binary composition view

The composition view already grouped findings per file into `links`
(`NEEDED` deps) and `contains` (embedded/static copies). It carried identity but
not risk. Decision: annotate each composition node with the advisory verdicts
for its component (`affected`/`not_affected`/`under_investigation`), joined by
component name because a verdict is a property of the (component, version)
identity the node already carries. Surfaced in both scan JSON (`advisories[]` on
each node) and the table (`advisories: verdict(id), ...` suffix). This makes the
74 ingested advisories usable at a glance per binary without changing the
identification engine.

### CSAF version parsing: "Update N" and compact "U<n>" become a patch component

NVIDIA's CSAF version descriptors carry more precision than a bare `X.Y`:
`11.6 Update 2` means `11.6.2`, and the compact inline form `12.5U1` means
`12.5.1`. The prior parser dropped both, weakening every affected/fixed bound.
Decision: `clean_version` now recognizes a word `Update N` suffix and a compact
`U<n>` suffix, mapping either to the next dotted component. This tightened real
bounds (e.g. CVE-2022-21821 `11.6` -> `11.6.2`; CVE-2024-0102 `12.5` -> `12.5.1`)
and is exhaustively tested. Unparseable text still yields an open range that the
index loader rejects rather than matching everything.

### Library-version -> toolkit-release mapping (resolves the prior follow-up)

`cuda-toolkit` advisories are keyed to a CUDA *release* (e.g. `11.4.2`), while a
scanned library is keyed to its own version (cudart `11.4.108`). Without a
bridge, toolkit CVEs never reached individually-scanned libraries. The grounded
bridge already exists in NVIDIA's data: every redist manifest states its
`release_label`, tying each component's exact version to the CUDA release that
shipped it.

Decision: derive that mapping first-party during `xtask fingerprints build` and
commit it in each fingerprint shard as `ComponentFingerprint.release_versions`
(`version -> [release labels]`). At scan time (fully offline), the matcher's new
`match_finding_via_toolkit` synthesizes an EXACT `cuda-toolkit` query at the
finding's shipping release and evaluates it against the toolkit advisories,
tagging each indirect result with `via_toolkit_release` for transparency. Only
`affected`/`under_investigation` verdicts are surfaced indirectly (a per-library
"not affected by this toolkit CVE" would be noise). Verified end-to-end: a real
`libcudart.so.11.4.108`, identified by its bytes, correlates against 28 real
`cuda-toolkit` CVEs via CUDA toolkit release 11.4.2, and correctly excludes
those fixed at or below the shipping release.

Alternatives rejected: (a) inferring the release from the library version alone
(not first-party, and library and toolkit version spaces differ); (b) a separate
committed mapping file (redundant with the manifest data already flowing through
the fingerprint derivation, and would drift).

---

## 2026-09-30 - Real NVIDIA CSAF ingestion; stale-sidecar policy

### Handle NVIDIA's actual product-tree shape

Running `db update` against the real `NVIDIA/product-security` repo revealed the
product tree does not match the simple nested form our fixtures assumed. NVIDIA
places the `product_name` branch (e.g. `TensorRT`, id `all_tensorrt`) and the
`product_version` branches in *sibling* subtrees, linked only by a product-id
naming convention (`all_tensorrt_v10_16_1` is prefixed by `all_tensorrt`), and
the version text lives in the leaf `product.name` (`v10.16.1`), not the branch
name. Path inheritance alone attributed versions to grouping labels like
`NVIDIA` or `All`, so zero CUDA advisories mapped.

Decision: a two-pass collection. First gather `product_name` ids -> family name;
then, for any version product whose resolved name is a weak grouping label,
re-link it to the longest product-name id that prefixes it. Version descriptors
are parsed into ranges (`v`/`V` stripped; "prior to X"/"before X"/"< X" become
an upper bound). This lifted mapping from 0 to 74 real advisories
(`cuda-toolkit`, `tensorrt`, `nvjpeg`). The heuristics are conservative:
unparseable version text yields an open range that the index loader rejects
loudly rather than matching everything.

Known follow-up: `cuda-toolkit` advisories are keyed to the CUDA *toolkit*
version (11.6, 12.1, ...), a different version space than our per-library
fingerprints (cudart `12.4.127`, npp `12.2.5.30`). Correlating them will need a
library-version -> toolkit-release mapping; deferred as its own decision.

### A stale upstream sidecar skips one document, not the whole build

NVIDIA occasionally re-publishes a CSAF document without regenerating its
`.sha256` sidecar, so a handful of sidecars are stale (present but mismatching).
Aborting an entire nightly refresh over one stale sidecar is too brittle.

Decision: the pinned commit SHA is the primary, content-addressed integrity
anchor over the whole tree; the per-file sidecar is a secondary check. When a
sidecar is present but mismatches, skip that one document and report it loudly
(`Ingest::integrity_skipped`, surfaced on stderr and reviewable in the refresh
PR), rather than failing the run. A *missing* sidecar remains non-fatal as
before; a *matching* one is still required to pass.

---

## 2026-09-30 - Per-binary composition view; NVIDIA source hierarchy of record

### Composition is derived from findings, not a new pass

"Which CUDA components does this binary link vs contain?" is answered without
any new parsing. Every `Finding` already records the file it was observed in
(`evidence[].location.path`) and a `Relationship`. The composition view
(`cudabom::commands::composition`) groups findings by that path and maps
`DynamicDependency -> links` and `EmbeddedCopy`/`StaticallyLinked -> contains`.

This keeps the evidence model the single source of truth: `identify_file` and
the `Finding` type are unchanged, so the composition can never disagree with the
findings list or `cudabom explain`. `DeclaredOnly` is intentionally not a
composition edge (it is not a byte-level fact); unmodeled future relationships
are conservatively skipped.

Surfaced as a `composition` section in `scan` JSON and the table view. On the
SBOM side, rather than restructuring the CycloneDX dependency graph (which would
churn the VEX/enrich paths), each component gains a `sourceFile` property tracing
it back to its binary; the existing subject `dependsOn` edges (embedded/static
vs dynamic) are retained.

Alternatives rejected: (a) a second analysis pass to build a dependency tree:
redundant with findings and a second source of truth; (b) recursive `NEEDED`
resolution now: valuable later, but the direct-edge view is the high-leverage
first step and needs no dependency resolver.

### NVIDIA redistributable manifests are the canonical corpus source

Recorded the full source hierarchy in `docs/sources.md`: redistrib JSON
manifests are canonical for component/release/hash inventory and drive the
fingerprint corpus; package repos, Repo Channels/CDN, Product Security CSAF, and
NGC are secondary/parallel feeds each scoped to a specific purpose. The manifest
is treated as a versioned, hash-addressable catalog (not a "stream"), giving the
evidence chain manifest -> archive -> observed facts -> derived fingerprint. No
NVIDIA binaries are committed; scanning stays offline by default.

---

## 2026-09-30 - First live binary derivation; SONAME allowlist for attribution

### Only libraries a component is reviewed to own are attributed to it

Running the subset-first corpus flow against the real `cuda_cudart` 11.4.108
archive surfaced a correctness issue: NVIDIA archives bundle extra shared
objects that do not belong to the named component. The `cuda_cudart` tarball
ships a `libcuda.so` driver *stub* and `libOpenCL.so` alongside the actual
`libcudart.so`. The binary-derivation step originally fed *every* `.so` in the
archive to `fingerprint_binary` with the component's provenance, which would
have attributed `libOpenCL.so`'s soname/build-id/hash to `cudart`: a false
positive waiting to happen (any artifact linking OpenCL would "match" cudart).

Decision: attribute a `.so` to a component only when its `DT_SONAME` stem is on
that component's reviewed allowlist (`soname_stems_for`, backed by the same
profile table as `resolve_component`). The stub and OpenCL libraries are read
and hashed but discarded because their stems are not on cudart's list. This
keeps attribution a documented fact rather than "whatever was in the tarball",
and shares one source of truth with the manifest-derivation and lockfile paths.

Result: the committed `fingerprints/cuda/redistrib_11.4.2.json` shard now
carries the real GNU build-id (`d7f9d083...`) and file sha256
(`f9a9d13a...`) of `libcudart.so.11.4.108`, verified against the archive whose
digest matches NVIDIA's signed manifest (`d08a1b7...`). No NVIDIA binaries are
committed; only the derived signals are.

Alternatives rejected: (a) trusting archive contents wholesale: produces false
attributions; (b) filtering by file path heuristics (e.g. skip `stubs/`):
fragile and still guesses; (c) a separate `libcuda`/`opencl` profile: out of
scope and would claim identity for libraries cudabom does not intend to own yet.

---

## 2026-09-30 - explain command and CSAF ingestion (offline)

### Data stores are JSON source-of-truth; no database dependency

The fingerprint shards (`fingerprints/cuda/*.json`), the advisory index
(`advisories/index.json`), and the corpus lockfiles
(`fingerprints/corpus.<version>.lock.json`)
are all committed JSON, deliberately not a database file (e.g. SQLite). The
entire freshness model rests on a human reading a PR diff (nightly refresh,
"never invent fingerprints", per-shard provenance); a binary DB file would make
that diff meaningless and produce unresolvable merge conflicts. Scale does not
force the issue: even all CUDA releases × components × build-ids is tens of
thousands of entries, trivial for an in-memory `BTreeMap`. Mature scanners
(Grype, Trivy) keep their *source* data as text in git and compile a runtime DB
only as a derived, shipped release artifact; so if cold-load time ever becomes
a *measured* problem, the answer is a derived, gitignored packed cache built at
release time, never a replacement of the reviewable JSON source and never a
hand-edited database. Until a benchmark shows a need, the loaders read JSON
directly. This avoids a C-backed dependency that would also fight
`#![forbid(unsafe_code)]`.

### The fingerprint database is derived from NVIDIA redist manifests and sharded per release

cudabom must never invent fingerprints, so the version/hash layer of the
fingerprint DB is derived from NVIDIA's own signed CUDA redistributable
manifests (`redistrib_<version>.json`), which state exact `version` <-> archive
`sha256` for every component. `cudabom-identify::redist` parses them and
`::derive` turns them into `FingerprintDb` entries, but only for components in a
small **reviewed profile table** that maps a manifest key (`cuda_cudart`) to a
canonical component (`cudart`) and its SONAME stems (`libcudart.so`). Keys with
no profile (e.g. `cuda_nvcc`, a compiler that ships no shared library) are
reported as `underived`, never given a fabricated stem.

The derived data is **sharded one file per upstream manifest** under
`fingerprints/cuda/redistrib_<version>.json`, so a shard's name is its
provenance and a refresh produces a small, reviewable diff; this matches how
Trivy/Grype/osv-scanner shard their data and avoids the unbounded-growth and
noisy-diff failure modes of a single monolithic file. The loader
`FingerprintDb::from_dir` merges all shards in sorted order into one in-memory
database, deduplicating stems and recording any hash->version collisions in a
`MergeReport` rather than silently overwriting (first shard wins,
deterministically). NVIDIA's per-release manifests are consumed as-is (we do not
merge upstream); only cudabom's derived output is sharded by our choice.

Honesty of scope: a manifest sha256 is of the published *archive* (`*.tar.xz` /
`*.zip`), so a derived `file_hashes` match proves "these bytes are the published
`cudart` 11.4.108 archive" and fires when scanning the archive itself.
Identifying a `.so` unpacked from that archive needs the separate,
binary-derived build-id/hash layer and is not claimed from the manifest.
`cargo xtask fingerprints build` performs the derivation; the committed shards
are regression-tested against real NVIDIA sha256 ground truth
(`crates/cudabom-identify/tests/real_fingerprints.rs`).

### The advisory index is a vendored, reviewed snapshot refreshed by nightly PR

Scans read a committed `advisories/index.json`, never the live network. This is
the model mature scanners use (Trivy, Grype, osv-scanner all ship a vendored DB)
and it reconciles two conflicting goals: reproducibility (a scan must give the
same verdicts given the same inputs, which requires a frozen, pinned snapshot)
and freshness (the snapshot must not go stale). A nightly job
(`.github/workflows/advisory-refresh.yml`) advances the pin: it resolves NVIDIA's
newest `main` commit to an immutable SHA, rebuilds the index via `db update`, and
opens a PR when the result changes. Merging, a human reviewing the diff, is the
only moment the consumed index changes, so every update is auditable and no user
scan silently depends on network availability or a moving upstream. Alternatives
rejected: auto-committing to `main` (no review gate on security-relevant data)
and making each scan hit the network (non-reproducible, offline-hostile, and it
would hammer NVIDIA's host).

### `db update` synthesizes a CSAF manifest from the repository tree

NVIDIA publishes machine-readable CSAF bulletins in `NVIDIA/product-security`
but implements none of the CSAF 2.0 discovery mechanisms (no
`/.well-known/csaf/provider-metadata.json`, no ROLIE feed, no DNS record, no
`security.txt` entry). This was verified against the upstream repo and
corroborated by third-party CSAF aggregators that classify NVIDIA as needing a
custom feeder. There is therefore no vendor manifest to follow, and, crucially,
no need to download any redistributable binary packages to learn what is
vulnerable; the CSAF documents themselves carry the affected-version data.

So cudabom synthesizes the manifest. The default `manifest` mode issues one Git
Trees API call for a pinned commit (a complete, machine-readable file inventory),
filters it to CSAF documents by the `<year>/<id>/<id>.json` path convention, and
fetches only those files over `raw.githubusercontent.com`, verifying each against
its published `.sha256` sidecar. This avoids pulling the markdown/CVE siblings
and enables future incremental updates by comparing tree SHAs. A `tarball` mode
(whole-repo archive, unpacked in memory) is retained as an air-gap / mirror
fallback and for a single-request capture. Both modes feed the same offline
`ingest` path, so ingestion has one tested implementation. Integrity rests first
on the pinned commit SHA (content-addressed over the tree); `--rev` must always
be a reviewed commit, never a branch, so the source cannot move underneath a
build. This supersedes the earlier "network fetch not added yet" decision below.

### `explain` reuses the pipeline and reads findings as-is

`cudabom explain` runs the same shared scan pipeline as `scan`/`gate` and simply
renders one finding's evidence chain. It adds no new identification logic: the
finding already carries its evidence, so `explain` is a pure view. An unknown
`--id` is a usage error (exit 2) that lists the available ids, rather than
failing silently or succeeding with empty output.

### CSAF ingestion is offline-first; the network fetch is a separate, deliberate step

`docs/advisories.md` describes `db update` fetching CSAF over the network. The
valuable, verifiable core of that (parsing CSAF 2.0 into the normalized index
and mapping products to components) is entirely offline and is what landed
here as `cudabom db build`. The network fetch (an HTTP dependency, a pinned
upstream revision, `.sha256` verification) is intentionally *not* added yet:
`db update` is declared and returns a clear "not enabled" message pointing at
`db build` against a local CSAF mirror. This keeps the dependency graph lean and
every byte of ingestion behavior unit-testable with CSAF fixtures.

### CSAF parsing tolerates unknown fields; mapping never guesses

The CSAF serde model omits `deny_unknown_fields`: real CSAF documents carry far
more than the subset cudabom needs, and ingestion must tolerate it. Conversely,
product resolution is strict: a CSAF product with no product-map entry is
recorded in the `unmapped` set (surfaced by `db status` and on stderr during
`db build`), never guessed or silently dropped. An advisory whose affected
products are all unmapped produces no index entry, but its products are still
reported so the map can be extended.

### Product map is JSON, not TOML

`docs/advisories.md` sketched the map as `product-map.toml`. It shipped as
`advisories/product-map.json` instead: the rest of cudabom's tunable inputs
(fingerprint DB, advisory index, policy) are JSON, and reusing JSON avoids
adding a TOML parser dependency for one small file. The matching semantics
(normalized exact + ordered substring rules) are unchanged from the doc's
intent.



### VEX verdict -> CycloneDX `analysis.state` mapping

`cudabom vex` emits a CycloneDX 1.6 VEX document: the SBOM of identified
components plus a `vulnerabilities` array. Advisory verdicts map to the
CycloneDX impact-analysis state honestly: `affected` -> `exploitable` (the
version is within an affected range), `not_affected` -> `not_affected`, and
`under_investigation` -> `in_triage`. Each statement's `affects` points at the
bom-ref of the matching component. A verdict whose component was not found is
still emitted with an empty `affects`, so a claim is never silently dropped. The
SBOM crate stays independent of the advisory database via a neutral `VexVerdict`
input type; the CLI does the mapping.

### Enrichment parses generic JSON to avoid corrupting the input SBOM

`cudabom enrich` adds discovered components to an existing CycloneDX document
without depending on our own (partial) CycloneDX model for *reading*. It parses
the input as generic `serde_json::Value`, so every field we do not model
(licenses, hashes, external references, custom fields, a pre-existing serial
number) is preserved byte-for-byte in the output. We only append to
`components[]` and touch `metadata.tools.components`. Duplicates are skipped by
purl or by name+version so re-running enrichment is idempotent for a given
component. If `metadata.tools` uses the deprecated array-of-tools shape, we
leave it untouched rather than risk corrupting a valid document.

### VEX and enrich are reporting actions, not gates

Both commands exit `0` on success regardless of what they find; they produce
documents, they do not enforce. Enforcement is `cudabom gate`'s job. This keeps
the exit-code contract clean: only `scan` (on positive identification) and
`gate` (on policy violation) return the `Findings` code. (Superseded: `scan`
now defaults to exit `0` and returns `Findings` only under `--fail-on
found|affected`; see the `scan --fail-on` entry in `CHANGELOG.md`.)



### Secure-by-default policy; every relaxation is explicit and justified

`cudabom-policy` turns a scan result into a pass/fail decision for `cudabom
gate`. The built-in default (`Policy::secure_default`, used when no `--policy`
is given) fails the gate on any `affected` advisory verdict and nothing else:
identification alone and `under_investigation` verdicts do not block, so a
partial advisory index cannot wedge a pipeline. Tightening is opt-in
(`min_confidence`, `under_investigation: true`), and every allowlist entry
*requires* a non-empty `reason` and must name an advisory and/or component;
`Policy::from_json` rejects empty reasons and no-op entries at load time. The
`Decision` records both standing violations and the exemptions that were applied
(with their reasons), so a gate result is self-explaining and auditable.

### Allow scoping avoids accidental over-exemption

An allow entry matches only when every field it sets matches: an
advisory-scoped exemption never suppresses a *different* advisory's verdict for
the same component, and a component-only exemption applies across that
component's findings. This keeps `allow` narrow by default: a tester can't
silence CVE-B by exempting CVE-A.

### Policy stays independent of the advisory DB

As with `cudabom-report`, the policy crate depends only on `cudabom-core` (plus
serde) and consumes advisory results through a neutral `AdvisoryVerdict` type;
the CLI maps `cudabom_advisory::Match` into it. This preserves the architecture
boundary that the enforcement layer does not depend on the advisory database.

### One scan pipeline for `scan` and `gate`

`scan` and `gate` need identical underlying work (extract -> facts -> identify
-> correlate). Rather than duplicate it, that logic and the shared loaders now
live in `commands/pipeline.rs`, returning a neutral `PipelineOutcome` that each
command renders or enforces on. The commands cannot drift in what they discover;
they differ only in what they do with the result.



### `cudabom-report` renders findings; it does not depend on the advisory DB

`docs/architecture.md` states the reporting layer must not depend on the
advisory database. To honor that while still rendering advisory verdicts, the
report crate defines a neutral `AdvisoryVerdict` type and a `Report<'a>` input
struct; the CLI maps `cudabom_advisory::Match` into these before rendering. So
`cudabom-report` depends only on `cudabom-core` (plus serde), and the advisory
coupling lives at the CLI seam where the data is already assembled.

### SARIF `level` reflects actionability, not intrinsic severity

cudabom does not assign CVSS. The SARIF renderer maps to `level` by how much a
result should prompt action: an `affected` advisory verdict is `error`; an
`under_investigation` verdict and an `Exact`/`Likely` identification are
`warning`; an `Unknown` identification and a `not_affected` verdict are `note`.
Rules are a fixed catalogue (one per confidence, one per verdict) so `ruleId`s
are stable and results are groupable in code-scanning UIs. The SARIF serde model
is a hand-written subset of the 2.1.0 schema rather than a dependency, matching
the lean approach already taken for CycloneDX in `cudabom-sbom`.

### Markdown is PR-comment-shaped and injection-safe

The Markdown output is built for a PR/MR comment: a heading with counts, a
findings table, and an advisory table followed by the standing coverage caveat.
Table cells are escaped (pipes and newlines) so a hostile or unusual value in a
component name or justification cannot break the table or the surrounding
comment. Output is deterministic (the caller sorts findings; verdicts are
rendered in the order given), so snapshot tests and diffs stay meaningful.



### Conservative VEX verdicts, matched to identification confidence

`cudabom-advisory` correlates findings against a normalized advisory index and
emits VEX-style verdicts (`affected` / `not_affected` / `under_investigation`).
The matching rules deliberately mirror the identification confidence model so a
verdict is never stronger than the evidence behind the finding:

- **Exact** version -> tested directly against affected/fixed ranges. An exact
  version outside every affected range is reported `not_affected` *for that
  advisory* (its ranges are exhaustive for what it covers). An exact identity
  with an unparseable version degrades to `under_investigation` rather than a
  guess.
- **Likely** with a major-only version (`12.x`) -> a definitive verdict only
  when the *entire* major series is on one side of the boundary
  (`contains_entire_major` / `excludes_entire_major`); a straddling series is
  `under_investigation`.
- **Unknown** -> the component name may match, so it is surfaced as
  `under_investigation`, but never as affected/not-affected.

Absence of any match is never a safety claim: `match_findings` returns only
positive verdicts, and `cudabom scan --advisories` always prints the caveat that
advisory coverage may be incomplete.

### A purpose-built version comparator, not `semver`

CUDA component versions are dotted numeric strings (`12`, `12.4`, `12.4.1`) that
do not follow full semver (no pre-release/build semantics, and `12.x` major
ranges are common). Rather than pull the `semver` crate and fight its
assumptions, `version.rs` is a small comparator: components compared left to
right as integers, trailing components treated as zero. Equality and ordering
are made consistent by hand (`PartialEq` delegates to `Ord`), so `12.4` equals
`12.4.0` under both `==` and comparison: a bug the derived `PartialEq` would
have introduced. This is exhaustively unit-tested, including the entire-major
boundary logic.

### Normalized index, not raw CSAF, at scan time

The advisory index consumed by a scan is a compact, schema-versioned JSON file
(`AdvisoryIndex` with per-component affected/fixed ranges), not raw CSAF. CSAF
2.0 documents are verbose and varied; parsing them every scan is wasteful and
couples the hot path to upstream format churn. The plan (see `docs/advisories.md`)
is for the explicit, network-using `cudabom db update` to parse and verify CSAF
once and write this index; a scan loads it read-only via `--advisories`. Bad
range data fails loudly (`SerdeRange::to_range` returns `None` on an unparseable
bound) rather than silently matching everything.



### Identification is data-driven; identity is never invented

- **The fingerprint database defines shape, not contents.** `cudabom-identify`
  ships an empty database by default and loads derived data (file hashes,
  build-ids, SONAME stems, version markers) from JSON via `--db`. The code never
  hardcodes a component identity, honoring the spec's rule against invented
  fingerprints.
- **Structural signals are separated from fingerprint knowledge.** The
  SONAME-grammar matcher parses `libNAME.so.MAJOR` purely from the string (this
  is documented Linux convention, not invention). On its own it yields nothing;
  only when the database knows the stem does it name a component, and then only
  at `Likely` with a major-version *range* (`12.x`), never a guessed exact
  version. A bare `NEEDED` entry is `Unknown`. A file-hash or build-id match is
  `Exact`. This implements the confidence rules in `docs/evidence-model.md`.
- **`FileFacts` is the neutral hand-off** between extractors and the matcher, so
  the identify crate does not depend on the extractor and the CLI assembles the
  input from whatever it gathered.

### Cross-platform SONAME/NEEDED testing without a linker

- **A hand-built ELF-with-`.dynamic` byte fixture** (`tests/common/dynamic_elf.rs`)
  exercises SONAME/NEEDED parsing on every host. The `object` writer cannot
  synthesize `.dynamic`, and a real linker emits ELF only on Linux, so the
  fixture is the only way to cover this path locally. Building it also surfaced
  and fixed a real parser bug: the dynamic string table was resolved via the
  wrong section index; it now locates the `SHT_DYNAMIC` section and reads its
  `sh_link` directly.

### CycloneDX by direct serialization, not a heavy crate

- **`cudabom-sbom` emits CycloneDX 1.6 JSON via serde types**, not a CycloneDX
  library. The schema is stable and the subset we emit is small, so modeling the
  fields directly keeps the dependency tree lean (consistent with the initial
  decision to defer heavy crates). Output is **deterministic**: components are
  sorted, the `serialNumber` is a content-derived UUID, and the timestamp is
  omitted unless supplied, so the same scan produces byte-identical BOMs.
- **cudabom facts ride along as namespaced properties** (`cudabom:confidence`,
  `cudabom:relationship`, `cudabom:evidence.N`) so confidence and evidence
  survive in any CycloneDX consumer. Embedded/static copies become dependency
  edges *of* the subject; dynamic dependencies are edges the subject depends on.
  A purl is emitted only when the version is known, to avoid a misleading
  versionless identifier.

---

## 2026-09-30 - Safe extraction and ELF fact layers

### MSRV raised 1.82 -> 1.85

- **`rust-version` is now 1.85.** The `object` crate (the ELF/PE/Mach-O reader
  we adopted) requires Rust 1.85, and it is the right tool for panic-free
  parsing of untrusted binaries. Since cudabom has no external library consumers
  yet and CI builds on stable, raising the floor is cheaper than pinning an
  older, less-maintained `object`. Revisit only if a downstream packager needs
  an older toolchain.

### Extraction dependency choices

- **`zip` + `tar` + `flate2` for archives, `walkdir` for directories,
  `sha2` for hashing, `object` for ELF.** Each is centrally pinned and audited
  via `cargo deny`. Alternatives considered: `goblin` for ELF (rejected for now:
  `object` has a cleaner, generic `FileHeader` API that handles ELF32/64 and
  both endiannesses in one code path); hand-rolled inflate (rejected: reinventing
  audited codec code is a liability). `zip` is pinned to the `2.x` stable line;
  `9.0.0-preN` is a pre-release and deliberately avoided.
- **The safety envelope is enforced by a `Budget`** (in `cudabom-core::config`)
  threaded through the whole traversal, so the aggregate byte cap and entry
  counts hold across *nested* archives, not just per archive. Per-file size and
  decompression-ratio caps are checked before and during decompression, and
  reads are hard-capped at `max_file_bytes + 1` so a lying header cannot overrun.

### Extraction safety posture

- **Nothing is written to disk or executed.** Members are materialized in memory
  and handed to a visitor. Archive entry names are sanitized (no absolute paths,
  no `..`, no Windows drive/UNC), and tar symlink/hardlink/device entries are
  skipped rather than followed; this is what prevents zip-slip and link-based
  escapes. Directory walks never follow symlinks and skip `node_modules`/VCS
  dirs. The behavior is proven by an in-memory malicious-archive test suite
  (zip-slip, absolute paths, per-file/aggregate/ratio caps, entry-count cap,
  gzip bomb, symlink escape, deep nesting).

### ELF facts

- **Facts, not identity.** `cudabom-elf` reports only what is literally in the
  bytes: class/endian/type/arch, `DT_SONAME`, `DT_NEEDED`, run paths, GNU
  build-id, section names, exported dynamic symbols, and (opt-in) bounded rodata
  strings. Turning these into component identity is the identify crate's job.
- **Hermetic tests without committed binaries.** Parser tests build real, valid
  ELF bytes with `object`'s writer (works on macOS too). The dynamic-section
  facts the writer cannot synthesize (SONAME/NEEDED/build-id) are covered by a
  Linux-gated test that compiles a real `.so` with the system toolchain, so no
  binary fixtures are committed and the spec's no-invented-facts rule holds.

### `scan` wiring

- **`cudabom scan` now runs extract -> ELF facts -> report.** It emits a
  deterministic JSON fact dump (`--format json`) or a table
  (`--format table`); SBOM/SARIF/markdown formats are declared but return a
  clear "not implemented yet" error until the identity/SBOM stages land. A
  malformed or oversized artifact maps to the documented `Input` (3) exit code,
  not a crash.

### GPU code inventory (fatbin / PTX)

- **Parse only what is verifiable; bounds-check everything.** The fatbin wrapper
  magic (`0xBA55ED50`), version/header-size/payload-size fields, and entry
  kind codes (PTX=1, ELF/cubin=2) are documented and stable, so those are read
  and interpreted. Entry fields whose exact semantics are less certain (e.g. the
  SM architecture slot) are read defensively and omitted when out of bounds
  rather than guessed, honoring the spec rule to derive behavior from real bytes
  and fixtures, not assumptions. Every read goes through a panic-free
  bounds-checked `Reader`; entry counts are capped; lying payload sizes are
  clamped to the bytes actually present.
- **PTX is parsed as documented text.** Only the leading `.version`,
  `.target sm_NN`, and `.address_size` directives are read, from a bounded
  prefix, since that is all the header carries and scanning the whole module
  would cost more than it is worth.
- **Embedded fatbins are found by scanning for the wrapper magic** across an ELF
  and validating each candidate by fully parsing it, so a false-positive magic
  that does not parse is skipped. This catches fatbins regardless of the exact
  `.nv_fatbin`/`__nv_fatbin` section naming.

---

## 2026-09-30 - Initial scaffold

### Language and toolchain

- **Rust, stable, pinned via `rust-toolchain.toml`.** The shipped analyzer is
  100% Rust; it never runs on a GPU and never executes what it scans. Rust
  gives memory-safe parsers for hostile input and a single easy-to-ship binary.
- **`rust-version` (MSRV) pinned to 1.82.** Chosen as a recent-but-not-bleeding
  floor. Alternatives: track stable only (rejected: no reproducibility signal
  for downstream packagers) or pin much older (rejected: gives up useful
  language features for little benefit). Revisit if a dependency needs newer.

### Workspace shape

- **Cargo workspace with `crates/cudabom-*` + `xtask`, not a single crate.**
  The problem decomposes cleanly (extract / elf / fatbin / identify / advisory /
  sbom / report / policy) and separate crates keep dependencies scoped: the ELF
  parser does not pull in the archive stack, etc. The alternative (one crate
  with modules, like the sibling `grackle` tool) is simpler but would couple the
  whole dependency graph together and slow incremental builds. All crate stubs
  are created up front so downstream crates compile against a stable surface.
- **`cudabom-core` is dependency-light** (only `serde` + `thiserror`). It owns
  the shared vocabulary every crate speaks, so it must not drag heavy parsers
  into everyone's build.

### Configuration is centralized and tunable

- **Dependencies and lints are declared once** in the root `Cargo.toml`
  (`[workspace.dependencies]`, `[workspace.lints]`) and inherited by every crate
  with `.workspace = true`. This is the single place to bump a version or change
  lint policy.
- **Runtime safety limits live in one struct** (`Limits` in
  `cudabom-core/src/config.rs`): nesting depth, byte caps, decompression ratio,
  entry count, per-file timeout. It is serde-deserializable with
  `deny_unknown_fields` so a typo'd knob fails loudly and a partial config falls
  back to documented defaults. This keeps the safety envelope tunable from one
  file instead of scattered constants.
- **`rustfmt.toml`, `clippy.toml`, `deny.toml`** each own their domain's knobs.

### Lints

- **`unsafe_code = "forbid"` workspace-wide.** Any exception must be justified in
  this file before the lint is relaxed for a specific spot.
- **clippy `pedantic` on, with a few opt-outs.** `doc_markdown` is allowed
  because domain prose is full of proper acronyms (CycloneDX, SARIF, CSAF, PEP
  770) that are not code items; `module_name_repetitions`, `must_use_candidate`,
  `missing_errors_doc`, and `missing_panics_doc` are allowed as low-value noise
  for a CLI.

### Release profile

- **`lto = true`, `codegen-units = 1`, `strip = true`, `panic = "abort"`.**
  Optimizes for a small, fast, single binary. `panic = "abort"` is acceptable
  because the tool is a batch CLI, not a library embedded in a host that needs
  to catch unwinds; parsers return errors rather than panicking anyway.

### Dependency choices (initial set only)

- `clap` (derive) for the CLI, `anyhow` for the binary's error plumbing,
  `thiserror` for the library error type, `serde`/`serde_json` for data.
- Heavier crates (`goblin`, `zstd`, `rayon`, `insta`, `proptest`, `schemars`,
  CycloneDX/SARIF crates) are still NOT added; they come in with the code that
  needs them. The extraction/ELF set (`object`, `zip`, `tar`, `flate2`, `sha2`,
  `walkdir`, `memchr`) was added with the fact layer; see the 2026-09-30 entry
  above.

### Deferred

- **Hugo docs site** (like the sibling tools' `.hugo/`): deferred until there is
  real content to publish. `docs/` holds the source-of-truth Markdown now.
- **PyPI (maturin), container image, GitHub Action repo, crates.io publish:**
  scaffolded in the release workflow but not enabled until credentials exist and
  a dry run passes. We do not reserve external names or publish without
  approval. The publish-* jobs are guarded on repository variables
  (`PUBLISH_CRATES`, `PUBLISH_HOMEBREW`, `PUBLISH_SNAP`) so they stay dormant
  until deliberately switched on.

### Fingerprint corpus and NVIDIA binaries

The identity work needs fingerprints derived from real NVIDIA binaries, and the
spec forbids inventing them. The chosen approach:

- **Never commit NVIDIA binaries.** Downloads land in gitignored scratch dirs
  (`/.fingerprint-cache/`, `/fingerprints/downloads/`, `/corpus/`) and are never
  added to the repo, honoring NVIDIA's license terms and keeping the tree clean.
- **Commit only derived data** under `fingerprints/` as reviewable JSON/TOML:
  sha256 hashes, exported/internal symbol sets, version-string patterns, and
  build-ids, plus provenance (source URL, package, version, platform, arch,
  checksum, collection date) recorded under `docs/fingerprints/`.
- **Derivation is an explicit, pinned `cargo xtask fingerprints build` step**,
  not part of a normal scan or normal CI. It verifies each redistributable's
  checksum before deriving, so the process is reproducible and auditable without
  redistributing NVIDIA code.

This is built out with the identity work; the extractor and ELF/fatbin fact
layer come first and require no NVIDIA binaries at all.
