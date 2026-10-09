# Fingerprint database

cudabom identifies CUDA components from *derived* data, never from committed
NVIDIA binaries. This document describes how the database is built, what is
stored, and the licensing constraints.

## What is stored (and what is not)

Committed under `fingerprints/`, as reviewable JSON/TOML:

- sha256 hashes of known official redistributable files,
- exported and internal symbol sets,
- version-string patterns (with the exact pattern and where it was observed),
- GNU build-ids.

Every entry records provenance: source URL, package, version, platform,
architecture, checksum, and collection date (recorded here under
`docs/fingerprints/`).

**Never committed:** the NVIDIA binaries themselves. They are downloaded into
gitignored scratch directories (`/.fingerprint-cache/`,
`/fingerprints/downloads/`, `/corpus/`), used to derive the data above, and left
out of the repository. cudabom neither includes nor redistributes NVIDIA
binaries or NVIDIA proprietary tools.

## How it is built

The binary layer derives from real redistributable bytes, which are fetched and
verified by the separate `corpus` tasks (never committed, see
[`../../fingerprints/README.md`](../../fingerprints/README.md)):

```bash
# Fetch + verify the pinned archives into ./corpus (gitignored).
cargo xtask corpus fetch --lock fingerprints

# Derive the fingerprint shards from the unpacked corpus.
cargo xtask fingerprints build --corpus corpus
```

The combined steps:

1. `corpus fetch` downloads the pinned official NVIDIA redistributables (e.g.
   `nvidia-*` wheels from PyPI, conda packages, CUDA redist archives) listed in
   the committed lockfiles and verifies each against its recorded checksum.
2. `fingerprints build` unpacks the fetched corpus and derives hashes, symbol
   sets, version patterns, and build-ids.
3. It writes the derived entries to `fingerprints/` and provenance here.

The download is explicit and pinned; it is not part of a normal scan or normal
CI run. This keeps the derivation reproducible and auditable without
redistributing NVIDIA code.

## Adding a fingerprint

See the "How to add a fingerprint" section of
[`../../CONTRIBUTING.md`](../../CONTRIBUTING.md).

## Licensing

Respect NVIDIA's license terms for every redistributable used. Only derived,
non-reconstructive data is committed. If in doubt about whether a piece of
derived data is permissible to publish, leave it out and open a discussion.
