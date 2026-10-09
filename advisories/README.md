# Advisory data

This directory holds the reviewed, maintained inputs that turn NVIDIA CSAF
security bulletins into cudabom's normalized advisory index.

## `product-map.json`

Maps CSAF product identities (NVIDIA's product vocabulary) to cudabom canonical
component names. Matching is case-insensitive and whitespace-normalized:

- `exact`: a normalized product name maps directly to a component.
- `rules`: ordered substring rules, checked after exact matches. CSAF product
  names often embed a version (e.g. `NVIDIA CUDA Toolkit 12.4`), so a substring
  rule like `cuda toolkit` catches the family regardless of version.

A product with no mapping is never guessed. `cudabom db status` lists unmapped
products so this file can be extended.

## Building an index from local CSAF

```
cudabom db build --from <csaf-file-or-dir> --map advisories/product-map.json -o index.json
cudabom db status --from <csaf-file-or-dir> --map advisories/product-map.json
```

`db build` writes the normalized index consumed by `cudabom scan --advisories`,
`cudabom gate --advisories`, and `cudabom vex --advisories`. `db status` reports
which products mapped and which did not.

## Fetching CSAF from upstream: `db update`

NVIDIA publishes machine-readable CSAF bulletins in the
[`NVIDIA/product-security`](https://github.com/NVIDIA/product-security)
repository (per-year directories, since October 2025) but provides **no CSAF
discovery manifest**: there is no `provider-metadata.json`, ROLIE feed, DNS
record, or `security.txt` entry that a standard CSAF consumer could follow. So
cudabom synthesizes the manifest itself and consumes NVIDIA's stream directly,
without downloading any redistributable binary packages.

The CSAF document for a bulletin lives at:

```
<year>/<bulletin-id>/<bulletin-id>.json          # the CSAF document
<year>/<bulletin-id>/<bulletin-id>.json.sha256   # its published checksum
<year>/<bulletin-id>/CVE-*.json                  # CVE records (ignored)
<year>/<bulletin-id>/<bulletin-id>.md            # markdown (ignored)
```

cudabom recognizes the CSAF document by convention: a `.json` file whose stem
equals its parent directory name (which excludes the `CVE-*.json` siblings and
any top-level `*.json`).

Two fetch strategies feed the same offline ingestion pipeline:

```
# Manifest (default): one Git Trees API call lists the repo at a pinned commit,
# cudabom filters it to CSAF documents and fetches only those (each verified
# against its .sha256 sibling when present).
cudabom db update --map advisories/product-map.json --rev <commit-sha> -o index.json

# Tarball (fallback / air-gap): download the whole-repository archive for the
# pinned commit and unpack its CSAF entries in memory.
cudabom db update --map advisories/product-map.json --rev <commit-sha> --mode tarball -o index.json
```

Integrity rests first on the pinned **commit SHA** (content-addressed over the
whole tree), then on NVIDIA's per-file `.sha256` sidecars (manifest mode) or an
optional `--sha256` of the whole archive (tarball mode). Always pin `--rev` to a
reviewed commit; a branch ref would let the source move underneath a build.

## Staying fresh: `advisories/index.json` and the nightly refresh

The reviewed, vendored index lives at `advisories/index.json`. Scans read this
committed snapshot offline; no scan touches the network. Freshness and
reproducibility are reconciled by a scheduled job rather than live lookups:

- `.github/workflows/advisory-refresh.yml` runs nightly. It resolves NVIDIA's
  newest `main` commit, pins to that exact SHA, rebuilds the index with
  `db update`, and opens a pull request when the result changes.
- A maintainer reviews the diff (new advisories, changed version ranges, and any
  newly **unmapped** products the PR body lists) and merges. Merging is the only
  moment the index that users consume changes, so every change is auditable.

To refresh locally instead, run `db update` with a chosen `--rev` and write to
`advisories/index.json`.
