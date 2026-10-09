# Advisory correlation

cudabom correlates identified CUDA components against NVIDIA's machine-readable
security bulletins and reports affected / not_affected / under_investigation
verdicts with justifications.

## Source

- Primary: the NVIDIA Product Security GitHub repository
  (`https://github.com/NVIDIA/product-security`), using its machine-readable
  CSAF/CVE data where available.
- Source of record: `https://www.nvidia.com/en-us/product-security/`.

NVIDIA's guidance states that from October 1, 2026 its PSIRT publishes bulletins
on GitHub in Markdown, CSAF, and CVE formats. Historical coverage may be
incomplete during the migration; cudabom exposes advisory coverage status rather
than treating missing historical data as proof of safety.

## `cudabom db build` and `cudabom db update`

`cudabom db build` is offline: it ingests local CSAF 2.0 documents (a file or a
directory of `*.json`) and, using the reviewed product map, builds a normalized
local index. `cudabom db status` reports which products mapped and which did
not.

`cudabom db update` is the network-using command: explicit, never automatic. It
fetches a pinned revision (`--rev <commit-sha>`), verifies each CSAF file against
its `.sha256`, and feeds the same ingestion path as `db build`. Two fetch
strategies share that pipeline: `--mode manifest` (default) lists the repository
via the Git Trees API and fetches only the CSAF documents, while `--mode tarball`
downloads the whole-repository archive and unpacks its CSAF entries in memory
(an optional `--sha256` verifies the archive). For air-gapped mirrors, use
`--mode tarball` against a local archive, or run `db build` directly against a
local CSAF mirror. The resulting index records the upstream commit so reports
can state "advisories as of \<commit\>".

## Normalization and mapping

CSAF `product_tree` (`full_product_names` and version branches),
`product_status` (`known_affected`, `fixed`, `known_not_affected`,
`under_investigation`), and `vulnerabilities` are parsed and mapped to cudabom
component identities through a maintained, reviewed mapping file
(`advisories/product-map.json`). Unmapped products are reported by
`cudabom db status`, never silently dropped.

## Matching and VEX

- EXACT version -> affected / not affected per the bulletin (an exact identity
  whose version cannot be parsed degrades to `under_investigation`).
- LIKELY with a range -> `under_investigation` unless the whole range is on one
  side of the boundary.
- UNKNOWN -> no claim.
- `not_affected` is emitted only with a defensible justification (e.g. the fixed
  version is proven by EXACT evidence). Never inferred from a missing version.
- The advisory coverage caveat is always printed: absence of a match is not
  proof of safety.
