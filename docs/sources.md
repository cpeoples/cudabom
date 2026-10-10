# NVIDIA authoritative data sources

cudabom is grounded in first-party, machine-readable NVIDIA data. This document
records the sources cudabom uses, what each is authoritative for, and how each
feeds the tool. The guiding principle: **cudabom does not invent fingerprints or
advisories**, so every claim traces back to one of these sources.

Two rules apply across all of them:

- **Never commit NVIDIA binaries.** Archives are fetched into gitignored scratch
  (`corpus/`), verified against NVIDIA's published SHA-256, inspected, and only
  the *derived* facts (hashes, build-ids, SONAME stems) are committed.
- **Scanning is offline by default.** Network access is confined to explicit,
  developer/CI-time refresh steps (`cargo xtask corpus …`, `cudabom db update`).
  A normal `cudabom scan` needs no network.

## Source hierarchy

| Source | Authoritative for | cudabom use |
| --- | --- | --- |
| CUDA redistributable JSON manifests | Canonical component/release inventory, versions, platforms, archive paths, SHA-256, sizes | Fingerprint corpus generation; release/component discovery; provenance |
| Jetson (L4T/JetPack) APT repository | Tegra aarch64 CUDA package inventory, versions, pool paths, SHA-256 | Jetson fingerprint corpus (synthesized redist manifests) |
| CUDA package repositories (APT/deb, rpm) | OS package inventory and historical versions | OS package/version mapping (future) |
| NVIDIA Repo Channels / CDN (`releases.json`) | Content-addressed artifact acquisition | Future-proof download resolution (investigate) |
| NVIDIA Product Security (CSAF/CVE) | Security advisories | Advisory correlation / VEX (`cudabom db update`) |
| NGC catalog + HTTP APIs | Container metadata, declared SBOM/VEX, scan results | Real-world evaluation; declared-vs-discovered reconciliation (`cudabom reconcile`) |
| CUDA binary utilities / PTX ISA / programming guide docs | Format and semantics reference | Parser/reference validation, **not** a runtime dependency |

### CUDA redistributable manifests (canonical)

Base: `https://developer.download.nvidia.com/compute/cuda/redist/`
Per-release: `.../redist/redistrib_<VERSION>.json`

Each manifest is a versioned, hash-addressable catalog (not a moving "stream"):
it enumerates NVIDIA components (e.g. `cuda_cudart`, `libcublas`, `libcufft`),
their versions, per-platform archives, and each archive's SHA-256 and size.
This is the **canonical source for building the fingerprint corpus**. The
derivation chain cudabom relies on is:

```
NVIDIA manifest  ->  NVIDIA archive  ->  observed binary facts  ->  cudabom fingerprint
   (says shipped)     (SHA-256 verified)   (build-id, SONAME, hash)   (committed, derived)
```

The `cargo xtask corpus lock` / `corpus fetch` / `fingerprints build` flow
implements exactly this (see `fingerprints/README.md`). NVIDIA's own
`build-system-archive-import-examples` consumes `redistrib_<version>.json` the
same way (resolve components, download, validate SHA-256, extract), which
confirms the model.

### Jetson (L4T/JetPack) APT repository

Base: `https://repo.download.nvidia.com/jetson/common/`
Per-release index: `dists/<release>/main/binary-arm64/Packages`

Jetson modules run Linux (L4T/JetPack), and their CUDA stack ships as Debian
packages rather than the `.tar.xz` redistributables. The Tegra `aarch64`
binaries have distinct build-ids and inner-`.so` hashes from the generic
`linux-sbsa` build, so without this source a scan of a real Jetson library
matches only a structural family, never an exact version.

The signed APT `Packages` index lists, for every CUDA library package, its
exact `Version`, pool `Filename`, and `SHA256`: the same facts a redist
manifest carries. `cargo xtask jetson discover` reads it and synthesizes a
redist-shaped `redistrib_<release>.json` (one archive per package, keyed under
the `linux-aarch64-tegra` platform), so the existing `corpus fetch` /
`fingerprints build` flow derives Tegra fingerprints with no special-casing.
The `.deb` payload is unpacked during the build (its inner `data.tar` extracted
via the `object` crate, which reads the signed `ar` archive portably). Covered
releases are JetPack 5 (r35.x) and JetPack 6 (r36.x); a release that serves no
CUDA package is skipped at discovery.

### CUDA package repositories

Base: `https://developer.download.nvidia.com/compute/cuda/repos/`

Standard APT/rpm metadata (`InRelease`, `Packages`, `Packages.gz`) enumerating
published CUDA OS packages and versions per distro/arch. Useful for OS
package/version inventory, secondary to the redistrib manifests for the binary
fingerprint corpus.

### NVIDIA Product Security (advisories)

`https://github.com/NVIDIA/product-security`

NVIDIA publishes machine-readable **CSAF** and **CVE Record** files alongside
Markdown bulletins. cudabom ingests these into a normalized local advisory index
(`advisories/index.json`) via `cudabom db update`, kept logically separate from
the fingerprint database.

### NGC (evaluation corpus)

`https://catalog.ngc.nvidia.com/` and `https://api.ngc.nvidia.com/`

NGC exposes container metadata plus NVIDIA-declared SBOM/VEX and scan results.
This is the basis for a high-value validation: compare what NGC *declares* an
image contains against what cudabom *discovers* in the bytes, surfacing
components present but undeclared. Implemented by `cudabom reconcile`.

Both the SBOM and VEX are CycloneDX JSON, retrieved per image tag:

- SBOM: `GET {api}/v2/org/{org}/repos/{repo}/images/{tag}/sbom`
- VEX:  `GET {api}/v2/org/{org}/repos/{repo}/images/{tag}/vex`

These endpoints require an NGC API key (`Authorization: Bearer <key>`); without
one they return 401. Accordingly the fetch is opt-in and key-gated
(`cudabom reconcile --ngc-image org/repo:tag`, key via `--ngc-api-key` or the
`NGC_API_KEY` environment variable) and is the only networked path; reconciling
against local `--sbom`/`--vex` files is fully offline.

### Reference documentation (validation only)

CUDA binary utilities, PTX ISA, the CUDA programming guide, CUPTI, and the CUDA
toolkit docs are authoritative for *formats and semantics* (fatbin wrapper, PTX
`.target`, cubin ELF machine, GPU architecture numbering). They validate the
parsers; they are not runtime dependencies of cudabom.
