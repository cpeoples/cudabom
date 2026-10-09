# Comparison with other tools

cudabom is not a replacement for general SBOM and binary-analysis tools; it
specializes in CUDA identity. This document compares cudabom against Syft,
Trivy, and OWASP blint on the same corpus, built by actually running current
versions of each. It is meant to be fair, including where the other tools do
better.

## Method

`cargo xtask eval` runs each tool against the labeled corpus and records what
each finds, what only cudabom finds, and what cudabom misses. The corpus and its
ground-truth labels are described in [`../CONTRIBUTING.md`](../CONTRIBUTING.md).

Each tool is run exactly as a user would run it: cudabom through its release
binary and the committed fingerprint DB + advisory index, the others through
their published CLIs, and reduced to the three steps that matter for CUDA
identity: does it **name** the CUDA component, does it **pin the exact
version**, and does it **correlate the version to a CVE**. Performance is then
measured by running each tool once over the whole corpus (identical input, so
process startup is amortized once) and timing it under the system `time`
utility; each cell pairs the cost with the outcome that run produced, so a fast
or low-memory run that found nothing is not mistaken for a win. A separate
container row scans a real CUDA image (Syft and Trivy's home turf) so the
comparison is not loose-binary-only. A tool that is not installed is recorded as
`n/a`, never as a loss. The table below is the ground-truth run over NVIDIA's own
redistributable binaries; regenerate it in place with
`cargo xtask eval --download --write-comparison` (counts are binaries matched /
total across the labeled corpus).

## Results

<!-- eval:results:begin -->

| Capability | cudabom | blint | Syft | Trivy |
|---|---|---|---|---|
| Names a CUDA component | 41 / 41 | 41 / 41 | 8 / 41 | - |
| Pins the exact CUDA version | 37 / 41 | no | no | no |
| Correlates to a CVE | 36 / 41 | no | no | 0 / 41 |

_Measured by `cargo xtask eval` across 41 real labeled binaries (counts are binaries matched / total). Correlation totals: cudabom correlated 877 advisory match(es) across 36 binaries._

blint names the library (SONAME/symbols) but does not pin the CUDA release version or correlate CVEs for a bare native binary, so its version and CVE cells are `no`.

| Performance: same corpus, one run per tool | cudabom | blint | Syft | Trivy |
| --- | --- | --- | --- | --- |
| Input files identified | 41 / 41 | 20 / 41 | 8 / 41 | - |
| Exact version pinned | yes | no | no | n/a |
| CVE / advisory matches | 299 | 0 | 0 | 0 |
| Items named (raw) | 91 identities | 1353 objects | 16 packages | - |
| Wall time | 4.53 s | 152.87 s | 1.88 s | 333 ms |
| Peak RSS | 1737.2 MiB | 2335.8 MiB | 1412.5 MiB | 92.5 MiB |

_Each tool is run once over the whole corpus (identical input, process startup amortized once) and timed under the system `time` utility (wall clock, kernel peak RSS). The outcome in each cell is what that run actually produced, so a fast or low-memory run that found nothing is visible as such rather than counted as a win. Lower cost is better only when the outcome is equal. The raw "named" figures are not like-for-like units (cudabom counts component identities; blint counts individual objects and explodes each static `.a` into its hundreds of members; Syft counts packages), so the "Input files identified" row normalizes each to the comparable unit: distinct top-level input files out of the corpus total. cudabom's "advisory match(es)" counts every affected-advisory hit over the whole-corpus run and is a superset of the per-binary CVE count in the accuracy table above. A tool shown as `n/a` was not installed on the host that generated this table._

| Performance: same container, one run per tool | cudabom | blint | Syft | Trivy |
| --- | --- | --- | --- | --- |
| Exact version pinned | yes | n/a (per-binary) | no | n/a |
| CVE / advisory matches | 25 | n/a (per-binary) | 0 | 0 |
| Items named (raw) | 48 identities | n/a (per-binary) | 0 packages | - |
| Wall time | 1.88 s | n/a (per-binary) | 1.60 s | 326 ms |
| Peak RSS | 735.8 MiB | n/a (per-binary) | 1083.9 MiB | 95.7 MiB |

_Container row: `nvidia/cuda:12.4.1-runtime-ubuntu22.04` (`nvidia/cuda@sha256:517da2300c184c9999ec203c2665244bdebd3578d12fcc7065e83667932643d9`), all tools scanning the identical CUDA subtree (/usr/local/cuda-12.4). blint is per-binary forensics, not a tree cataloguer, so it is `n/a` here._

<!-- eval:results:end -->

### What the measured run shows

The tables above carry the numbers; two things they do not make obvious:

- **cudabom and blint both name 41/41, but the claims differ.** blint says "this
  binary touches CUDA" (recovered from driver symbols like `cuGetProcAddress_v2`,
  a `libcuda.so.1` dependency, SONAME and strings, not the filename). cudabom says
  *which component, which exact release, and which CVEs apply*. Only the latter is
  actionable for a security gate. Syft (8/41) keys off package context a loose or
  vendored shared object does not carry, and Trivy's `rootfs` scan finds 0 CVEs
  because there is no OS package-DB entry for a bare CUDA library.
- **The 4 binaries cudabom names but does not pin** are large static archives
  (`libnccl_static.a`, `libcutensor_static.a`, `libcudss_static.a`) whose member
  hashes do not survive static linking. cudabom still names the component from its
  exported public-API symbol set (an `ExportedSymbolSet` signal at `likely`
  confidence) but cannot pin the release from symbols alone. The small
  `libcudart_static.a` *is* pinned, because its few members' hashes survive.

The gap the general tools leave is the last mile: from build-id/hash to exact
CUDA version to CVE correlation. cudabom closes it with first-party fingerprints
from NVIDIA's redistributables and correlation against NVIDIA's CSAF advisories.
It is authoritative for CUDA identity specifically, not a replacement for Syft or
Trivy on broad package and OS-level work.

