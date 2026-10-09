# NGC declared-SBOM/VEX fixtures

Committed, offline CycloneDX documents shaped like the artifacts NVIDIA NGC
publishes per container image, used to exercise `cudabom reconcile` without a
network connection or an API key.

- `sbom.cyclonedx.json`: a declared Software Bill of Materials listing CUDA
  components (`cuda-cudart`, `libcublas-12-4`) plus a non-CUDA package
  (`openssl`), to exercise canonical name normalization and the non-CUDA count.
- `vex.cyclonedx.json`: a declared VEX with one `not_affected` analysis
  statement referencing the cudart component by `bom-ref`.

These mirror the real NGC endpoints (both are CycloneDX JSON):

- SBOM: `GET https://api.ngc.nvidia.com/v2/org/{org}/repos/{repo}/images/{tag}/sbom`
- VEX:  `GET https://api.ngc.nvidia.com/v2/org/{org}/repos/{repo}/images/{tag}/vex`

The live endpoints require an NGC API key; `cudabom reconcile --ngc-image
<org/repo:tag>` fetches them (opt-in, key-gated). The fixtures let the reconcile
logic be validated deterministically offline. Values here are illustrative, not
a real image's contents.
