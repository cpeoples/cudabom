# fuzz

libFuzzer (`cargo-fuzz`) targets for every parser cudabom exposes to hostile
input. Parsers must be panic-free on malformed input; these targets prove it and
run as short jobs in CI.

Planned targets, one per parser boundary:

- ELF fact extraction
- fatbin container / cubin / PTX header
- CSAF advisory input
- CycloneDX SBOM input
- wheel (zip) member walking
- OCI image manifest

Fuzz corpora and artifacts are gitignored (see [`../.gitignore`](../.gitignore)).
This directory is populated alongside the parsers they exercise.
