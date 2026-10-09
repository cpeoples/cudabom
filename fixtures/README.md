# fixtures

Small CUDA C++ programs used strictly to generate **real** CUDA test artifacts
that cudabom must inspect. These are not part of cudabom's implementation and
are never runtime dependencies of the shipped binary.

- `src/` (committed): CUDA C++ sources for fixture programs.
- `build/`, `out/` (gitignored): compiled fixtures, treated as ephemeral test
  artifacts. Compiled by an optional CI job in an official NVIDIA CUDA Toolkit
  container. Not committed unless licensing explicitly permits redistribution.

Planned fixture coverage: dynamic cudart, static cudart, stripped static
cudart, a CUDA library statically linked into another ELF, a vendored/renamed
CUDA library, multiple toolkit versions and SM targets, PTX-only artifacts,
SASS/cubin artifacts, multi-architecture fatbins, and an artifact whose PEP 770
SBOM disagrees with its contents.
