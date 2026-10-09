# Evidence model

cudabom's product is evidence-backed CUDA identity. Every reported component
carries the observations that support it and an explicit confidence level. This
document is the authoritative definition of the types and rules; the code in
`cudabom-core` and `cudabom-identify` implements them.

## Evidence types

Each evidence item records what was observed, where, and how strong it is. These
types are validated against real binaries before they are trusted; do not add a
type without a fixture that exercises it.

| Type | Meaning | Strength |
|---|---|---|
| `KnownFileHash` | exact sha256 of a known official redistributable | strong |
| `BuildId` | GNU build-id matching a known build | strong |
| `SymbolVersionNode` | ELF symbol version definitions/requirements | medium |
| `ExportedSymbolSet` | component's namespaced public API symbols (names the component, not a version; used for large static archives) | medium |
| `InternalSymbolSet` | internal/static symbols indicating a static copy | medium |
| `VersionString` | version text embedded in rodata (pattern documented) | medium |
| `FatbinProducer` | toolchain/producer metadata from embedded fatbins | medium |
| `Soname` | e.g. a `libcudart.so.N`-style SONAME | weak-medium |
| `NeededEntry` | a dependency on a CUDA library (not an embedded copy) | weak |
| `FileName` | filenames lie | weakest |
| `CodeSimilarity` | disassembly / fuzzy-hash similarity | later |
| `DeclaredSbom` | present in a PEP 770 or supplied SBOM (declared, not proven) | context |
| `Architecture` | target machine (`X86_64`, `Aarch64`, …) from the ELF `e_machine` / PE COFF machine | context |

`Architecture` is not an identity signal and never changes confidence on
its own. It is attached to every finding (alongside the signal that produced it)
to record which ABI the match came from: the one detail that distinguishes an
otherwise identical `linux-x86_64` vs `linux-sbsa` build that share a SONAME.

## Confidence rules

- **EXACT**: a known-hash or build-id match, OR at least two independent
  strong evidence items that agree on a precise version, at least one carrying
  the version itself.
- **LIKELY**: identity well supported, but the version is incomplete or
  unconfirmed. Report the narrowest supported range (e.g. `13.x`), never a
  guessed exact version.
- **UNKNOWN**: CUDA-related signals exist but identity cannot be established.
  Still reported, with evidence, so a human can investigate.

Conflicting evidence lowers confidence and is surfaced explicitly in the
`conflicts` field. cudabom never asserts more than the evidence supports: a
confident wrong answer is worse than "unknown".

## Relationship types

- **Embedded copy**: the component's bytes are in this file/artifact.
- **Statically linked**: component code compiled into another binary.
- **Dynamic dependency**: a `NEEDED` CUDA library supplied elsewhere.
- **Declared only**: listed in an SBOM but not found in the bytes.

These map to different CycloneDX relationships and different risk statements.

## Worked examples

These trace real matcher paths (see `cudabom-identify::matcher` and its tests);
each shows the evidence observed and the resulting confidence.

- **Known file hash → `Exact`.** A scanned `libcudart.so.12.4.127` whose sha256
  is recorded in the fingerprint DB resolves to the exact version(s) that hash
  identifies, with `KnownFileHash` evidence and an `EmbeddedCopy` relationship.
  A hash match is definitive, so no weaker signal is also reported for that file.

- **GNU build-id → `Exact`.** A `.so` stripped of nothing but its file identity
  still carries its `.note.gnu.build-id`; a build-id known to the DB yields the
  same `Exact` result via `BuildId` evidence, even if the bytes were recompressed
  so the file hash differs.

- **SONAME stem → `Likely` (ABI-major range).** A `libcublas.so.12` whose
  `DT_SONAME` stem (`libcublas.so`) is known to the DB names the component, but
  the SONAME carries only the ABI major, so the honest claim is `12.x` at
  `Likely` with `Soname` evidence, never a guessed micro version.

- **Exported symbol set → `Likely` (component only).** A static archive member
  (`libnccl_static.a/…​.o`) carries no SONAME and no matchable hash, but exports
  the component's namespaced API symbols (`ncclAllReduce`, `ncclCommInitRank`,
  …). Matching ≥2 of a component's recorded `symbol_markers` names the component
  at `Likely` with `ExportedSymbolSet` evidence and a `StaticallyLinked`
  relationship. A symbol set identifies the component, not a version, so no
  version is asserted.

- **PE version resource → `Likely` (exact micro version).** A Windows
  `cudart64_12.dll` with a `VS_VERSIONINFO` product string `NVIDIA CUDA 12.4.99
  Runtime` names the component and reports `12.4.99` at `Likely` via
  `VersionString`-style evidence: a resource is more precise than an ELF SONAME
  but still spoofable, so it is never `Exact` on its own.

- **`NEEDED` dependency → dynamic dependency edge.** An application that lists
  `libcudart.so.12` in `DT_NEEDED` produces a `DynamicDependency` finding
  (`NeededEntry` evidence): the library is used but lives elsewhere, so cudabom
  records the edge without claiming an embedded copy.

- **Declared-only SBOM → context.** A component present in a supplied PEP 770 /
  CycloneDX SBOM but not found in any scanned bytes is reported with
  `DeclaredSbom` evidence and a `DeclaredOnly` relationship: a declared fact,
  explicitly not a proven one.
