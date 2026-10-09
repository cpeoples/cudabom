# Security policy

## Reporting a vulnerability

Please open a private security advisory via the
[Security tab](https://github.com/cpeoples/cudabom/security/advisories/new)
rather than a public issue.

## Scope

cudabom consumes attacker-controlled files: wheels, shared libraries,
executables, and container images pulled from untrusted sources. Its own
robustness is therefore in scope.

In scope:

- Vulnerabilities in cudabom itself: a parser bug that lets a crafted artifact
  crash, hang, or execute code in the scanner process; a path-traversal or
  symlink-escape in the extractor that writes outside its virtual root; a
  decompression bomb that evades the configured limits; or a report path that
  leaks bytes cudabom read out of a scanned artifact.
- Issues in the published distribution (release archives, SLSA provenance,
  CycloneDX SBOM, Sigstore signatures).

Out of scope:

- Vulnerabilities in the *software cudabom identifies*. A CUDA component that
  cudabom flags as affected by an NVIDIA advisory is the artifact owner's issue,
  not a vulnerability in cudabom.
- The accuracy of a specific identification or advisory match. Report those as
  regular issues with a reproducer; they are correctness bugs, not security
  vulnerabilities.

## Hardening guarantees

cudabom never executes, loads (`dlopen`), or JIT-compiles anything it scans, and
makes no network connections except the explicit refresh/fetch commands
(`cudabom db update`, `cudabom update`, and `reconcile --ngc-image`).
All crates build under `#![forbid(unsafe_code)]`. See
[docs/threat-model.md](docs/threat-model.md) for the full model.

## Supported versions

Only the latest minor release line is supported. See
[Releases](https://github.com/cpeoples/cudabom/releases) for the current
version.
