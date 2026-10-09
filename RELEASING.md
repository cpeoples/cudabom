# Releasing cudabom

This is the maintainer runbook for cutting a release. The release pipeline is
defined in [`.github/workflows/release.yml`](.github/workflows/release.yml) and
is driven entirely by publishing a GitHub Release for a version tag.

## Overview

```
tag vX.Y.Z  ->  publish GitHub Release
    -> build (5 targets: linux x86_64/aarch64, macOS x86_64/aarch64, windows x86_64)
    -> aggregate-hashes -> provenance (SLSA Build L3)
    -> sign-and-attest (CycloneDX SBOM + Sigstore signatures -> release assets)
    -> publish-crate (crates.io)      [when credentials are configured]
    -> bump-tap    (Homebrew formula) [when credentials are configured]
    -> publish-snap (Snap Store)      [when credentials are configured]
    -> build-wheels -> publish-testpypi -> smoke-test -> publish-pypi
                                                         [when PUBLISH_PYPI=true]
```

## Preconditions

- `main` is green (CI, cargo-audit, CodeQL, Scorecard).
- `CHANGELOG.md` has an entry for the new version.
- The version in the workspace `Cargo.toml` matches the tag you are about to
  push (the crates.io job also sets it from the tag as a safety net).

## Bumping the version (single source of truth)

The release version lives in exactly one logical place:
`[workspace.package] version` in the root `Cargo.toml`, inherited by every crate
via `version.workspace = true`. Cargo additionally requires each internal
path dependency in `[workspace.dependencies]` to repeat that version so the tree
publishes cleanly to crates.io. **Never edit those by hand.** Use the one task
that rewrites all of them atomically and verifies they agree:

```bash
cargo xtask release-version X.Y.Z   # rewrites package version + all internal pins
cargo update -w                     # refresh Cargo.lock
cargo xtask release-version --check # verify every pin agrees (also runs in CI)
```

`SCHEMA_VERSION` (`cudabom-core`) is the JSON **output-contract** version and is
intentionally decoupled from the release version; do not bump it here.

## Steps

1. Merge everything for the release to `main`.
2. Bump the version with `cargo xtask release-version X.Y.Z` (see above), commit.
3. Tag and push:

   ```bash
   git tag -a vX.Y.Z -m "Release X.Y.Z"
   git push origin vX.Y.Z
   ```

4. On GitHub: Releases -> Draft a new release -> pick the tag -> Publish.
5. Watch the `Release` workflow. On success the release has: per-target
   archives + `.sha256`, a CycloneDX SBOM, SLSA provenance
   (`*.intoto.jsonl`), and Sigstore signatures (`*.sigstore.json`).

## Verifying a release

```bash
# SLSA provenance
slsa-verifier verify-artifact <archive> \
  --provenance-path <tag>.intoto.jsonl \
  --source-uri github.com/cpeoples/cudabom

# Sigstore signature
cosign verify-blob <artifact> --bundle <artifact>.sigstore.json ...
```

## Distribution channels

Release archives, crates.io, Homebrew, Snap, and PyPI are wired in the release
workflow. The jobs that publish to external registries only run on a published
release and are guarded so a fork or dry run cannot publish. Each is also
gated on an opt-in repository variable, so a channel stays dormant until you
flip its switch:

- `PUBLISH_CRATES=true` - enable the crates.io publish job.
- `PUBLISH_HOMEBREW=true` - enable the Homebrew formula-bump job.
- `PUBLISH_SNAP=true` - enable the Snap Store publish job.
- `PUBLISH_PYPI=true` - enable the wheel build + PyPI publish jobs.

Required repository secrets / environments (mirroring the project's sibling
tools):

- `CARGO_REGISTRY_TOKEN` - crates.io publish.
- `HOMEBREW_TAP_TOKEN` - open a formula-bump PR on `cpeoples/homebrew-tap`.
  The seed `Formula/cudabom.rb` already exists; the job rewrites its version
  and checksums from the release archives on each tag.
- Snap Store credentials via the `snapcraft` environment.
- PyPI uses Trusted Publishing (OIDC) via the `pypi` environment: no API token
  is stored. Register this repo + workflow + `pypi` environment as a trusted
  publisher at https://pypi.org/manage/account/publishing/ before the first
  release. `maturin` (`bindings = "bin"`) builds a binary wheel per platform so
  `pip install cudabom` / `uvx cudabom` drop the `cudabom` executable on PATH.
- TestPyPI uses Trusted Publishing via the `testpypi` environment: register the
  same project at https://test.pypi.org/manage/account/publishing/. Every
  release (and every manual dispatch) publishes to TestPyPI first, then a
  smoke-test job installs `cudabom` from TestPyPI on Linux/macOS/Windows and
  runs it before production PyPI is touched. A TestPyPI failure blocks prod.

### PyPI dry run

Trigger the workflow manually (Actions -> Release -> Run workflow) to build
wheels and publish only to TestPyPI, leaving production untouched:

- `publish_pypi = false` (default): build + TestPyPI + smoke test, then stop.
- `publish_pypi = true`: also publish to production PyPI.

## Not yet wired

The following channels are planned and intentionally left as TODOs until the
tooling is provisioned:

- Container image at `ghcr.io/cpeoples/cudabom`.
- GitHub Action published from `cpeoples/cudabom-action`.

Do not enable a channel until its credentials exist and a dry run has passed.
