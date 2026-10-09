# CI/CD integration

Examples for running cudabom in CI. These reference the composite GitHub Action
([`../../action.yml`](../../action.yml)) and the raw CLI.

## GitHub Actions

Scan on every push and pull request and surface findings inline in the Security
tab and on the PR diff:

```yaml
permissions:
  contents: read
  security-events: write

jobs:
  cudabom:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: cpeoples/cudabom-action@v0
        with:
          target: dist/
```

Set `fail-on-findings: false` to report without failing the build, or set
`format`/`output` to write a different report type.

The composite Action runs on **Linux and macOS runners** (x86_64 and aarch64).
cudabom still *scans* Windows PE targets (`.dll`), so to run it on a Windows
runner, install the release binary directly (download and verify the
`*-pc-windows-msvc` archive) and invoke `cudabom scan` as a plain step rather
than through the Action.

## Policy-gated builds

For more than a single pass/fail threshold (a confidence floor, blocking
`under_investigation`, or an auditable allowlist), run `cudabom gate` with a
policy file. The schema is in [`../policy.md`](../policy.md).

```yaml
jobs:
  cudabom-gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: cpeoples/cudabom-action@v0
        with:
          upload-sarif: "false"
          fail-on-findings: "false"   # the gate step owns pass/fail
      - name: Gate on policy
        run: cudabom gate dist/ --policy .cudabom/policy.json
```

`gate` exits `1` on a standing violation (failing the step) and `0` when the
policy passes, so no extra wiring is needed. Add `--format json` to capture the
decision as a build artifact.

## GitLab CI

```yaml
cudabom:
  image: ubuntu:latest
  script:
    - cudabom scan dist/ --format sarif --output cudabom.sarif
  artifacts:
    reports:
      sast: cudabom.sarif
```

## Air-gapped / offline

A scan makes no network calls; only the explicit refresh/fetch commands do
(`db update`, `update`, and `reconcile --ngc-image`). For air-gapped
environments, build the advisory index from a mirrored CSAF source ahead of
time, then point `scan` at the committed fingerprint database and that index:

```bash
# Build the advisory index from a local CSAF mirror (no network).
cudabom db build \
  --from /mnt/mirror/product-security \
  --map advisories/product-map.json \
  -o advisories/index.json

# Scan offline against the fingerprint DB and the index built above.
cudabom scan dist/ --db fingerprints/cuda --advisories advisories/index.json
```
