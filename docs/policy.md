# Gate policy

`cudabom gate` runs the scan pipeline and then evaluates a policy to decide
whether the build should pass or fail. The policy is a small, reviewable JSON
document. Run without `--policy`, `gate` uses a built-in secure default; a file
only has to express how you deviate from it.

## The secure default

With no `--policy`, the gate fails on any `affected` advisory verdict and
nothing else: identification alone does not fail the build, and an
`under_investigation` verdict warns but does not block (so a partial advisory
index cannot wedge a pipeline). This is equivalent to:

```json
{
  "schema_version": 1,
  "fail_on": {
    "advisory_verdicts": ["affected"],
    "under_investigation": false
  }
}
```

## Schema

Only `schema_version` is required; every other field has a secure default, so a
minimal policy is `{ "schema_version": 1 }`. Unknown fields are rejected, so a
typo fails loudly rather than silently weakening the gate.

| Field | Type | Default | Meaning |
|---|---|---|---|
| `schema_version` | integer | required | Policy format version. The current version is `1`; a newer version than the running binary understands is an error. |
| `fail_on.advisory_verdicts` | array of verdict | `["affected"]` | Verdicts that fail the gate. Allowed: `affected`, `not_affected`, `under_investigation`. |
| `fail_on.under_investigation` | boolean | `false` | Fail when any verdict is `under_investigation`. A convenience alias for adding `under_investigation` to `advisory_verdicts`. |
| `fail_on.min_confidence` | confidence or `null` | `null` | Fail when any component is identified at or above this confidence, independent of advisories. Allowed: `unknown`, `likely`, `exact`. `null` means identification never fails the gate. |
| `allow` | array of exemption | `[]` | Explicit, justified exemptions (see below). |

### Exemptions (`allow`)

Each entry suppresses a would-be violation and is recorded in the decision for
the audit trail. An entry must set `advisory`, `component`, or both, and must
carry a non-empty `reason`.

| Field | Type | Meaning |
|---|---|---|
| `advisory` | string | Exempt this advisory id (e.g. `CVE-2025-0001`). |
| `component` | string | Exempt this component (e.g. `cudart`). |
| `reason` | string | Why the exemption exists. Required; an empty reason is rejected. |

An entry matches only when every field it sets matches the violation. An
`advisory`-scoped entry does not suppress a different advisory, even for the
same component; a `component`-only entry exempts every violation for that
component.

## Example

Fail on `affected` advisories and on anything identified at `exact` confidence,
while exempting one triaged CVE and one first-party component:

```json
{
  "schema_version": 1,
  "fail_on": {
    "advisory_verdicts": ["affected", "under_investigation"],
    "min_confidence": "exact",
    "under_investigation": true
  },
  "allow": [
    { "advisory": "CVE-2025-0001", "component": "cublas", "reason": "not reachable in our build; tracked in TICKET-42" },
    { "component": "cudart", "reason": "first-party, shipped by us and patched on our own cadence" }
  ]
}
```

## Running it

```bash
# Secure default (fail on affected):
cudabom gate dist/ --db "$DB" --advisories "$ADV"

# With a policy file:
cudabom gate dist/ --db "$DB" --advisories "$ADV" --policy policy.json

# Machine-readable decision for a pipeline step:
cudabom gate dist/ --db "$DB" --advisories "$ADV" --format json
```

The table output leads with `gate: PASS` or `gate: FAIL (N violation(s))`,
lists each standing violation, and then any exemptions that were applied.
`--format json` emits a stable `{ passed, violations, exemptions }` object.

Exit codes: `0` when the gate passes, `1` when it fails (a standing violation),
`3` for an unreadable target, policy, database, or advisory index.

## When to use `gate` vs. `scan --fail-on`

`scan --fail-on affected` is the one-line check: fail the build when an advisory
affects an identified version. Reach for `gate` when you need more than a single
threshold: a confidence floor, blocking `under_investigation`, or an auditable
allowlist with reasons. Both read the same fingerprint database and advisory
index; `gate` adds the policy layer on top.
