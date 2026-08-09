# CI skip contract

**Superseded by directive `optimizr-actions` #159.** `[skip-tests]` as a
billing-outage muleta is prohibited org-wide: PR validation must run on the
governed self-hosted runner (`self_hosted_mode: metadata-pr` for metadata,
`ephemeral-pr`/`trusted-main` for code execution) with real evidence, and
skip must never be derived from the account billing state. This document is
kept as the historical contract.

The `[skip-tests]` marker was the single organization marker for bypassing
hosted test and pull-request validation jobs during a confirmed GitHub
Actions billing outage. It did not bypass release, deployment, or the
self-hosted deployment security gate.

## Event contract

| Event | Source of the marker | Effect |
|---|---|---|
| `pull_request` | pull-request title | hosted PR/CI jobs are skipped at the caller |
| `push` | `github.event.head_commit.message` | hosted CI jobs are skipped |
| `workflow_dispatch` | explicit boolean input such as `bypass_tests` | hosted CI jobs are skipped |

Reusable-workflow consumers must put the condition on the calling job, before
`uses:`. GitHub evaluates `jobs.<job_id>.if` before the job runs and marks a
false condition as skipped. A condition implemented only inside the reusable
cannot protect the caller from a billing failure that happens while GitHub is
starting the called job.

Canonical callers are available in:

- `templates/workflows/commitlint.yml`;
- `templates/workflows/validate-pr.yml`.

The templates pass the pull-request payload and exact base/head SHAs explicitly
to keep validation deterministic. Consumer-specific CI jobs should use the same
event mapping. The legacy singular marker `[skip-test]` is not part of this
contract.

## Production invariant

A merge with `[skip-tests]` may continue to a trusted self-hosted deployment,
but the deploy reusable still runs filesystem and immutable-image security
gates. Release remains independently governed and never reads the test marker.
Local validation evidence must be recorded in the pull request whenever hosted
tests are bypassed.

## Adoption audit

The organization audit follows directive #159 instead of the historical
billing-guard contract:

- `PR_BILLING_SKIP_GUARD` — a caller-level `[skip-tests]` guard is present and
  prohibited; validation must run on the governed self-hosted runner with real
  evidence.
- `SELF_HOSTED_PR_WITHOUT_GOVERNED_MODE` — a pull-request workflow engages a
  self-hosted runner without `self_hosted_mode` (`metadata-pr`,
  `ephemeral-pr`, `trusted-main`).
- `HOSTED_PR_CODE_VALIDATION` — a pull-request job validates candidate code on
  a hosted runner while the repository has governed self-hosted runners.
