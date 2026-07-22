# CI skip contract

`[skip-tests]` is the single organization marker for bypassing hosted test and
pull-request validation jobs during a confirmed GitHub Actions billing outage.
It does not bypass release, deployment, or the self-hosted deployment security
gate.

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

The organization audit emits `MISSING_PR_BILLING_SKIP_GUARD` for every hosted
pull-request job or canonical reusable caller that lacks its own title guard.
Do not rely on a guarded root job and `needs`: during the July 2026 billing
outage GitHub still rejected a Certbot workflow at startup before
dependency-based skipping was resolved. This catches the failure mode before
the next billing outage.
