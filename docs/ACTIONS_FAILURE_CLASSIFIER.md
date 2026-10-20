# Actions failure classifier

`scripts/ci/classify_actions_failure.py` separates failures that carry no code
evidence (hosted billing block, runner unavailable) from real code or gate
failures. It is offline, stdlib-only and fail-closed: it reads evidence that was
already saved from the GitHub Actions API and never calls the network.

Status: additive helper. No workflow, composite action, input, output,
permission or default under `v1` changes, and no consumer depends on it yet.

## Inputs

Either a combined file or three files (UTF-8 JSON):

| Argument | Content |
|---|---|
| `--evidence FILE` | `{"run": {...}, "jobs": [...] \| {"jobs": [...]}, "annotations": [...] \| {"annotations": [...]}}` |
| `--run FILE` | `GET /repos/{o}/{r}/actions/runs/{id}` |
| `--jobs FILE` | `GET /repos/{o}/{r}/actions/runs/{id}/jobs` |
| `--annotations FILE` | check-run annotations of the failed jobs |

Fields read: `run.id`, `run.conclusion`; per job `runner_id`, `steps`,
`conclusion`, `status`; per annotation `message`, `title`, `raw_details`.

## Output

JSON on stdout (sorted keys): `classification`, `is_code_failure`,
`promotion_allowed`, `reason`, `evidence` (counters only: run id/conclusion,
`job_count`, `prestart_jobs`, `started_jobs`, `unknown_jobs`,
`billing_annotations`). No annotation text, runner names, hosts or labels are
echoed.

| `classification` | Meaning | `is_code_failure` | `promotion_allowed` |
|---|---|---|---|
| `hosted_billing_blocked` | every job pre-start (`runner_id=0`, `steps=[]`) and an annotation has a known billing marker | false | false |
| `runner_unavailable` | every job pre-start (or finished with no steps) and no billing marker | false | false |
| `code_or_gate_failure` | a started job or step failed (`failure`, `cancelled`, `timed_out`, `action_required`) | true | false |
| `passed` | run `success`, every job started and `success`/`completed` | false | true |
| `inconclusive` | anything else | false | false |

Exit code: `0` only when `promotion_allowed` is true; `1` for every other
classification; `2` for unreadable or invalid input files.

## Failure modes (all fail-closed)

- Missing/empty jobs, non-list annotations, non-object root: `inconclusive`.
- `runner_id` missing, `null`, boolean or negative, or `steps` not a list:
  `inconclusive`. A skipped job (`runner_id: null`) therefore makes the run
  `inconclusive` rather than `runner_unavailable`.
- Billing annotation together with a started job: `inconclusive` (conflict).
- Mix of started and pre-start jobs: `inconclusive`.
- A successful job with an empty `steps` array is never `passed`; it is
  reported as `runner_unavailable`.
- In-progress run (`conclusion` null): `inconclusive`.

Limitations: `timed_out`/`cancelled` after runner start are reported as
`code_or_gate_failure` because the payload cannot tell a hung test from a lost
runner mid-job; treat that class as "needs human triage", not as proof of a
code defect. Billing detection relies on three English message markers and
must be extended if GitHub changes the wording (unknown wording degrades to
`runner_unavailable`, never to `passed`).

## Affected consumers

None. The script is not referenced by any reusable workflow, composite action,
template or the capability catalog, so `v1` callers see no behavior change.
Intended later use: gating retry (see #319) and rollback decisions on
`is_code_failure`, and never treating a billing or runner outage as evidence
that code passed or failed.

## Migration impact

None. Nothing to change in consumers.

## Rollback

Delete `scripts/ci/classify_actions_failure.py`,
`tests/test_actions_failure_classification.py` and this document (single
revert of the PR). No tag, workflow or deployment is involved.
