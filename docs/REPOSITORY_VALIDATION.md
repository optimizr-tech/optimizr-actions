# Repository-owned validation contract

`_repository-validation.yml` executes one executable already committed to the consumer repository. Arguments are a JSON array and are passed directly as process argv; the workflow never evaluates consumer text as shell source.

## Consumer entrypoint

Commit a small executable such as `scripts/ci/validate.sh`. It should orchestrate product-specific checks and return non-zero on failure. Keep secrets out of output.

```yaml
jobs:
  validation:
    uses: optimizr-tech/optimizr-actions/.github/workflows/_repository-validation.yml@v1
    with:
      script_path: scripts/ci/validate.sh
      args_json: '["--ci"]'
      required_paths_json: '["pyproject.toml", "uv.lock"]'
      runner_json: '["self-hosted","Linux","security"]'
      require_trusted_ref: true
      node_version: "24"
      npm_version: "11"
      pnpm_version: "11"
      # Optional: only for an idempotent entrypoint that reserves exit 75
      # for a transient dependency download failure.
      retry_attempts: 3
      retry_backoff_seconds: 5
```

`node_version`, `npm_version`, and `pnpm_version` are optional and are installed
before the consumer executable when supplied. `npm_version` and `pnpm_version`
require `node_version`; npm is installed globally at the requested controlled
version, and pnpm is installed only when the consumer needs it. The
`_validation-gate.yml@v1` wrapper supplies the organization defaults (Node 24,
npm 11, and pnpm 11) and forwards them to this workflow, so a full consumer
entrypoint such as `scripts/ci-local.sh all` can use both npm and pnpm without
duplicating setup steps.

The default trust boundary requires the candidate to be reachable from `refs/heads/main`. A persistent self-hosted runner cannot disable that requirement. Hosted pull-request callers may deliberately set `require_trusted_ref: false`, but must not reuse that caller on a persistent production runner.

`timeout_seconds` bounds the consumer command (default 900, maximum 7200).
`job_timeout_minutes` bounds the reusable workflow job (default 65, maximum
360); `_validation-gate.yml@v1` forwards it. Keep the command timeout lower
than the job timeout so the workflow can upload evidence and clean up after a
timeout or command completion. Existing callers retain both defaults.

For a trusted main self-hosted Docker validation that needs to pull from GHCR,
callers may set `registry_auth: true`. This opt-in is accepted only for a
self-hosted Linux runner during `push` or `workflow_dispatch` on
`refs/heads/main`; it is rejected for hosted and `ephemeral-pr` validation.
The workflow grants `packages: read` only to the repository-validation job,
logs in with the short-lived `github.token`, and uses the fixed temporary
Docker config under `$RUNNER_TEMP/optimizr-registry-docker-config`. The config
is removed in an `always()` cleanup step, including when login or validation
fails. Because the consumer command runs with that config available for its
Docker pulls, never enable this option for untrusted repository code.

Existing callers remain unchanged because `registry_auth` defaults to `false`.
Callers that opt in must also grant `packages: read` in the caller workflow;
the reusable workflow cannot elevate a caller's token permissions.

After checkout, the reusable verifies that `git rev-parse HEAD` matches the
requested candidate, that the Git root is the requested workspace, and that the
worktree is clean. `required_paths_json` is optional and accepts a bounded JSON
array of up to 256 repository-relative files or directories that must be
materialized before the consumer script starts. Generic scanner workflows
derive their tracked input paths from the Git index and pass them to this
guard before scanning. When a required path is missing but the SHA,
Git root and clean-worktree checks pass, `checkout-integrity` performs one
bounded repair: it disables stale sparse-checkout state and checks out tracked
files from the expected SHA. It authenticates those Git subprocesses with the
workflow's short-lived `github.token` through an ephemeral HTTP extra header;
the token is not written to Git configuration, outputs, or evidence. If no
token is available, the repair fails before any fetch. It then repeats the
complete verification. The repair never deletes untracked data, changes
`HEAD`, or runs when the worktree is dirty or points at another SHA; a failed
repair remains fail-closed.

The check emits a sanitized step summary with the runner, workspace and exact
SHA. Runner registration, workspace recovery beyond this bounded Git repair,
and host-wide serialization remain responsibilities of `optimizr-infra-ops`.

## Billing emergency

Use the workflow's manual dispatch only with a protected GitHub Environment that requires human reviewers. The dispatch requires an exact SHA, a trusted self-hosted runner, and a repository-owned executable. It does not accept arbitrary shell commands or inherited secrets.

## Evidence and failure behavior

Evidence contains repository, exact head/base SHAs, executable path, argument hashes/count, optional immutable image IDs, exit code, duration, timeout state, failure classification, and available Git/Docker/Compose versions. It never serializes process environment values. Missing, non-executable, symlinked, traversing, or out-of-workspace scripts fail closed.

### Transient dependency retries

The default is exactly one attempt. A consumer may opt into at most three
attempts only when its entrypoint is idempotent and returns the reserved exit
code `75` for a transient dependency download failure. The reusable applies a
bounded linear backoff (`retry_backoff_seconds`, from `0` to `60` seconds) and
never retries timeouts or ordinary command failures. A final exit code of `75`
remains failed and is recorded as `retryable_dependency`; a retry cannot turn
an incomplete final validation into success.

The evidence records every attempt and the reusable exposes `failure_kind` and
`attempt_count`. The classifications are `none`, `command_failed`, `timeout`,
and `retryable_dependency`. A job that never starts because no matching runner
is available cannot produce workflow evidence; runner registration, capacity,
and alerting remain infrastructure responsibilities.

Rollback is to pin the consumer to the preceding `optimizr-actions` commit while retaining an equivalent mandatory validation job. Do not replace the gate with an all-skipped path.
