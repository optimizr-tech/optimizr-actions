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
