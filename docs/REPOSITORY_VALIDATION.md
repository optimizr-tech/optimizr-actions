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
```

The default trust boundary requires the candidate to be reachable from `refs/heads/main`. A persistent self-hosted runner cannot disable that requirement. Hosted pull-request callers may deliberately set `require_trusted_ref: false`, but must not reuse that caller on a persistent production runner.

## Billing emergency

Copy `templates/repository-validation-emergency.yml` into the consumer repository and protect the selected GitHub Environment with required reviewers. The template dispatches from the consumer, records approval without checking out candidate code, then calls the central reusable workflow for the exact SHA on a trusted self-hosted runner. It does not accept arbitrary shell commands or inherited secrets.

## Evidence and failure behavior

Evidence contains repository, exact head/base SHAs, executable path, argument hashes/count, optional immutable image digests/IDs, before/after Git workspace state hashes, exit code, duration, timeout state, and available Git/Docker/Compose versions. It never serializes process environment values. Missing, non-executable, symlinked, traversing, or out-of-workspace scripts fail closed.

Rollback is to pin the consumer to the preceding `optimizr-actions` commit while retaining an equivalent mandatory validation job. Do not replace the gate with an all-skipped path.
