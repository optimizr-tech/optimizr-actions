# Reusable CI status gate

`_ci-status-gate.yml` is a small, trusted reusable workflow for publishing a stable caller check from job results.

It is intentionally status-only. It does not check out the caller repository, execute candidate code, run Docker, access secrets, call the GitHub API, or request write permissions. Its only job runs a short local script from the reusable workflow definition.

## Contract

Callers provide an explicit runner label array and the results of their metadata and test jobs:

```yaml
ci-gate:
  name: ci.yml
  needs: [test, pr-metadata]
  if: always()
  uses: optimizr-tech/optimizr-actions/.github/workflows/_ci-status-gate.yml@<immutable-commit-sha>
  with:
    runner_json: '["self-hosted","Linux","local-docker"]'
    test_result: ${{ needs.test.result }}
    metadata_result: ${{ needs.pr-metadata.result }}
```

The selected runner must provide Bash and Python 3. The workflow installs no tools. The called workflow must be pinned to an immutable commit SHA. Keep `if: always()` on the caller job so the gate can report failed or skipped dependencies. Do not pass secrets to this workflow.

The status rules are:

- For `pull_request`, metadata must pass; the candidate test job may pass or be skipped.
- For `push` and `workflow_dispatch`, trusted-main validation must pass.
- A skipped test is accepted only for a `push` whose commit message contains `[skip-tests]`.
- An unsupported event, unknown result, absent result, or malformed runner label array fails closed.

A passing PR status with a skipped candidate test is metadata-only. It does not establish that the PR code ran, that Buildx works for the candidate, or that the candidate is safe. Consumers must keep their existing trusted-main validation and release/deploy dependencies. The caller owns the meaning and completeness of the jobs it aggregates; this reusable workflow is not a release attestation.

## Runner group policy

Reusable workflows from the same organization can use self-hosted runners available to the caller repository. A restricted runner group can therefore allow this exact trusted reusable workflow while declining to allow the caller's candidate-controlled workflow file. Verify the actual runner-group workflow allowlist with an organization owner before changing caller routing. Do not allow a broad PR workflow such as `ci.yml` when its contents can be changed by the PR.

After updating a runner-group workflow allowlist, validate that the reusable gate receives the intended runner group and that no candidate job receives a persistent runner. If the called job remains queued or has no runner-group assignment, keep the group closed and reconcile the access rule rather than falling back to a hosted or production runner.

See [reusable workflows and runner context](https://docs.github.com/en/actions/reference/workflows-and-actions/reusing-workflow-configurations) and [self-hosted runner group access](https://docs.github.com/en/actions/how-tos/manage-runners/self-hosted-runners/manage-access).
