# Candidate functional canary

`_candidate-functional-canary.yml` is an opt-in reusable workflow for functional
checks that need to execute pull-request code on an isolated Linux runner. It
does not change the caller's PR workflow, branch protection, release flow, or
the organization-wide required checks.

## Trust and SHA contract

- The caller invokes this workflow from a `pull_request` workflow. The reusable
  forwards `github.event.pull_request.head.sha` itself; callers cannot substitute
  a different candidate SHA.
- The underlying repository-validation workflow rejects non-PR self-hosted
  execution, checks out that SHA with `persist-credentials: false`, and verifies
  checkout integrity before running the repository-owned script.
- Runner labels are fixed inside this reusable: `self-hosted`, `Linux`,
  `ephemeral`, and `isolated-pr-canary`. Callers cannot select a runner or add a
  fallback. If the lane is absent, the job remains queued; it must not fall back
  to GitHub-hosted, WSL, `local-docker`, or another persistent runner.
- `isolated-pr-canary` is a proposed operator-managed label; the label alone
  does not prove host isolation. InfraOps must assign it only after the positive and
  negative canaries, host/daemon separation, cleanup, and fresh-identity checks
  required by [InfraOps #160](https://github.com/optimizr-tech/optimizr-infra-ops/issues/160).
- The workflow requests only `contents: read`; it declares no secrets and grants
  no package, deployment, or production credentials. Tests needing private
  registry access require a separately reviewed least-privilege design; they
  must not pass production or deploy credentials into candidate code.

## Relationship to existing checks

The caller's existing PR metadata-only check remains separate and does not
validate application code. A consumer may add this functional canary for the
tests its owner selects; the reusable does not make that check globally required
or alter branch protection. Consumers should require it only after InfraOps has
proved the lane and the service owner has selected the applicable tests. A PR
that needs functional evidence is not merge-ready while that evidence is absent.

After merge, the consumer's existing trusted-`main` validation remains a second
barrier. This canary does not authorize a release, image publication, deploy,
health-check, or badge update; those remain governed by the consumer's current
post-merge delivery gates.

## Consumer example

Add this as a separate job to a consumer workflow triggered by `pull_request`;
keep the existing metadata job unchanged:

```yaml
jobs:
  functional-canary:
    uses: optimizr-tech/optimizr-actions/.github/workflows/_candidate-functional-canary.yml@v1
    with:
      script_path: scripts/ci-functional-canary.sh
      args_json: '["--non-production"]'
      required_paths_json: '["scripts/ci-functional-canary.sh"]'
```

The example is not an adoption mandate. The consumer owner remains responsible
for the script, its non-production fixtures, the chosen required status, and
evidence that its selected tests cover the change. Do not add the call until the
isolated lane is available, and do not treat a queued job as a passing check.
