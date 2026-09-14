# Consumer profiles

Opinionated adoption profiles that compose the contracts already published by
`optimizr-actions`. A profile is the *default* way to consume the canonical
capabilities for a given repository shape; it never removes the ability to add
product-specific extensions in the consumer repository.

Every profile is validated by an audit rule that detects local
reimplementations of capabilities that have a canonical reusable (see
`docs/ORG_ADOPTION_AUDIT.md`). Divergence is allowed only when declared as a
product-specific extension with a registered reason.

The artifacts referenced below are the public, tested surface of this
repository, versioned in `catalog/capabilities.json` and verified by
`tests/test_capability_catalog.py`. Runner compatibility and trust boundaries
for each artifact are recorded in the catalog; see
`docs/RUNNER_AND_TRUST_BOUNDARIES.md` for the decision matrix.

## Shared foundation

All profiles start from the repository-governance and security contracts:

| Capability | Reusable | Purpose |
| --- | --- | --- |
| Repository validation | `_repository-validation.yml` | Repository-owned contracts, exact-SHA enforcement, compose/shell/python/trivy/gitleaks/actionlint gates with evidence |
| PR validation | `_validate-pr.yml` | Trusted and untrusted PR paths with caller-level `[skip-tests]` billing guard |
| Commit convention | `_commitlint.yml` | Conventional commit enforcement |
| PR metadata | `_pr-metadata.yml` | PR metadata validation |
| Security suite | `_security-suite.yml` | Combined security gate, SAST, dependency policy and supply-chain evidence |
| Dependency updates | `_dependabot-security-automerge.yml` | Governed Dependabot auto-merge for security PRs |
| Authorization | `.github/actions/validation-authorization/action.yml` | Trust-boundary decision for PR-driven validation |

See `docs/CI_SKIP_CONTRACT.md` for the meaning of `[skip-tests]`: it switches
the validation infrastructure, it does not reduce functional coverage.

## Compose/infra

For repositories that deploy services composed with Docker Compose and
managed through `optimizr-infra-ops`-style runbooks.

| Capability | Reusable | Purpose |
| --- | --- | --- |
| Compose model validation | `_docker-compose-validate.yml` | Structural validation of Compose model |
| Shell syntax/static lint | `_static-lint.yml` | ShellCheck and actionlint on workflows |
| Repository-owned contracts | `_repository-validation.yml` | Central contract evaluation with evidence |
| Filesystem security | `_security-gate.yml` (fs scan) | Trivy vuln/misconfig/secret scan of the filesystem |
| Image security | `_trivy-scan.yml` / `_security-gate.yml` (image scan) | Immutable image identity, baseline and remediation-window evidence |
| Deploy evidence | `.github/actions/record-deploy-manifest/action.yml` + `write-deploy-manifest` | Canonical deploy manifest; replaces consumer-local fallbacks |
| Post-deploy verification | `_post-deploy-verification.yml` + `wait-for-healthcheck` | Healthcheck and post-deploy evidence after deploy |
| Deploy env validation | `.github/actions/validate-deploy-env/action.yml` | Pre-deploy environment validation |

### Compose caller permissions

The job containing `uses:` for `_docker-compose-validate.yml@v1` must declare
the permission ceiling required by the reusable workflow:

```yaml
jobs:
  compose:
    permissions:
      contents: read
      actions: write
    uses: optimizr-tech/optimizr-actions/.github/workflows/_docker-compose-validate.yml@v1
```

These are job-level permissions for the reusable caller, not broad permissions
for every job in the workflow. GitHub validates this ceiling before creating
the called job, so omitting a required scope can result in `startup_failure`
without a job or step log.

### Buildx base-image authentication

When `build_image: true`, `_docker-compose-validate.yml@v1` starts with an
isolated empty Docker configuration under the runner temporary directory. This
prevents stale credentials on a persistent `local-docker` runner from changing
anonymous pulls of public base images. The default is:

```yaml
with:
  build_image: true
  registry_auth_mode: anonymous
```

Private base images require an explicit protected credential. Callers must use
`registry_auth_mode: explicit`, set the registry hostname, pass read-only
`registry_username`/`registry_password` secrets, and run only on a trusted
self-hosted Linux `trusted-main` path (`push` or `workflow_dispatch` on
`refs/heads/main`). Do not pass those secrets to pull-request validation or
reuse the production deploy runner:

```yaml
jobs:
  compose:
    permissions:
      contents: read
      actions: write
    uses: optimizr-tech/optimizr-actions/.github/workflows/_docker-compose-validate.yml@v1
    with:
      runner_json: '["self-hosted","Linux","local-docker"]'
      self_hosted_mode: trusted-main
      build_image: true
      registry: ghcr.io
      registry_auth_mode: explicit
    secrets:
      registry_username: ${{ secrets.GHCR_READ_USERNAME }}
      registry_password: ${{ secrets.GHCR_READ_TOKEN }}
```

The reusable rejects explicit registry authentication outside the trusted
boundary, logs in only to the isolated Docker config, and removes that config
with an `always()` cleanup step. A public-base failure caused by a persistent
runner's inherited Docker credential is therefore fixed by the anonymous
default; it must not be “solved” by moving validation to a production runner.

## Python service

For single-service repositories that run Python with uv.

| Capability | Reusable | Purpose |
| --- | --- | --- |
| uv sync/test/coverage | `_python-uv-test.yml` + `.github/actions/python-uv-test-steps/action.yml` | Matrix test, coverage and evidence |
| Ruff/mypy | `_static-lint.yml` | Python static analysis (Ruff) and type checking (mypy) |
| Dependency/license policy | `_dependency-policy.yml` | Dependency and license policy gates |
| SAST | `_sast-gate.yml` | Static application security testing with evidence |
| Compose/migrations | `_docker-compose-validate.yml` + `_postgres-major-logical-migration.yml` | Compose validation and postgres migration when declared |
| Exact-SHA validation and deployment | `_repository-validation.yml` + `_vps-self-hosted-deploy.yml` | Governed exact-SHA deployment with evidence |

## Monorepo Python + Node

For repositories combining a Python backend and a Node/frontend workspace.

| Capability | Reusable | Purpose |
| --- | --- | --- |
| Backend and frontend matrices | `_python-uv-test.yml` + `_node-project-test.yml` | Per-workspace test matrices with evidence |
| Generated API contracts | `_quality-gate-baseline.yml` | Baseline and diff enforcement for generated contracts |
| Dependency policies by workspace | `_dependency-policy.yml` | Scoped dependency/license policies per workspace |
| Quality gates | `_quality-gate.yml` + `_quality-gate-pr.yml` | Uniform quality gate with duplicate-collection detection |
| Unified exact-SHA evidence | `_repository-validation.yml` + `_supply-chain-evidence.yml` | Single evidence stream across workspaces |

## Extension principle

A repository may extend its profile with product-specific steps and
workflows. The audit differentiates *product-specific extension* from
*avoidable reimplementation*:

- **Extension**: adds behavior the canonical reusable does not provide, or
  hardens a contract with repository-owned facts. Declared in
  `docs/adoption.md` with a reason.
- **Reimplementation**: recreates a canonical capability (local Compose
  validation, local Trivy, local uv test runner) without a registered reason.
  Reported as a finding with the canonical replacement and migration path.

Consumer fallbacks must keep evidence equivalent to the central contract:
same outputs, same exact-SHA source pins, same evidence files. A fallback
that silently drops evidence is treated as a divergence finding.

## Canary consumers

Before recommending general adoption, each profile is exercised by a canary
consumer repository:

| Profile | Canary consumer | Adoption signal |
| --- | --- | --- |
| Compose/infra | `optimizr-monitoring` | Already calls `_repository-validation` and Compose validation; its remaining local CI validation exercises the profile gap the audit flags. Migration tracked in optimizr-tech/optimizr-monitoring#89-#98 |
| Python service | `optimizr-serve` | Smallest service with canonical validation callers; cheapest to migrate and measure. Migration tracked in optimizr-tech/optimizr-serve#1220-#1224 |
| Monorepo Python + Node | To be confirmed after `optimizr-serve` migrates | Adoption audit found `optimizr-serve` to be the only repository calling both `_python-uv-test.yml` and `_node-project-test.yml` (strongest partial monorepo signal); it is re-evaluated as monorepo canary after its Python service migration lands |

Each canary follows the same sequence: run the public adoption audit on the
repository, file migration issues for each finding (no automatic commits),
re-run the audit after migration, and record evidence in the central audit
issue. A profile is recommended for general adoption only after its canary
reaches zero actionable findings.
