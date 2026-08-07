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
| Compose/infra | `optimizr-monitoring` | Already calls `_repository-validation` and Compose validation; its remaining local CI validation exercises the profile gap the audit flags |
| Python service | `optimizr-serve` | Smallest service with canonical validation callers; cheapest to migrate and measure |
| Monorepo Python + Node | To be selected by the adoption audit | First repository that calls both `_python-uv-test.yml` and `_node-project-test.yml`; per-workspace dependency policies tracked by `_dependency-policy.yml` callers |

Each canary follows the same sequence: run the public adoption audit on the
repository, file migration issues for each finding (no automatic commits),
re-run the audit after migration, and record evidence in the central audit
issue. A profile is recommended for general adoption only after its canary
reaches zero actionable findings.
