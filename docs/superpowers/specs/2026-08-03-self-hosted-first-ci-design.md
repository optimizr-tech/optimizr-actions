# Self-hosted-first CI design

## Status

Approved for implementation on 2026-08-03.

## Problem

GitHub-hosted jobs in private Optimizr repositories can be rejected before runner acquisition when organization billing is unavailable. Such jobs expose no executable steps, so a workflow cannot detect the condition and dynamically fall back. Consumer-level `[skip-tests]`, `skip_tests`, and `bypass_tests` conditions currently avoid some hosted jobs by removing them from the required matrix, which weakens validation and creates inconsistent release authority.

## Decision

Optimizr CI is self-hosted-first.

- Required validation for pull requests runs only on governed ephemeral self-hosted Linux runners.
- Required validation for protected `main` runs on governed persistent self-hosted Linux runners.
- GitHub-hosted execution is an optional portability canary and is never the only required validation path.
- `[skip-tests]`, `skip_tests`, and `bypass_tests` must not authorize, suppress, or replace required validation.
- A required job that is `skipped`, `failure`, or `cancelled` blocks exact-SHA attestation.
- Release, staging, and production deployment depend on the same validated SHA.

## Runner trust modes

### Hosted canary

```text
runner_json = ["ubuntu-latest"]
validation_path = hosted
```

This path is optional in private consumers and may be disabled by repository or organization configuration without affecting the mandatory matrix.

### Ephemeral pull request

```text
runner_json = ["self-hosted", "Linux", "<service>", "ephemeral"]
validation_path = ephemeral-pr
```

The runner must:

- be registered for a bounded execution;
- have no production secrets or production filesystem mounts;
- have no deployment permissions;
- be destroyed or returned to a known-clean image after execution;
- execute only `pull_request` events;
- retain sanitized evidence bound to the candidate SHA.

A persistent deployment runner must never execute pull-request candidate code.

### Trusted main

```text
runner_json = ["self-hosted", "Linux", "<service>"]
validation_path = self-hosted
```

This path is allowed only for `push` or protected `workflow_dispatch` on `refs/heads/main`. Repository validation must prove that the candidate is the exact caller SHA and is reachable from the trusted ref.

### Reviewed emergency

The existing protected Environment route remains available only for reviewed `workflow_dispatch` on `refs/heads/main`. It does not permit tests to be omitted.

## Central workflow changes

`_validation-gate.yml` will accept `ephemeral-pr` and enforce its event and labels before any candidate checkout. It will pass a bounded ephemeral override to `_repository-validation.yml`, while persistent self-hosted validation continues requiring trusted-ref ancestry.

`_node-project-test.yml` will gain the same `self_hosted_mode` trust contract already used by commitlint, PR validation, Compose, Trivy, and Python UV workflows.

The exact-SHA attestation remains based on successful repository validation and security suite results. `ephemeral-pr` evidence validates a pull request but does not authorize protected-main release or deployment.

## Consumer migration

Each active consumer receives a focused draft PR that:

1. removes workflow interpretation of `[skip-tests]`, `skip_tests`, and `bypass_tests`;
2. routes PR validation to service-specific ephemeral runners;
3. routes protected-main validation to persistent service runners;
4. keeps hosted execution optional and non-required;
5. preserves the complete existing test, security, and evidence matrix;
6. blocks downstream delivery when any required result is not `success`;
7. updates runbooks and existing draft PR titles after the new workflow is available.

Migration order:

1. `optimizr-actions` central contract;
2. `optimizr-serve` and TestSprite staging canary;
3. NGINX, Payment, Certbot, Corp Docs, Marketing Site;
4. CDN, Fiscal, Monitoring, Keycloak, Infra Ops;
5. remaining organization repositories after runner-label inventory.

## TestSprite and staging

TestSprite must target an isolated HTTPS staging or preview environment and must reject production hosts. Its API key must not be exposed to arbitrary pull-request code. Until the staging deployment and committed TestSprite suite are ready, TestSprite may remain a non-required protected-main/manual check; unit, integration, lint, Compose, SAST, dependency, and filesystem security checks remain mandatory.

The eventual flow is:

```text
pull request validation
  -> exact candidate artifacts
  -> isolated staging deployment
  -> TestSprite against staging
  -> staging attestation
  -> reviewed promotion
```

## Failure behavior

- Missing ephemeral runner: PR remains queued or blocked.
- Offline persistent runner: protected-main delivery remains blocked.
- Billing unavailable: optional hosted canary may be disabled or skipped; mandatory self-hosted validation continues.
- Required child unexpectedly skipped: attestation fails.
- Candidate SHA mismatch: validation fails.
- Staging or TestSprite unavailable: promotion is blocked once that stage becomes required.

## Rollback

Rollback restores the last reviewed self-hosted workflow revision. It must not restore title- or commit-based test bypasses. A temporary hosted path is acceptable only when billing is available and the complete mandatory matrix remains equivalent.