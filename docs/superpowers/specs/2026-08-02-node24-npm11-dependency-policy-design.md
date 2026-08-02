# Node 24/npm 11 Dependency Policy Design

## Problem

The dependency-policy action currently inherits the runner Node/npm toolchain and validates npm synchronization by regenerating `package-lock.json`. Serve run `30765362153` used Node 22/npm 10 against a repository that requires Node 24 and has npm 11 lockfile metadata, producing an artificial lockfile diff before dependency policy evaluation.

## Decision

The organization dependency contract will use a controlled Node 24 runtime and npm 11 by default. npm lockfiles will be validated immutably with `npm ci --ignore-scripts --no-audit --no-fund`; the gate will never regenerate `package-lock.json`.

The versions remain explicit reusable inputs so a reviewed consumer may select another supported toolchain without copying the action. Inputs are propagated through `_dependency-policy.yml`, `_security-suite.yml`, and `_validation-gate.yml`.

## Components

- `.github/actions/dependency-policy/action.yml`
  - detects the selected ecosystems once;
  - installs Node only when a Node ecosystem is present;
  - installs npm only for npm projects;
  - uses immutable npm validation;
  - preserves uv, Poetry, pnpm, Yarn, Trivy, confinement, and policy enforcement.
- `.github/workflows/_dependency-policy.yml`
  - exposes and forwards `node_version` and `npm_version`.
- `.github/workflows/_security-suite.yml`
  - forwards the toolchain into dependency policy.
- `.github/workflows/_validation-gate.yml`
  - exposes the same organization-level override surface.
- `tests/test_dependency_policy_contract.py`
  - rejects inherited Node/npm and lockfile regeneration;
  - requires pinned setup-node, controlled versions, and `npm ci`;
  - verifies propagation through every reusable layer.
- `docs/DEPENDENCY_POLICY.md`
  - documents defaults, immutable behavior, overrides, and rollback.

## Failure behavior

The gate fails closed when Node/npm installation fails, the declared engine is incompatible, `npm ci` reports a stale lockfile, structural validation fails, advisory data is unavailable, or policy evaluation blocks findings. A failure must not upload an empty evidence path as a second misleading error; the evidence directory is created before lock validation.

## Compatibility

Python-only repositories do not install Node. pnpm and Yarn continue using their controlled package managers, now on the controlled Node runtime. Existing consumers require no change because defaults are backward-compatible at the interface level.

## Validation

1. Contract test fails against the existing Node 22/npm 10 behavior.
2. Contract test passes after implementation.
3. Full repository unit discovery runs on Linux CI.
4. Serve PR #1188 reruns the security suite and demonstrates no `EBADENGINE` warning and no `libc` lockfile diff.

## Rollback

Revert the PR and restore the previous `v1` revision. Consumers that need emergency stability may temporarily pin the prior reviewed Actions SHA while retaining an equivalent Node 24/npm 11 immutable lock check.
