# Deploy Manifest Integration Implementation Plan

> **For agentic workers:** use the execution and verification skills task by task.

**Goal:** add optional coherent deployment manifests to both VPS reusables.

**Architecture:** collect sanitized runtime metadata through one Python entrypoint and load that implementation from the exact reusable workflow revision.

**Tech stack:** GitHub Actions, Bash argv, Python standard library, unittest.

## Constraints

- Existing inputs, defaults and deployment lifecycle remain compatible.
- Manifest recording defaults to disabled.
- No production secrets or command output enter evidence.
- Failure evidence never replaces `last-successful.json`.
- Third-party actions remain immutable-SHA pinned.

## Tasks

### 1. Extend the schema

- [x] Add explicit `optional_build_result` with a backward-compatible default.
- [x] Preserve schema version 1.0 and existing writer behavior.
- [x] Update the standalone composite contract.

### 2. Add coherent collection

- [x] Implement fixed-argv Compose service/image and Docker health collection.
- [x] Reject traversal, symlinks and invalid identifiers.
- [x] Add the `record-deploy-manifest` composite action.

### 3. Integrate VPS reusables

- [x] Add optional manifest inputs to both reusable workflows.
- [x] Check out `job.workflow_repository` at `job.workflow_sha`.
- [x] Record manifests through final `if: always()` steps.
- [x] Record optional monorepo build outcomes.
- [x] Remove the remaining runtime dependency on `optimizr-infra-ops` health action.

### 4. Verify and document

- [x] Add collector and workflow contract tests.
- [x] Update existing action contract tests.
- [x] Document revision coherence, evidence and rollback.
- [ ] Require hosted tests, actionlint and exact-SHA PR validation before merge.
- [ ] Pilot in a consumer through a separate PR before enabling broadly.
