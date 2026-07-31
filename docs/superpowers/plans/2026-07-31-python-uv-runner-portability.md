# Python UV Runner Portability Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the Python UV reusable obey the governed hosted/self-hosted runner contract without interpreting billing markers or executing code from `optimizr-infra-ops`.

**Architecture:** Extend the existing runner-selection contract used by Compose and Trivy to `_python-uv-test.yml`. Keep the existing caller interface backward-compatible, route both normal and integration jobs through the same trust preflight, and use the composite action already owned by `optimizr-actions`.

**Tech Stack:** GitHub Actions YAML, composite actions, Python unittest, PyYAML.

## Global Constraints

- `[skip-tests]` remains a caller-only routing decision.
- Persistent self-hosted runners execute only trusted `main` pushes or protected dispatches.
- Pull-request execution on self-hosted infrastructure requires an `ephemeral` runner label.
- Existing inputs and defaults remain backward-compatible.
- Consumers continue using the governed floating `@v1` reference.

---

### Task 1: Define the missing portability contract

**Files:**
- Modify: `tests/test_validation_runner_portability.py`

**Interfaces:**
- Consumes: Existing workflow text contracts.
- Produces: Regression coverage for Python UV runner selection, marker isolation and Actions-owned composite use.

- [x] Add `_python-uv-test.yml` to the governed reusable matrix.
- [x] Require `runner_json`, `self_hosted_mode` and `fromJSON(inputs.runner_json)`.
- [x] Reject internal `[skip-tests]` and push-message inspection.
- [x] Require both Python jobs to use the Actions-owned composite.
- [x] Run the focused test and observe the expected RED failures.

### Task 2: Implement governed Python validation runners

**Files:**
- Modify: `.github/workflows/_python-uv-test.yml`

**Interfaces:**
- Consumes: `runner_json`, `self_hosted_mode`, existing Python test inputs.
- Produces: Hosted, trusted-main and ephemeral-PR execution paths with identical Python validation behavior.

- [x] Add runner-selection inputs with hosted-compatible defaults.
- [x] Remove internal billing-marker interpretation.
- [x] Add trust validation before checkout in both jobs.
- [x] Disable persisted checkout credentials.
- [x] Replace the two `infra-ops` action calls with the existing `optimizr-actions` composite.
- [x] Preserve the explicit optional `skip` input as caller policy only.

### Task 3: Reduce the migration allowlist and verify

**Files:**
- Modify: `tests/test_repository_boundary.py`

**Interfaces:**
- Consumes: Executable `uses:` references under workflows and composite actions.
- Produces: An allowlist containing only the three remaining quality-gate dependencies.

- [x] Remove the two Python UV legacy references from the allowlist.
- [x] Run focused portability and repository-boundary tests.
- [x] Parse the changed workflow as YAML.
- [ ] Run the complete repository suite and actionlint in the pull-request workflow.
