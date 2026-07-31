# Governed Validation Runners Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make reusable validation infrastructure-selectable while preserving functional equivalence and fail-closed aggregation.

**Architecture:** Each reusable validates a bounded runner-mode contract before checkout. Billing markers stay in private callers. The security-suite summary determines required jobs by profile and rejects unexpected skips.

**Tech Stack:** GitHub Actions YAML, embedded Python, Python unittest.

## Global Constraints

- Public reusables never interpret `[skip-tests]`.
- Persistent self-hosted runners execute only trusted `main` or protected dispatch code.
- Pull-request candidate code may use only hosted or explicitly ephemeral self-hosted runners.
- Consumers continue using floating `@v1`.

---

### Task 1: Add failing runner portability contracts

**Files:**
- Create: `tests/test_validation_runner_portability.py`

- [x] Require `runner_json`, `self_hosted_mode`, and `fromJSON` in the four reusables.
- [x] Reject internal billing-marker inspection.
- [x] Require ephemeral PR mode for commitlint and PR metadata validation.

### Task 2: Add failing security-suite skip behavior tests

**Files:**
- Create: `tests/test_security_suite_skip_behavior.py`

- [x] Prove a required Python dependency job cannot be skipped.
- [x] Prove supply-chain may be skipped without image references.
- [x] Prove supply-chain becomes mandatory when image references exist.

### Task 3: Implement governed runner selection

**Files:**
- Modify: `.github/workflows/_docker-compose-validate.yml`
- Modify: `.github/workflows/_trivy-scan.yml`
- Modify: `.github/workflows/_commitlint.yml`
- Modify: `.github/workflows/_validate-pr.yml`

- [x] Add hosted, trusted-main, and ephemeral-pr validation where applicable.
- [x] Remove all internal `[skip-tests]` interpretation.
- [x] Keep explicit optional skip only on Compose and Trivy.

### Task 4: Make suite aggregation fail closed

**Files:**
- Modify: `.github/workflows/_security-suite.yml`

- [x] Compute required jobs from profile and image inputs.
- [x] Fail on required skipped or unsuccessful jobs.
- [x] Record required, expected-skipped, and unexpectedly-skipped sets in sanitized evidence.

### Task 5: Verify

- [x] Run the 7 focused unittest cases.
- [x] Parse all changed workflow YAML.
- [ ] Run the complete Linux suite and actionlint in the PR workflow.
- [ ] Exercise hosted and trusted-main consumer canaries after publication.
