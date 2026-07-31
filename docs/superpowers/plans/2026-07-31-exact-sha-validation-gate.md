# Exact-SHA Validation Gate Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce one commit-bound validation output consumed by release and deploy without API polling or duplicated skip logic.

**Architecture:** Compose repository-owned validation and the governed security suite, then create a canonical attestation whose workflow outputs become the sole downstream authority.

**Tech Stack:** GitHub Actions YAML, Python standard library, composite action, unittest.

## Global Constraints

- Preserve floating `@v1` consumption.
- Require `candidate_sha == github.sha`.
- Reject every non-success required child result.
- Keep production image gates in deploy reusables.
- Do not add secrets or API polling.

---

### Task 1: Define failing attestation behavior

**Files:**
- Create: `tests/test_validation_attestation.py`
- Create: `tests/test_validation_gate_contract.py`

- [x] Require digest-bound success evidence.
- [x] Require skipped checks to fail closed.
- [x] Require candidate/context SHA equality.
- [x] Require gate outputs and no polling implementation.

### Task 2: Implement attestation writer and action

**Files:**
- Create: `scripts/validation_attestation/attestation.py`
- Create: `.github/actions/validation-attestation/action.yml`

- [x] Validate schemas, paths, SHAs, workflow identity, and result allowlists.
- [x] Write sanitized canonical JSON and SHA-256 digest.
- [x] Publish bounded GitHub Action outputs.

### Task 3: Expose security-suite result

**Files:**
- Modify: `.github/workflows/_security-suite.yml`

- [x] Export passed result and evidence path only after the fail-closed summary succeeds.

### Task 4: Add central gate

**Files:**
- Create: `.github/workflows/_validation-gate.yml`

- [x] Validate hosted, trusted-main, and reviewed-emergency routing.
- [x] Execute repository validation and security suite once.
- [x] Aggregate child job conclusions into one exact-SHA attestation.
- [x] Expose result, SHA, path, digest, and resolved Actions workflow SHA.

### Task 5: Verify and adopt

- [x] Run 6 focused unit/contract tests.
- [x] Parse reusable and composite YAML.
- [ ] Run full Linux suite, actionlint, and metadata validation in PR checks.
- [ ] Confirm the exact stacked PR head passes remote validation after base synchronization.
- [ ] Migrate canary consumers through issues after publication.
