# Repository Validation Routing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix reusable repository validation so caller events never suppress execution and move protected emergency dispatch to a consumer-owned caller.

**Architecture:** Keep the normal reusable call-only, add a separate protected emergency reusable, and publish a thin consumer dispatch template. Both reusable workflows expose commit-bound outputs.

**Tech Stack:** GitHub Actions YAML, Python unittest static contracts.

## Global Constraints

- Preserve floating `@v1` compatibility.
- Do not interpret `[skip-tests]` inside public reusables.
- Keep `contents: read`, no inherited secrets, and no `pull_request_target`.
- Never execute untrusted pull-request code on persistent production runners.

---

### Task 1: Prove the mixed-trigger defect

**Files:**
- Modify: `tests/test_repository_validation_contract.py`

- [x] Add a failing assertion that `_repository-validation.yml` has no `workflow_dispatch` trigger or caller-event filter.
- [x] Run `python -m unittest tests.test_repository_validation_contract -v` and confirm failure against the current workflow.

### Task 2: Split normal and emergency execution

**Files:**
- Modify: `.github/workflows/_repository-validation.yml`
- Create: `.github/workflows/_repository-validation-emergency.yml`
- Create: `templates/workflows/repository-validation-emergency.yml`

- [x] Make the normal workflow call-only and remove `github.event_name` conditions.
- [x] Add `result`, `validated_sha`, and `evidence_path` outputs.
- [x] Move Environment protection and self-hosted enforcement to the emergency reusable.
- [x] Add a consumer-owned dispatch template with typed inputs only.

### Task 3: Verify contracts

**Files:**
- Test: `tests/test_repository_validation_contract.py`

- [x] Run the focused unittest suite and confirm all tests pass.
- [x] Parse all three changed workflow/template YAML files.
- [ ] Run the complete Linux repository suite, actionlint, and composite metadata validation in the PR workflow.
- [ ] Confirm the exact stacked PR head passes remote validation after base synchronization.
