# Node Project Validation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add bounded reusable npm/pnpm project validation.

**Architecture:** Normalize a small project matrix, set up controlled package managers, run package scripts as argv, and retain sanitized artifacts.

**Tech Stack:** GitHub Actions, Python standard library, npm, pnpm, unittest.

## Global Constraints

- Maximum 10 projects and 20 artifact paths per project.
- No arbitrary command strings, inherited secrets or paths outside the workspace.
- Third-party actions remain SHA-pinned.
- Default permissions remain `contents: read`.

---

### Task 1: Runner tests and implementation

**Files:**
- Create: `tests/test_node_project_runner.py`
- Create: `scripts/node_project/runner.py`

- [x] Verify failing imports before implementation.
- [x] Implement path, script, argv and artifact controls.
- [x] Verify success and symlink-denial tests.

### Task 2: Workflow contract

**Files:**
- Create: `.github/actions/node-project-test/action.yml`
- Create: `.github/workflows/_node-project-test.yml`
- Create: `tests/test_node_project_contract.py`

- [x] Validate the matrix before checkout.
- [x] Run each project with pinned setup actions and always upload controlled evidence.

### Task 3: Documentation

**Files:**
- Create: `docs/NODE_PROJECT_TEST.md`
- Create: `docs/superpowers/specs/2026-07-20-node-project-validation-design.md`

- [x] Document examples, security boundaries and rollback.
