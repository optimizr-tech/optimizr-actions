# Security Suite Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an allowlisted reusable security-suite orchestrator.

**Architecture:** Resolve the profile once, call existing governed reusable workflows, then emit a sanitized always-uploaded result.

**Tech Stack:** GitHub Actions YAML, Bash, Python standard library, unittest.

## Global Constraints

- Keep `permissions: contents: read`.
- Never accept arbitrary shell commands or inherited secrets.
- Keep third-party actions SHA-pinned.
- Publish only after #28, #29, #30 and #31.

---

### Task 1: Contract tests

**Files:**
- Create: `tests/test_security_suite_contract.py`

- [x] Assert all five profiles and child workflow references.
- [x] Assert read-only permissions, pinned artifact upload and no unsafe command/secrets inputs.

### Task 2: Reusable workflow

**Files:**
- Create: `.github/workflows/_security-suite.yml`

- [x] Add profile resolution, conditional child jobs and always-running summary.
- [x] Bind every job to the caller's validated `runner_json`.

### Task 3: Documentation

**Files:**
- Create: `docs/SECURITY_SUITE.md`
- Create: `docs/superpowers/specs/2026-07-20-security-suite-design.md`

- [x] Document profiles, usage, dependency order and rollback.
