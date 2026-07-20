# Repository Validation Gate Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add a safe repository-owned validation command and reviewed billing-emergency workflow.

**Architecture:** A Python argv runner owns validation and evidence; a composite action adapts it to GitHub Actions; a reusable workflow separates normal and protected manual execution.

**Tech Stack:** Python standard library, Bash composite steps, GitHub reusable workflows, unittest.

## Global Constraints

- Preserve `v1` caller compatibility.
- Keep `contents: read` permissions and avoid inherited secrets.
- Never evaluate consumer-provided shell text.
- Never run untrusted pull-request code on persistent self-hosted runners.

### Task 1: Define failing behavior tests

- [x] Add unit tests for arguments, path confinement, literal argv and sanitized evidence.
- [x] Add static tests for workflow triggers and security boundaries.
- [x] Run `python -m unittest discover -s tests -v` and observe missing implementation failures.

### Task 2: Implement the argv-safe runner

- [x] Add `scripts/repository_validation/runner.py` with path, SHA, timeout and JSON validation.
- [x] Write atomic evidence without environment serialization.
- [x] Add trusted-branch ancestry verification.

### Task 3: Publish portable Actions contracts

- [x] Add the composite action.
- [x] Add normal `workflow_call` and protected `workflow_dispatch` jobs.
- [x] Pin third-party actions and retain evidence on failure.

### Task 4: Document, validate and publish

- [x] Document normal, emergency, migration and rollback use.
- [ ] Run the complete repository test and YAML validation suites in GitHub CI.
- [ ] Open a draft PR closing #21.
