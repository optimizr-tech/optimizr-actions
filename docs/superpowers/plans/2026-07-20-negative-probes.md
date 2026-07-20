# Negative Security Probes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add protected, declarative and non-destructive post-deploy security probes.

**Architecture:** A JSON manifest defines bounded requests; named secrets map aliases to origins; a Python runner performs checks and redacted evidence; a reusable workflow enforces protected self-hosted execution.

**Tech Stack:** Python urllib/ssl, JSON, GitHub Environments, reusable workflows.

## Global Constraints

- Only GET, HEAD and OPTIONS are permitted.
- Never record target URLs, credentials or response bodies.
- Require protected environment approval and a trusted self-hosted runner.

### Task 1: Define safety tests
- [x] Add failing tests for destructive methods, target redaction and workflow named secrets.

### Task 2: Implement manifest and HTTP runner
- [x] Add schema validation, redirect denial, request/time/body limits and policy assertions.
- [x] Add alias-only SHA-bound evidence.

### Task 3: Add protected workflow
- [x] Add named target secrets and environment approval.
- [x] Upload evidence even after failed probes.

### Task 4: Validate and publish
- [x] Run focused unit, compile and YAML parsing checks.
- [ ] Run complete repository CI.
- [ ] Open a draft PR closing #26.
