# Post-Deploy Verification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add protected positive runtime checks plus optional negative probes.

**Architecture:** Validate a declarative manifest, inspect container state through fixed Docker argv, probe named HTTP origins, upload sanitized evidence, and optionally invoke the negative-probe reusable.

**Tech Stack:** Python standard library, Docker CLI, GitHub Actions, unittest.

## Global Constraints
- Exact 40-character deployed SHA.
- Trusted self-hosted runner and protected environment.
- No arbitrary commands, redirects, proxies, private endpoint evidence, or response bodies.

---

### Task 1: TDD runner
- [x] Confirm missing runner fails.
- [x] Implement bounded manifest, Docker and HTTP checks.
- [x] Verify real local HTTP and fake-Docker argv/redaction.

### Task 2: Reusable workflow
- [x] Enforce environment, self-hosted labels and exact checkout.
- [x] Upload positive evidence on every result.
- [x] Optionally call `_negative-probes.yml@v1`.

### Task 3: Documentation
- [x] Document manifest, caller example, evidence and rollback.
