# Static-Site Deployment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add protected static-site deployment with candidate and rollback volumes.

**Architecture:** Stage source, build a candidate volume, verify, backup/promote the stable volume, atomically promote source, and restore on failure.

**Tech Stack:** Python standard library, Docker/Compose CLI, GitHub Actions, unittest.

## Global Constraints
- Exact SHA, protected environment and trusted self-hosted runner.
- No arbitrary commands, symlinks, traversal or unverified promotion.
- Builder image must expose fixed `test`, `find` and `cp` entrypoints.

---

### Task 1: TDD deployment engine
- [x] Confirm missing implementation fails.
- [x] Implement manifest/path validation and fixed Docker argv.
- [x] Verify candidate/backup/promotion and failure retention.

### Task 2: Workflow contract
- [x] Enforce protected exact-SHA execution.
- [x] Always upload sanitized evidence and clean workspace.

### Task 3: Documentation
- [x] Document builder contract, manifest, sequence and rollback.
