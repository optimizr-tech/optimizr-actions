# Atomic Environment Writer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a schema-driven atomic environment-file writer.

**Architecture:** Read an audited schema, obtain values only from the process environment, render Compose-safe lines, atomically replace a destination inside an allowed root, and retain redacted evidence.

**Tech Stack:** Python standard library, composite GitHub Action, unittest.

## Global Constraints

- No secret values in action inputs, logs, hashes, or evidence.
- Destination must remain inside an existing explicit allowed root.
- Default mode is `0600`; only restricted modes are accepted.
- Schema and evidence paths remain inside the checked-out repository.

---

### Task 1: Tests and schema renderer
- [x] Write failing imports and contract tests.
- [x] Implement schema normalization and Compose escaping.
- [x] Verify missing values and redaction.

### Task 2: Atomic writer and action
- [x] Implement allowed-root/symlink checks and atomic replacement.
- [x] Add the composite action without secret inputs.
- [x] Verify exact destination mode.

### Task 3: Documentation
- [x] Document schema, usage, security boundaries and rollback.
