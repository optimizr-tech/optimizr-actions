# Release Badge Recovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add one reusable fallback for release badge repair.

**Architecture:** Resolve a validated semver tag, serialize updates and delegate rendering/commit to the canonical badge action.

**Tech Stack:** Python standard library, Git, GitHub Actions, unittest.

## Global Constraints
- Semantic-release remains primary.
- `contents: write` only; no inherited secrets.
- No unvalidated tag, branch or path reaches the composite.

---

### Task 1: TDD resolver
- [x] Confirm missing resolver fails.
- [x] Implement semver/ref/path validation and latest-tag resolution.
- [x] Test with a real temporary Git repository.

### Task 2: Reusable workflow
- [x] Add stable non-cancelling concurrency and pinned checkout.
- [x] Delegate to `update-release-badge@v1`.

### Task 3: Documentation
- [x] Document consumer wrapper, primary/fallback responsibility and rollback.
