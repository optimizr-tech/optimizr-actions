# Organization Adoption Audit Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a public hosted, privacy-preserving organization workflow audit.

**Architecture:** Query selected repositories by API, apply offline rules, upload a redacted artifact and optionally update a private central issue.

**Tech Stack:** Python standard library, GitHub REST API, GitHub Actions, unittest.

## Global Constraints
- Never clone private repositories.
- Never place private repository names or source snippets in public artifacts.
- Separate read-only audit and issue-write tokens.
- Keep workflow `GITHUB_TOKEN` permissions read-only.

---

### Task 1: Offline audit rules
- [x] Confirm missing module fails.
- [x] Implement legacy/ref/pinning/permission/path/self-hosted/duplication rules.
- [x] Verify public aliasing and redaction.

### Task 2: API and reporting
- [x] Fetch only metadata and workflow contents for an explicit secret allowlist.
- [x] Add Markdown/JSON reports and idempotent private issue markers.

### Task 3: Hosted workflow
- [x] Add scheduled/dispatch public report job.
- [x] Add independent optional private issue job.
- [x] Pin checkout/upload actions and document token scopes.
