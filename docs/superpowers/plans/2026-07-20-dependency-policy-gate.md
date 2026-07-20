# Dependency Policy Gate Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add reusable lockfile, vulnerability and license enforcement for Python and Node consumers.

**Architecture:** Native package managers prove lock synchronization; Trivy emits a stable JSON inventory; a Python policy engine applies severity, license and expiring-exception rules.

**Tech Stack:** Python, uv, Poetry, npm, pnpm, Yarn, Trivy, GitHub Actions.

## Global Constraints

- Fail closed on missing/stale locks and unavailable advisory data.
- Policy exceptions require exact scope, owner, statement and expiry.
- Preserve read-only permissions and sanitized evidence.

### Task 1: Test ecosystem and policy behavior
- [x] Add failing tests for lock detection, npm synchronization, expired exceptions, vulnerabilities and licenses.

### Task 2: Implement policy engine
- [x] Add detection, policy schema, report evaluation and hashed evidence.

### Task 3: Implement portable workflow
- [x] Add controlled package-manager checks and Trivy license/vulnerability scan.
- [x] Add read-only reusable workflow and artifact retention.

### Task 4: Validate and publish
- [x] Run focused unit, compile and YAML parsing checks.
- [ ] Run complete repository CI.
- [ ] Open a draft PR closing #23.
