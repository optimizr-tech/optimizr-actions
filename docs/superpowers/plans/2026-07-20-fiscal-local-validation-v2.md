# Fiscal Local Validation V2 Implementation Plan

> **For agentic workers:** execute and verify each task before publishing.

**Goal:** replace caller-declared Fiscal service evidence with a repository-owned real-topology validation contract.

**Architecture:** validate a versioned preset, execute its repository-owned entrypoint, validate strict metadata, then write atomic secret-free evidence.

**Tech stack:** Python standard library, composite GitHub Action, Docker-owned consumer entrypoint, unittest.

## Constraints

- no arbitrary command strings or service declarations as action inputs;
- no credentials, environment values, output logs or tenant data in evidence;
- required service digests must be immutable;
- unsafe paths, dirty worktrees and unresolved conformance fail closed;
- consumer repository retains service lifecycle ownership.

## Tasks

### 1. Preset schema

- [x] Define schema version 2 with entrypoint, tools, service constraints and check/conformance IDs.
- [x] Require PostgreSQL 18, RabbitMQ 4.3, MinIO, Keycloak 26 and forbid Redis.

### 2. Portable runner

- [x] Confine preset, entrypoint, lockfile and evidence paths.
- [x] Execute only the preset-owned entrypoint through an allowlisted interpreter.
- [x] Validate service versions/digests and required outcomes.
- [x] Write atomic `0600` evidence without raw argv/environment/output.

### 3. Composite action

- [x] Expose preset, evidence, bounded args and local-only dirty override.
- [x] Avoid service/version/command inputs.

### 4. Verification

- [x] Start with failing tests for the missing v2 behavior.
- [x] Verify success, immutable digest enforcement, forbidden service, traversal/redaction and failed entrypoint evidence.
- [ ] Run full hosted repository tests and action metadata validation on the PR SHA.

### 5. Consumer adoption

- [ ] Add the Fiscal repository entrypoint and real Compose/test lifecycle in a separate consumer PR.
- [ ] Attach sanitized evidence from the exact consumer commit before closing the capability issue.
