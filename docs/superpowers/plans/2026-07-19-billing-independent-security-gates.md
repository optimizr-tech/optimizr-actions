# Billing-Independent Security Gates Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enforce equivalent blocking security validation on GitHub-hosted and trusted self-hosted runners, including mandatory filesystem and built-image scanning before VPS rollout.

**Architecture:** A runner-neutral composite action owns Trivy setup, database freshness, exception validation, reporting, and evidence. A reusable workflow exposes the action to hosted or self-hosted callers, while existing deploy workflows invoke the same action before synchronization and after image build.

**Tech Stack:** GitHub Actions YAML, Bash, Python 3 standard library, Docker Compose, Trivy v0.70.0, `unittest`.

## Global Constraints

- Preserve existing reusable workflow input names and caller compatibility under `@v1`.
- Third-party actions must use immutable full commit SHAs.
- Required or unknown security results fail closed.
- Do not execute pull-request code on persistent production runners.
- Do not record secrets, environment values, host addresses, or customer data.
- `ignore_unfixed` defaults to `false` and must remain explicit.
- Filesystem scanning occurs before deployment synchronization.
- Image scanning occurs after build and before rollout.

---

### Task 1: Define security-gate contracts

**Files:**
- Create: `tests/test_security_gate_contract.py`
- Create: `tests/test_security_gate_evidence.py`

**Interfaces:**
- Consumes: repository paths and public Python functions from `scripts.security_gate.evidence`.
- Produces: executable behavioral and static contracts for all later tasks.

- [ ] Write tests for stale/missing database rejection, exception metadata and expiration, target scoping, image identity, evidence hashing, action pinning, blocking reports, reusable runner selection, and deploy ordering.
- [ ] Run `python -m unittest tests.test_security_gate_contract tests.test_security_gate_evidence -v` and confirm failures are caused by missing implementation.
- [ ] Commit the failing contracts with `:white_check_mark: test(security): define billing-independent gate contract`.

### Task 2: Implement evidence and exception policy

**Files:**
- Create: `scripts/security_gate/__init__.py`
- Create: `scripts/security_gate/evidence.py`

**Interfaces:**
- Produces: `validate_db_metadata`, `render_exception_policy`, `resolve_image_identity`, `write_evidence`, and CLI subcommands `validate-db`, `render-exceptions`, and `write-evidence`.

- [ ] Implement the smallest standard-library functions required by the tests.
- [ ] Run `python -m unittest tests.test_security_gate_evidence -v` and confirm all evidence tests pass.
- [ ] Commit with `:sparkles: feat(security): add fail-closed evidence policy`.

### Task 3: Add portable action and reusable workflow

**Files:**
- Create: `.github/actions/security-gate/action.yml`
- Create: `.github/workflows/_security-gate.yml`

**Interfaces:**
- Composite inputs: `scan_type`, `scan_ref`, `image_refs`, `severity`, `ignore_unfixed`, `exceptions_file`, `trivy_version`, `db_max_age_hours`, `evidence_dir`.
- Reusable workflow inputs mirror the composite inputs and add `runner_json` and artifact controls.

- [ ] Pin `aquasecurity/setup-trivy` by full SHA and install Trivy `v0.70.0`.
- [ ] Refresh and validate the vulnerability database before scanning.
- [ ] Generate table, JSON, and SARIF reports, preserve the blocking exit status, and write evidence for every target.
- [ ] Add a runner-neutral reusable workflow and evidence upload.
- [ ] Run `python -m unittest tests.test_security_gate_contract -v` and validate both YAML files with PyYAML.
- [ ] Commit with `:shield: feat(security): add portable blocking gate`.

### Task 4: Enforce gates in reusable deploy workflows

**Files:**
- Modify: `.github/workflows/_vps-self-hosted-deploy.yml`
- Modify: `.github/workflows/_vps-monorepo-deploy.yml`

**Interfaces:**
- New optional inputs: `security_require_image_scan`, `security_severity`, `security_ignore_unfixed`, `security_exceptions_file`, `security_trivy_version`, `security_db_max_age_hours`. The filesystem gate has no disable input.

- [ ] Add the filesystem gate immediately after checkout.
- [ ] Discover unique Compose image IDs after build.
- [ ] Fail when image scanning is required and no image is available.
- [ ] Run the image gate before `Deploy` or `Roll out services`.
- [ ] Upload security evidence with `if: always()` before cleanup.
- [ ] Run focused contract tests and YAML validation.
- [ ] Commit with `:lock: fix(deploy): require security gate before rollout`.

### Task 5: Document adoption and verify

**Files:**
- Create: `docs/SECURITY_GATE.md`
- Modify: `README.md`

**Interfaces:**
- Produces: caller examples for hosted, self-hosted, deploy integration, exception policy, evidence, rollback, and billing-outage operation.

- [ ] Document normal and billing-outage paths, safe runner constraints, exception schema, outputs, failure modes, migration, and rollback.
- [ ] Run `python -m unittest discover -v`, `python -m compileall scripts tests`, YAML parsing, `git diff --check`, and secret-pattern checks.
- [ ] Open a draft PR linked to issue #19 and report any unavailable runtime checks explicitly.
- [ ] Commit with `:memo: docs(security): document billing-independent gates`.
