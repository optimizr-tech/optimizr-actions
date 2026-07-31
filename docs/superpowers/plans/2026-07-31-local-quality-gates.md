# Local Quality-Gate Package Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove every executable `optimizr-infra-ops` dependency from `optimizr-actions` while preserving the published quality-gate interfaces.

**Architecture:** Vendor the portable quality-gate package under `scripts/quality_gate`, make the three reusables check out the exact workflow repository revision resolved by GitHub, and keep historical `infra_ops_ref`/token inputs as ignored compatibility no-ops. The compatibility composite materializes the package from its own immutable action checkout.

**Tech Stack:** Python standard library, GitHub Actions reusable workflows, composite actions, unittest, actionlint.

## Global Constraints

- No consumer or production deployment is changed by this PR.
- `v1` remains floating and backward-compatible.
- Exact reusable identity uses `job.workflow_repository` and `job.workflow_sha`.
- No private repository read token is required to execute a portable quality gate.
- Existing quality-gate exit codes and marker-delimited comment behavior remain available.

---

### Task 1: Establish zero-dependency contracts

**Files:**
- Add: `tests/test_quality_gate_local_source.py`
- Modify: `tests/test_repository_boundary.py`

- [x] Require every quality-gate module to exist locally.
- [x] Require all three workflows to use exact reusable source checkout.
- [x] Require the executable infra-ops allowlist to be empty.
- [x] Exercise coverage/security parsing and a red regression verdict.
- [x] Require the compatibility composite to use its own action source.

### Task 2: Vendor the portable package

**Files:**
- Add: `scripts/quality_gate/*.py`

- [x] Add normalized metric models.
- [x] Add coverage, dependency, duplication and bundle parsers.
- [x] Add baseline comparison and severity policy.
- [x] Add deterministic marker-delimited rendering.
- [x] Add idempotent GitHub comment upsert.
- [x] Add exact-run resolution and artifact collection.
- [x] Add baseline/PR orchestration.
- [x] Preserve the legacy metrics interface.

### Task 3: Localize reusable execution

**Files:**
- Modify: `.github/workflows/_quality-gate-baseline.yml`
- Modify: `.github/workflows/_quality-gate-pr.yml`
- Modify: `.github/workflows/_quality-gate.yml`
- Modify: `.github/actions/quality-gate-scripts/action.yml`
- Modify: `.github/actionlint.yaml`

- [x] Remove every executable reference to `optimizr-infra-ops`.
- [x] Check out `job.workflow_repository` at `job.workflow_sha`.
- [x] Point `PYTHONPATH` to the exact reusable revision.
- [x] Keep historical inputs and secret declarations as compatibility no-ops.
- [x] Make the compatibility action materialize its own package.
- [x] Scope actionlint exceptions to the three affected workflows.

### Task 4: Document and verify

**Files:**
- Modify: `docs/ACTIONS_CONSOLIDATION.md`

- [x] Replace the stale six-reference inventory with the zero-execution boundary.
- [x] Document exact reusable source checkout and compatibility policy.
- [ ] Run focused unit tests against the exact branch.
- [ ] Run the complete public repository validation workflow.
- [ ] Validate all workflow/composite YAML and actionlint.
- [ ] Record the successful run on the pull request before review.

The cumulative branch is temporarily validated through a pull request targeting `main`; its focused stacked base is restored only after the exact head completes the public validation workflow.
