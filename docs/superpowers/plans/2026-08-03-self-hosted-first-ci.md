# Self-hosted-first CI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make governed self-hosted runners the mandatory Optimizr validation infrastructure, remove marker-based test bypasses, and migrate every consumer without allowing pull-request code onto persistent production runners.

**Architecture:** The public `optimizr-actions` repository owns runner trust validation and exact-SHA attestation. Pull requests use ephemeral self-hosted runners, protected `main` uses persistent trusted runners, and hosted jobs are optional canaries. Consumer PRs adopt the central contract in waves and remain draft until their runner labels and complete required matrix are proven.

**Tech Stack:** GitHub Actions reusable workflows, Python contract tests, Bash preflight checks, Docker/Compose, Trivy, TestSprite, GitHub self-hosted runners.

## Global Constraints

- Do not merge or deploy automatically.
- Do not execute pull-request candidate code on persistent deployment runners.
- Do not interpret `[skip-tests]`, `skip_tests`, or `bypass_tests` as authorization.
- Required skipped, failed, or cancelled jobs block attestation.
- Every validation and promotion decision is bound to the exact candidate SHA.
- TestSprite targets isolated staging only and never a production hostname.
- Existing consumer test and security coverage must not be reduced.

---

### Task 1: Add central ephemeral pull-request trust contract

**Files:**
- Modify: `tests/test_validation_gate_contract.py`
- Modify: `tests/test_repository_validation_contract.py`
- Modify: `.github/workflows/_validation-gate.yml`
- Modify: `.github/workflows/_repository-validation.yml`

**Interfaces:**
- Consumes: `runner_json`, `validation_path`, `candidate_sha`, caller event and ref.
- Produces: `validation_path=ephemeral-pr`, bounded `allow_ephemeral_pr`, exact-SHA attestation.

- [ ] **Step 1: Add failing tests for `ephemeral-pr`**

Require the gate to contain an `ephemeral-pr` branch that checks `pull_request`, `self-hosted`, `Linux`, and `ephemeral`, and require repository validation to expose an `allow_ephemeral_pr` input.

- [ ] **Step 2: Run the focused tests and verify RED**

Run:

```bash
python -m unittest tests.test_validation_gate_contract tests.test_repository_validation_contract -v
```

Expected: failures for missing `ephemeral-pr` and `allow_ephemeral_pr` contracts.

- [ ] **Step 3: Implement the minimal gate and repository-validation changes**

Persistent self-hosted keeps `require_trusted_ref=true`. Ephemeral PR sets `require_trusted_ref=false`, `allow_ephemeral_pr=true`, and fails unless the caller event and labels match the approved contract.

- [ ] **Step 4: Run the focused tests and verify GREEN**

Run the same command. Expected: all focused tests pass.

- [ ] **Step 5: Commit**

```bash
git add tests/test_validation_gate_contract.py tests/test_repository_validation_contract.py .github/workflows/_validation-gate.yml .github/workflows/_repository-validation.yml
git commit -m ':construction_worker: feat(ci): support ephemeral PR validation'
```

### Task 2: Govern Node project runners

**Files:**
- Modify: `tests/test_validation_runner_portability.py`
- Modify: `.github/workflows/_node-project-test.yml`

**Interfaces:**
- Consumes: `runner_json`, new `self_hosted_mode`, caller event/ref.
- Produces: hosted, trusted-main, or ephemeral-pr runner preflight before candidate checkout.

- [ ] **Step 1: Add `_node-project-test.yml` to portability tests**

Require `runner_json`, `self_hosted_mode`, dynamic `runs-on`, no fixed hosted runner, no marker interpretation, and an explicit ephemeral label check.

- [ ] **Step 2: Run focused portability tests and verify RED**

```bash
python -m unittest tests.test_validation_runner_portability -v
```

Expected: Node reusable fails the new self-hosted-mode assertions.

- [ ] **Step 3: Add trust validation to the matrix-preparation job**

Validate runner labels and caller event before parsing the project matrix. Hosted requires exactly `ubuntu-latest` with mode `none`; trusted-main requires protected main push/dispatch; ephemeral-pr requires pull request plus `ephemeral` label.

- [ ] **Step 4: Run focused tests and verify GREEN**

Expected: all portability tests pass.

- [ ] **Step 5: Commit**

```bash
git add tests/test_validation_runner_portability.py .github/workflows/_node-project-test.yml
git commit -m ':lock: fix(ci): govern Node validation runners'
```

### Task 3: Publish central documentation and draft PR

**Files:**
- Create: `docs/superpowers/specs/2026-08-03-self-hosted-first-ci-design.md`
- Create: `docs/superpowers/plans/2026-08-03-self-hosted-first-ci.md`
- Modify as required: central runner/security documentation and templates discovered by the contract suite.

**Interfaces:**
- Produces: reviewed central PR linked to issue #112.

- [ ] **Step 1: Run the complete repository contract suite**

```bash
python -m unittest discover -v
```

- [ ] **Step 2: Parse workflow YAML and run actionlint**

Use the repository's canonical validation commands and record exact-SHA evidence.

- [ ] **Step 3: Open a draft PR**

Title:

```text
:construction_worker: feat(ci): make validation self-hosted-first
```

The PR must reference #112, explain the security boundary, and remain unmerged until the central checks and consumer canary are green.

### Task 4: Migrate Serve governance and Node validation

**Files:**
- Modify: `optimizr-serve/.github/workflows/commitlint.yml`
- Modify: `optimizr-serve/.github/workflows/validate-pr.yml`
- Modify: `optimizr-serve/.github/workflows/node-validation.yml`
- Add or modify: repository workflow contract tests.

**Interfaces:**
- PR runner: `["self-hosted","Linux","serve","ephemeral"]`, mode `ephemeral-pr`.
- Main runner: `["self-hosted","Linux","serve"]`, mode `trusted-main`.

- [ ] **Step 1: Add consumer tests rejecting marker-based conditions**
- [ ] **Step 2: Verify tests fail against current callers**
- [ ] **Step 3: Remove marker conditions and pass governed runner inputs**
- [ ] **Step 4: Verify metadata, commitlint, frontend tests, and exact-SHA evidence**
- [ ] **Step 5: Open a draft consumer PR without merging**

### Task 5: Harden TestSprite staging execution

**Files:**
- Modify on PR #1180 branch: `.github/workflows/testsprite.yml`
- Modify: `tests/unit/test_testsprite_workflow_contract.py`
- Modify: `docs/runbooks/testsprite-ci.md`

**Interfaces:**
- Trusted staging URL: `https://testsprite-dev.optimizr.tech` or the reviewed replacement.
- Secret: `TESTSPRITE_API_KEY`, never available to arbitrary PR candidate code.

- [ ] **Step 1: Add failing tests that reject production URLs and PR-secret execution**
- [ ] **Step 2: Restrict secret-bearing TestSprite execution to trusted staging promotion/manual main**
- [ ] **Step 3: Route staging validation to governed self-hosted infrastructure**
- [ ] **Step 4: Keep TestSprite non-required until staging and `testsprite_tests/` exist**
- [ ] **Step 5: Update PR #1180 and retain draft state**

### Task 6: Migrate first operational wave

**Repositories:**
- `optimizr-infra-nginx`
- `optimizr-payment`
- `optimizr-infra-certbot`
- `optimizr-corp-docs`
- `optimizr-marketing-site`

For each repository:

- [ ] inventory runner labels and all marker/bypass conditions;
- [ ] add a failing workflow contract test;
- [ ] route required PR checks to the ephemeral service runner;
- [ ] route protected-main checks to the persistent service runner;
- [ ] remove bypass inputs and downstream acceptance of skipped validation;
- [ ] retain hosted jobs only as optional canaries;
- [ ] open one focused draft PR;
- [ ] remove `[skip-tests]` from existing PR titles only after the new caller is present on their base branch.

### Task 7: Migrate second operational wave

**Repositories:**
- `optimizr-cdn`
- `optimizr-fiscal`
- `optimizr-monitoring`
- `optimizr-infra-keycloak`
- `optimizr-infra-ops`

Apply the same test-first migration. Monitoring must invert its current normal-push routing so self-hosted is the default. Keycloak must prove the same product-specific OIDC/Fiscal/CDN smoke matrix on trusted main without running PR code on its persistent runner.

### Task 8: Complete the organization inventory

**Repositories:** Every remaining active repository returned by the GitHub installation, including legacy and ERP repositories.

- [ ] classify each repository as active, archived, documentation-only, or manual-product;
- [ ] record its available persistent and ephemeral runner labels;
- [ ] migrate active automated checks;
- [ ] replace fake automated coverage in manual products with reproducible static/export/schema contracts;
- [ ] open tracking issues where runner infrastructure does not yet exist;
- [ ] remove marker interpretation from templates and organization documentation;
- [ ] update open PR titles after their base workflows are safe.

### Task 9: Verify and close the rollout

- [ ] central exact-SHA PR canary succeeds on an ephemeral runner;
- [ ] trusted-main canary succeeds with the same required matrix;
- [ ] negative required-skipped test blocks attestation;
- [ ] one full consumer chain reaches validation, staging, TestSprite, and verification;
- [ ] organization code search finds no functional marker/bypass conditions;
- [ ] issue #112 receives linked evidence and is closed only after all acceptance criteria are met.