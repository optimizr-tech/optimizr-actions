# Actions Foundation and Deploy Evidence Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `optimizr-actions` the autonomous source of truth for portable automation and add a tested, sanitized deploy-evidence contract without changing any existing production caller.

**Architecture:** Portable behavior lives in small Python modules with composite actions as thin adapters. Existing `v1` workflows remain unchanged in this PR; repository-boundary tests record current migration debt and reject new dependencies on `optimizr-infra-ops`. Follow-up PRs integrate deploy workflows, deprecate `infra-ops` copies, and migrate CDN callers independently.

**Tech Stack:** GitHub Actions YAML, Python 3 standard library, `unittest`, JSON, POSIX filesystem permissions.

## Global Constraints

- Never commit directly to `main`; every repository change is delivered through a reviewable PR.
- Do not merge, move `v1`, deploy, restart services, or mutate the VPS in this plan.
- Preserve all existing required inputs, outputs, defaults and caller semantics in `v1`.
- Do not serialize environment variables or accept credential-bearing metadata.
- Keep self-hosted runners deploy-only and unreachable from untrusted PR jobs.
- External actions remain pinned to immutable commit SHAs.

---

### Task 1: Version the responsibility boundary and drift inventory

**Files:**
- Create: `docs/ACTIONS_CONSOLIDATION.md`
- Modify: `README.md`
- Test: `tests/test_repository_boundary.py`

**Interfaces:**
- Produces: an explicit allowlist named `LEGACY_INFRA_OPS_REFERENCES` in the test file.
- Consumes: current repository paths and known references in `_python-uv-test.yml`, `_vps-monorepo-deploy.yml` and `_quality-gate-pr.yml`.

- [ ] **Step 1: Write the boundary test**

Create a test that recursively scans `.github/workflows` and `.github/actions` for `optimizr-tech/optimizr-infra-ops/`, compares matches with an exact `(path, line)` allowlist, and fails on any new reference.

- [ ] **Step 2: Run the test and verify the allowlist matches current debt**

Run:

```bash
python -m unittest tests.test_repository_boundary -v
```

Expected: PASS only when every current reference is listed exactly and no unlisted reference exists.

- [ ] **Step 3: Document the migration order**

Document artifact ownership, known identical and divergent copies, compatibility strategy, consumer migration order, and removal gates.

- [ ] **Step 4: Update the README**

Link the consolidation document and state that `optimizr-actions` owns portable automation while `infra-ops` owns VPS operations.

- [ ] **Step 5: Commit**

```bash
git add README.md docs/ACTIONS_CONSOLIDATION.md tests/test_repository_boundary.py
git commit -m ":memo: docs(actions): record consolidation boundary"
```

### Task 2: Implement the deploy-manifest writer with TDD

**Files:**
- Create: `scripts/deploy_manifest/__init__.py`
- Create: `scripts/deploy_manifest/write.py`
- Create: `tests/test_deploy_manifest_writer.py`

**Interfaces:**
- Produces: `write_manifest(config: ManifestConfig) -> ManifestResult`.
- Produces: CLI `python -m scripts.deploy_manifest.write` with explicit arguments and JSON-array inputs.
- Consumes: a canonical deployment path, status, metadata strings, services/images/healthchecks JSON, migration result, rollback reference and retention.

- [ ] **Step 1: Write failing unit tests**

Cover:

- successful immutable manifest and `last-successful.json`;
- failure manifest preserving the previous successful pointer;
- `0600` files and `0750` directory;
- retention excluding `last-successful.json`;
- rejection of root, relative and symlink deployment paths;
- rejection of malformed JSON, unknown object keys, multiline values, secret-like keys or values, and excessive lengths;
- atomic replacement without leftover temporary files.

- [ ] **Step 2: Run tests and verify RED**

```bash
python -m unittest tests.test_deploy_manifest_writer -v
```

Expected: FAIL because `scripts.deploy_manifest.write` does not exist.

- [ ] **Step 3: Implement strict data classes and validation**

Implement immutable `ManifestConfig` and `ManifestResult` dataclasses, strict JSON parsing, metadata validation, path validation, atomic writes using `tempfile.mkstemp`, `flush`, `os.fsync`, `os.chmod` and `os.replace`.

- [ ] **Step 4: Run tests and verify GREEN**

```bash
python -m unittest tests.test_deploy_manifest_writer -v
```

Expected: all tests PASS.

- [ ] **Step 5: Commit**

```bash
git add scripts/deploy_manifest tests/test_deploy_manifest_writer.py
git commit -m ":sparkles: feat(deploy): add sanitized manifest writer"
```

### Task 3: Add a thin composite action adapter

**Files:**
- Create: `.github/actions/write-deploy-manifest/action.yml`
- Create: `tests/test_deploy_manifest_action.py`
- Create: `docs/DEPLOY_MANIFEST.md`

**Interfaces:**
- Consumes: composite inputs matching the CLI arguments.
- Produces: `manifest_path` and `last_successful_path` outputs.
- Delegates: `python "$GITHUB_ACTION_PATH/../../../scripts/deploy_manifest/write.py"`.

- [ ] **Step 1: Write failing static contract tests**

Assert that the action delegates to the Python module, uses explicit environment variables and argument arrays, contains no inline Python heredoc, exposes only documented inputs, and writes outputs through `GITHUB_OUTPUT`.

- [ ] **Step 2: Run tests and verify RED**

```bash
python -m unittest tests.test_deploy_manifest_action -v
```

Expected: FAIL because the action does not exist.

- [ ] **Step 3: Implement the composite adapter**

Create a Bash argument array, append only non-empty optional values, invoke the writer, and map its two output lines to action outputs. Do not add a workflow trigger or call the action from a deploy workflow in this PR.

- [ ] **Step 4: Document the schema and consumer contract**

Include a sanitized JSON example, retention, rollback semantics, permissions, prohibited data and adoption steps.

- [ ] **Step 5: Run tests and verify GREEN**

```bash
python -m unittest tests.test_deploy_manifest_action -v
python -m unittest discover -v
```

Expected: all tests PASS.

- [ ] **Step 6: Commit**

```bash
git add .github/actions/write-deploy-manifest/action.yml tests/test_deploy_manifest_action.py docs/DEPLOY_MANIFEST.md
git commit -m ":sparkles: feat(actions): expose deploy manifest adapter"
```

### Task 4: Validate and publish the foundation PR

**Files:**
- Modify only if validation identifies an issue.

**Interfaces:**
- Produces: one draft PR from `feat/actions-foundation-current` to `main`.

- [ ] **Step 1: Run repository tests**

```bash
python -m unittest discover -v
```

Expected: PASS.

- [ ] **Step 2: Run syntax and diff checks**

```bash
git diff --check origin/main...HEAD
python -m compileall scripts tests
```

Expected: no errors.

- [ ] **Step 3: Validate GitHub Actions YAML**

Run the repository's pinned actionlint validation or the hosted workflow. Record clearly if hosted execution is absent.

- [ ] **Step 4: Check merge relationship**

Verify the branch is based on current `main`, is not behind, and has no conflicting files.

- [ ] **Step 5: Open a draft PR**

The PR must state that it does not change existing deploy workflows, consumers, production, or `v1`.

### Task 5: Follow-up PRs after foundation review

**Files:**
- Future `optimizr-actions` PR: `_vps-self-hosted-deploy.yml`, `_vps-monorepo-deploy.yml`, contract tests.
- Future `optimizr-infra-ops` PR: docs, compatibility/deprecation metadata, no deletions before consumer migration.
- Future `optimizr-cdn` PR: caller reference and sanitized manifest inputs only.

**Interfaces:**
- Consumes: the reviewed `write-deploy-manifest` composite at an immutable SHA.
- Produces: manifest evidence on the next authorized production deployment.

- [ ] **Step 1: Stop after opening the foundation PR**

Do not begin consumer changes until the foundation diff and checks have been reviewed.

- [ ] **Step 2: Prepare separate PRs**

Each follow-up PR must independently prove caller compatibility, self-hosted runner event safety, stateful-service preservation and merge cleanliness.
