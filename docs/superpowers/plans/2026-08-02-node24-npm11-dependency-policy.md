# Node 24/npm 11 Dependency Policy Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the reusable dependency policy validate npm lockfiles with controlled Node 24/npm 11 and immutable `npm ci`, then prove the Serve lockfile is not rewritten.

**Architecture:** The dependency-policy composite detects ecosystems before tool setup, installs only the required Node/npm toolchain, and keeps all package-manager checks inside the confined dependency root. The workflow layers expose and forward the same inputs so consumers use one governed contract rather than local setup logic.

**Tech Stack:** GitHub Actions reusable workflows, composite actions, Bash, Python `unittest`, npm.

## Global Constraints

- Default Node version is `24`.
- Default npm version is `11`.
- npm lock validation uses `npm ci --ignore-scripts --no-audit --no-fund`.
- `npm install --package-lock-only` is forbidden in the dependency-policy action.
- All third-party actions remain pinned to immutable 40-character SHAs.
- Python, pnpm, Yarn, Trivy, confinement, and fail-closed policy behavior remain intact.

---

### Task 1: Add failing Node toolchain contract tests

**Files:**
- Modify: `tests/test_dependency_policy_contract.py`

**Interfaces:**
- Consumes: current action/workflow text files.
- Produces: contract assertions for `node_version`, `npm_version`, setup-node pinning, immutable npm validation, and reusable propagation.

- [ ] **Step 1: Add the failing assertions**

Add tests that require:

```python
self.assertIn('default: "24"', action_text)
self.assertIn('default: "11"', action_text)
self.assertRegex(action_text, r"actions/setup-node@[0-9a-f]{40}")
self.assertIn("npm ci --ignore-scripts --no-audit --no-fund", action_text)
self.assertNotIn("npm install --package-lock-only", action_text)
```

Also assert `_dependency-policy.yml`, `_security-suite.yml`, and `_validation-gate.yml` each declare and forward `node_version` and `npm_version`.

- [ ] **Step 2: Run the focused test and verify RED**

Run:

```bash
python -m unittest tests.test_dependency_policy_contract -v
```

Expected: FAIL because the current action inherits runner Node/npm, regenerates `package-lock.json`, and the workflow layers do not expose the new inputs.

- [ ] **Step 3: Commit the RED test**

```bash
git add tests/test_dependency_policy_contract.py
git commit -m ":test_tube: test(deps): require controlled Node lock validation"
```

### Task 2: Implement controlled ecosystem setup and immutable npm validation

**Files:**
- Modify: `.github/actions/dependency-policy/action.yml`
- Test: `tests/test_dependency_policy_contract.py`

**Interfaces:**
- Consumes: inputs `node_version: string`, `npm_version: string`.
- Produces: ecosystem outputs `node_required` and `npm_required`; controlled Node/npm available before lock validation.

- [ ] **Step 1: Add action inputs**

Add:

```yaml
  node_version:
    description: Controlled Node.js version used for Node lock validation
    required: false
    default: "24"
  npm_version:
    description: Controlled npm version used for package-lock validation
    required: false
    default: "11"
```

- [ ] **Step 2: Detect ecosystems before tool setup**

Add a Bash step after root confinement that runs `policy.py detect`, writes the detected values to a temporary file, and exports:

```text
node_required=true|false
npm_required=true|false
```

Node is required for `node-npm`, `node-pnpm`, or `node-yarn`; npm is required only for `node-npm`.

- [ ] **Step 3: Install controlled Node and npm**

Use pinned setup-node:

```yaml
- name: Setup controlled Node.js
  if: steps.ecosystems.outputs.node_required == 'true'
  uses: actions/setup-node@820762786026740c76f36085b0efc47a31fe5020
  with:
    node-version: ${{ inputs.node_version }}
```

Then install npm only for npm projects:

```bash
npm install --global --no-audit --no-fund "npm@${NPM_VERSION}"
node --version
npm --version
```

- [ ] **Step 4: Replace npm lock regeneration**

Keep the structural validator and replace:

```bash
npm install --package-lock-only --ignore-scripts --no-audit --no-fund
git diff --exit-code -- package-lock.json
```

with:

```bash
npm ci --ignore-scripts --no-audit --no-fund
git diff --exit-code -- package-lock.json
```

Create `$GITHUB_WORKSPACE/$EVIDENCE_DIR` before the lock loop so failures leave a deterministic artifact location.

- [ ] **Step 5: Run the focused test and verify GREEN**

Run:

```bash
python -m unittest tests.test_dependency_policy_contract -v
```

Expected: PASS.

- [ ] **Step 6: Commit the implementation**

```bash
git add .github/actions/dependency-policy/action.yml tests/test_dependency_policy_contract.py
git commit -m ":bug: fix(deps): control Node npm lock validation"
```

### Task 3: Propagate toolchain inputs through reusable workflows

**Files:**
- Modify: `.github/workflows/_dependency-policy.yml`
- Modify: `.github/workflows/_security-suite.yml`
- Modify: `.github/workflows/_validation-gate.yml`
- Test: `tests/test_dependency_policy_contract.py`

**Interfaces:**
- Consumes: `node_version` and `npm_version` inputs.
- Produces: a consistent override surface from validation gate to dependency-policy composite.

- [ ] **Step 1: Add inputs to `_dependency-policy.yml`**

Declare defaults `24` and `11`, then forward both to `.github/actions/dependency-policy@v1`.

- [ ] **Step 2: Add inputs to `_security-suite.yml`**

Declare the same defaults and pass both to `_dependency-policy.yml@v1`.

- [ ] **Step 3: Add inputs to `_validation-gate.yml`**

Declare the same defaults and pass both to `_security-suite.yml@v1`.

- [ ] **Step 4: Run focused and workflow contract tests**

Run:

```bash
python -m unittest tests.test_dependency_policy_contract -v
python -m unittest discover -s tests -p 'test_*contract.py' -v
```

Expected: all applicable contract tests pass on Linux.

- [ ] **Step 5: Commit propagation**

```bash
git add .github/workflows/_dependency-policy.yml .github/workflows/_security-suite.yml .github/workflows/_validation-gate.yml tests/test_dependency_policy_contract.py
git commit -m ":construction_worker: feat(deps): propagate Node toolchain inputs"
```

### Task 4: Document the immutable Node contract

**Files:**
- Modify: `docs/DEPENDENCY_POLICY.md`
- Test: `tests/test_dependency_policy_contract.py`

**Interfaces:**
- Produces: operator guidance for defaults, overrides, failure behavior, and rollback.

- [ ] **Step 1: Extend documentation**

Document:

- Node 24 and npm 11 defaults;
- npm 11 lockfiles are checked with immutable `npm ci` and never regenerated;
- reviewed consumers may override versions through the validation gate;
- an engine mismatch or stale lock fails closed;
- rollback to a prior reviewed Actions SHA must preserve equivalent validation.

- [ ] **Step 2: Run documentation contract**

Run:

```bash
python -m unittest tests.test_dependency_policy_contract -v
```

Expected: PASS.

- [ ] **Step 3: Commit documentation**

```bash
git add docs/DEPENDENCY_POLICY.md tests/test_dependency_policy_contract.py
git commit -m ":memo: docs(deps): define Node 24 npm 11 contract"
```

### Task 5: Open draft PR and validate with Serve

**Files:**
- No additional source files.

**Interfaces:**
- Produces: draft PR closing #126 and a consumer canary on Serve PR #1188.

- [ ] **Step 1: Open the Actions draft PR**

Use title:

```text
:bug: fix(deps): enforce Node 24 npm 11 lock validation
```

The body must include RED/GREEN evidence, run `30765362153`, rollback, and `Closes #126`.

- [ ] **Step 2: Run Actions CI**

Require all repository checks to execute; `skipped` is not passing evidence.

- [ ] **Step 3: Publish through governed `v1` only after merge**

Do not move `v1` manually.

- [ ] **Step 4: Rerun Serve PR #1188 security suite**

Expected evidence:

```text
Node v24.x
npm 11.x
no EBADENGINE for optimizr-serve
no package-lock libc diff
dependency policy reaches Trivy/policy evaluation
```

- [ ] **Step 5: Record the canary on #126 and Serve #1188**

Attach run IDs and exact resolved Actions SHA.
