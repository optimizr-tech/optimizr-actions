# Security Suite Runner Trust Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `_security-suite.yml` and every reusable it composes enforce the approved hosted, ephemeral-PR, and trusted-main runner trust contract before checking out or executing consumer code.

**Architecture:** Add the existing `self_hosted_mode` input and first-step trust guard to the security-suite orchestrator and each directly callable child reusable. The suite propagates the same mode to every child so nested execution cannot silently lose the caller trust decision. Contract tests enumerate the complete security workflow surface and fail whenever a child omits runner-mode validation or the suite fails to propagate it.

**Tech Stack:** GitHub Actions reusable workflows, Bash, embedded Python 3 runner-contract validation, Python `unittest` contract tests.

## Global Constraints

- Required pull-request validation uses `["self-hosted", "Linux", "<service>", "ephemeral"]` with `self_hosted_mode: ephemeral-pr`.
- Required protected-main validation uses `["self-hosted", "Linux", "<service>"]` with `self_hosted_mode: trusted-main`.
- Hosted execution uses exactly `["ubuntu-latest"]` with `self_hosted_mode: none` and remains optional for private consumers.
- No reusable may interpret `[skip-tests]`, `skip_tests`, or `bypass_tests` as authorization to omit required validation.
- Runner trust validation must execute before checkout or consumer-controlled code.
- Existing `@v1` nested references remain floating; exact resolved identity remains execution evidence.
- This branch must not move `v1`, merge a PR, deploy, or modify a consumer repository.

---

### Task 1: Define the failing security-suite trust contract

**Files:**
- Modify: `tests/test_security_suite_contract.py`
- Modify: `tests/test_validation_runner_portability.py`

**Interfaces:**
- Consumes: Existing workflow text under `.github/workflows/`.
- Produces: Contract assertions requiring `self_hosted_mode`, hosted/ephemeral/trusted-main validation, and propagation to all nested security workflows.

- [ ] **Step 1: Extend the suite contract test**

Add tests equivalent to:

```python
    def test_suite_enforces_runner_trust_before_children(self):
        self.assertIn("self_hosted_mode:", self.text)
        self.assertIn('hosted validation must use ["ubuntu-latest"] with mode=none', self.text)
        self.assertIn('os.environ["EVENT_NAME"] != "pull_request"', self.text)
        self.assertIn('"ephemeral" not in labels', self.text)
        self.assertIn('os.environ["EVENT_REF"] != "refs/heads/main"', self.text)

    def test_suite_propagates_runner_mode_to_every_child(self):
        self.assertEqual(
            self.text.count("self_hosted_mode: ${{ inputs.self_hosted_mode }}"),
            5,
        )
```

- [ ] **Step 2: Add security children to the portability matrix**

Extend `ValidationRunnerPortabilityTests.WORKFLOWS` with:

```python
        "_security-suite.yml",
        "_static-lint.yml",
        "_security-gate.yml",
        "_dependency-policy.yml",
        "_sast-gate.yml",
        "_supply-chain-evidence.yml",
```

Extend the PR-capable workflow tuple with the same six workflows so every directly callable child must contain the ephemeral event/label guard.

- [ ] **Step 3: Run the focused tests and verify RED**

Run:

```bash
python -m unittest \
  tests.test_security_suite_contract \
  tests.test_validation_runner_portability -v
```

Expected: failures report missing `self_hosted_mode` and missing ephemeral/trusted-main guard text in the suite and child workflows.

- [ ] **Step 4: Commit the failing contract**

```bash
git add tests/test_security_suite_contract.py tests/test_validation_runner_portability.py
git commit -m ":white_check_mark: test(ci): require security runner trust"
```

---

### Task 2: Enforce and propagate trust in the security-suite orchestrator

**Files:**
- Modify: `.github/workflows/_security-suite.yml`
- Test: `tests/test_security_suite_contract.py`

**Interfaces:**
- Consumes: `runner_json: string`, `self_hosted_mode: string`, caller `github.event_name`, and caller `github.ref`.
- Produces: A validated profile job and five child workflow calls carrying the exact same `self_hosted_mode`.

- [ ] **Step 1: Add the mode input**

Insert after `runner_json`:

```yaml
      self_hosted_mode:
        description: none, trusted-main, or ephemeral-pr
        required: false
        type: string
        default: none
```

- [ ] **Step 2: Validate trust before profile resolution**

Add `Validate runner trust contract` as the first `profile.steps` entry. It must:

```python
labels = json.loads(os.environ["RUNNER_JSON"])
if not isinstance(labels, list) or not labels or any(
    not isinstance(value, str) or not value for value in labels
):
    raise SystemExit("runner_json must be a non-empty JSON string array")
mode = os.environ["SELF_HOSTED_MODE"]
if "self-hosted" not in labels:
    if labels != ["ubuntu-latest"] or mode != "none":
        raise SystemExit('hosted validation must use ["ubuntu-latest"] with mode=none')
    raise SystemExit(0)
if "Linux" not in labels:
    raise SystemExit("self-hosted validation requires the Linux label")
if mode == "trusted-main":
    if (
        os.environ["EVENT_NAME"] not in {"push", "workflow_dispatch"}
        or os.environ["EVENT_REF"] != "refs/heads/main"
    ):
        raise SystemExit(
            "trusted-main requires push/workflow_dispatch on refs/heads/main"
        )
elif mode == "ephemeral-pr":
    if (
        os.environ["EVENT_NAME"] != "pull_request"
        or "ephemeral" not in labels
    ):
        raise SystemExit(
            "ephemeral-pr requires pull_request and an ephemeral runner label"
        )
else:
    raise SystemExit(
        "self-hosted validation requires mode trusted-main or ephemeral-pr"
    )
```

The step environment must bind `RUNNER_JSON`, `SELF_HOSTED_MODE`, `EVENT_NAME`, and `EVENT_REF` from the reusable inputs/caller context.

- [ ] **Step 3: Propagate the mode to all children**

Add this input to `static-lint`, `filesystem-security`, `dependency-policy`, `sast`, and `supply-chain` calls:

```yaml
      self_hosted_mode: ${{ inputs.self_hosted_mode }}
```

- [ ] **Step 4: Run suite tests and verify partial GREEN**

Run:

```bash
python -m unittest tests.test_security_suite_contract -v
```

Expected: suite-specific tests pass; portability tests still fail for child workflows that have not yet implemented the input/guard.

- [ ] **Step 5: Commit the orchestrator change**

```bash
git add .github/workflows/_security-suite.yml
git commit -m ":lock: fix(ci): govern security suite runners"
```

---

### Task 3: Enforce trust in every directly callable security child

**Files:**
- Modify: `.github/workflows/_static-lint.yml`
- Modify: `.github/workflows/_security-gate.yml`
- Modify: `.github/workflows/_dependency-policy.yml`
- Modify: `.github/workflows/_sast-gate.yml`
- Modify: `.github/workflows/_supply-chain-evidence.yml`
- Test: `tests/test_validation_runner_portability.py`

**Interfaces:**
- Consumes: The same `runner_json`, `self_hosted_mode`, `github.event_name`, and `github.ref` contract as the suite.
- Produces: Each workflow independently refuses an invalid hosted/self-hosted pairing before checkout.

- [ ] **Step 1: Add the shared input to every workflow**

Insert after each `runner_json` input:

```yaml
      self_hosted_mode:
        description: none, trusted-main, or ephemeral-pr
        required: false
        type: string
        default: none
```

- [ ] **Step 2: Add the trust guard as the first job step**

For every workflow, add the same `Validate runner trust contract` step specified in Task 2 before any `actions/checkout`, setup action, local action, or consumer-controlled command.

- [ ] **Step 3: Run the focused portability tests and verify GREEN**

Run:

```bash
python -m unittest \
  tests.test_security_suite_contract \
  tests.test_validation_runner_portability -v
```

Expected: all focused tests pass.

- [ ] **Step 4: Commit the child workflow changes**

```bash
git add \
  .github/workflows/_static-lint.yml \
  .github/workflows/_security-gate.yml \
  .github/workflows/_dependency-policy.yml \
  .github/workflows/_sast-gate.yml \
  .github/workflows/_supply-chain-evidence.yml
git commit -m ":lock: fix(ci): bound security child runners"
```

---

### Task 4: Verify the complete central contract

**Files:**
- Verify: `.github/workflows/*.yml`
- Verify: `tests/*.py`
- Verify: `docs/superpowers/specs/2026-08-03-self-hosted-first-ci-design.md`

**Interfaces:**
- Consumes: Completed workflow and test changes.
- Produces: Review evidence for the pull request and the exact publication dependency for the CDN follow-up.

- [ ] **Step 1: Run the complete Python contract suite**

```bash
python -m unittest discover -s tests -p 'test_*.py' -v
```

Expected: PASS with no failures or errors.

- [ ] **Step 2: Run workflow lint**

```bash
actionlint
```

Expected: exit code `0` and no diagnostics.

- [ ] **Step 3: Verify policy markers are absent**

```bash
python - <<'PY'
from pathlib import Path
files = [
    "_security-suite.yml",
    "_static-lint.yml",
    "_security-gate.yml",
    "_dependency-policy.yml",
    "_sast-gate.yml",
    "_supply-chain-evidence.yml",
]
for name in files:
    text = (Path(".github/workflows") / name).read_text()
    for forbidden in ("[skip-tests]", "skip_tests", "bypass_tests"):
        assert forbidden not in text, (name, forbidden)
print("security runner policy verified")
PY
```

Expected: `security runner policy verified`.

- [ ] **Step 4: Open a draft pull request**

The PR body must state:

- the CDN run `30875615791` failed before steps in `Resolve security profile` while the caller selected `ubuntu-latest`;
- this change closes the central trust-contract gap but does not provision runners;
- `v1` must not move until all contract tests and actionlint pass;
- the CDN consumer PR must remain dependent on this publication;
- related issues: `#112`, `#113`, `#114`.

---

### Task 5: Prepare the CDN adoption after central publication

**Files:**
- Consumer modify after `v1` publication: `optimizr-tech/optimizr-cdn/.github/workflows/security-suite.yml`
- Consumer test: `optimizr-tech/optimizr-cdn/tests/test_self_hosted_first_ci_contract.py`
- Consumer plan: `optimizr-tech/optimizr-cdn/docs/superpowers/plans/2026-08-04-security-suite-self-hosted-adoption.md`

**Interfaces:**
- Consumes: Published `_security-suite.yml@v1` with `self_hosted_mode` support.
- Produces: CDN PR security validation on ephemeral PR runners and persistent trusted-main runners, with no title/commit bypass.

- [ ] **Step 1: Write a failing CDN contract test**

Require `security-suite.yml` to contain:

```python
self.assertIn(
    "runner_json: ${{ github.event_name == 'pull_request' && "
    "'[\"self-hosted\",\"Linux\",\"cdn\",\"ephemeral\"]' || "
    "'[\"self-hosted\",\"Linux\",\"cdn\"]' }}",
    text,
)
self.assertIn(
    "self_hosted_mode: ${{ github.event_name == 'pull_request' && "
    "'ephemeral-pr' || 'trusted-main' }}",
    text,
)
self.assertNotIn("[skip-tests]", text)
self.assertNotIn("github.event.head_commit.message", text)
self.assertNotIn("github.event.pull_request.title", text)
```

- [ ] **Step 2: Verify RED against the current CDN main**

```bash
python -m unittest tests.test_self_hosted_first_ci_contract -v
```

Expected: failure because `security-suite.yml` still selects `ubuntu-latest`, omits `self_hosted_mode`, and interprets `[skip-tests]`.

- [ ] **Step 3: Migrate the caller only after `v1` supports the input**

Replace the caller job condition and inputs with:

```yaml
  security:
    uses: optimizr-tech/optimizr-actions/.github/workflows/_security-suite.yml@v1
    with:
      profile: python
      runner_json: ${{ github.event_name == 'pull_request' && '["self-hosted","Linux","cdn","ephemeral"]' || '["self-hosted","Linux","cdn"]' }}
      self_hosted_mode: ${{ github.event_name == 'pull_request' && 'ephemeral-pr' || 'trusted-main' }}
      retention_days: 30
```

- [ ] **Step 4: Verify CDN GREEN and execute canaries**

Required evidence:

1. PR path schedules only on `[self-hosted, Linux, cdn, ephemeral]` and completes the Python suite.
2. Main path schedules only on `[self-hosted, Linux, cdn]` and completes the same required jobs.
3. Negative test with an invalid persistent PR label fails before checkout.
4. Required child `skipped` remains blocking in the suite summary.
5. Evidence is attached to the exact CDN SHA.

- [ ] **Step 5: Update issues with evidence**

Add the central PR/run and CDN canary run IDs to `optimizr-actions#112` and `optimizr-actions#113`. Do not close either issue until all acceptance criteria are demonstrably satisfied.
