# Validation Gate Runner Mode Propagation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the canonical validation gate propagate the correct security-suite runner trust mode for every governed validation path.

**Architecture:** Keep `validation_path` as the single public trust decision. Translate it inside `_validation-gate.yml` and pass the resulting literal to the existing `_security-suite.yml@v1` input. Add a static contract test that fails whenever this propagation disappears or changes incompatibly.

**Tech Stack:** GitHub Actions reusable workflows, Python `unittest`, YAML static contracts.

## Global Constraints

- Do not add a second caller-controlled trust input.
- Preserve all existing validation-gate outputs and attestation semantics.
- Do not interpret `[skip-tests]`, `skip_tests`, or equivalent markers.
- Do not change consumers, `v1`, runners, releases, or deployments in this PR.

---

### Task 1: Lock the parent-child trust mapping

**Files:**
- Modify: `tests/test_validation_gate_contract.py`
- Modify: `.github/workflows/_validation-gate.yml`

**Interfaces:**
- Consumes: `inputs.validation_path` values `hosted`, `self-hosted`, `ephemeral-pr`, `reviewed-emergency`.
- Produces: `_security-suite.yml@v1` input `self_hosted_mode` with `none`, `trusted-main`, or `ephemeral-pr`.

- [ ] **Step 1: Write the failing contract test**

Add `test_gate_propagates_security_runner_trust_mode` and require the exact expression:

```python
self.assertIn(
    "self_hosted_mode: ${{ inputs.validation_path == 'ephemeral-pr' && 'ephemeral-pr' || ((inputs.validation_path == 'self-hosted' || inputs.validation_path == 'reviewed-emergency') && 'trusted-main' || 'none') }}",
    text,
)
```

- [ ] **Step 2: Run the focused test and verify RED**

Run:

```bash
python -m unittest tests.test_validation_gate_contract.ValidationGateContractTests.test_gate_propagates_security_runner_trust_mode -v
```

Expected: failure because `_validation-gate.yml` does not pass `self_hosted_mode`.

- [ ] **Step 3: Add the minimal workflow mapping**

Under the `security-suite` job `with:` block, add:

```yaml
self_hosted_mode: ${{ inputs.validation_path == 'ephemeral-pr' && 'ephemeral-pr' || ((inputs.validation_path == 'self-hosted' || inputs.validation_path == 'reviewed-emergency') && 'trusted-main' || 'none') }}
```

- [ ] **Step 4: Run focused and complete contract tests**

Run:

```bash
python -m unittest tests.test_validation_gate_contract -v
```

Expected: all tests pass.

- [ ] **Step 5: Publish a draft PR**

Open a draft PR against `main`, link #113, and keep it unmerged until GitHub workflow parsing and the full repository validation complete successfully on the exact head SHA.
