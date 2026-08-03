# Exact-SHA Validation Authorization Implementation Plan

> **For agentic workers:** Implement with TDD. Keep the central action independent from consumer-specific preparation and deployment.

**Goal:** Replace duplicated consumer authorization shells with one fail-closed composite that consumes canonical validation-gate outputs.

**Architecture:** A pure Python CLI owns validation and normalized outputs. A composite action maps GitHub inputs to the CLI. Consumers pass `needs.validation-gate.result` and gate outputs explicitly.

## Task 1 — Add RED unit and action contracts

- [ ] Create `tests/test_validation_authorization.py` with success and negative CLI cases.
- [ ] Create `tests/test_validation_authorization_contract.py` requiring action metadata, all inputs/outputs, no checkout, no API polling, and no marker interpretation.
- [ ] Require the canonical digest form `sha256:<64 lowercase hex>`.
- [ ] Run both focused tests and record RED because the action/script do not exist.

## Task 2 — Implement the authorization CLI

- [ ] Add `scripts/validation_authorization/authorize.py`.
- [ ] Parse required values and `allowed_paths_json`.
- [ ] Validate gate job/result, SHA syntax/equality, digest syntax, workflow SHA, path allowlist, and protected ref.
- [ ] Write outputs only after complete authorization.
- [ ] Return exit code `2` for malformed inputs and `1` for a well-formed but unauthorized result.
- [ ] Run focused unit tests until GREEN.

## Task 3 — Add the composite action

- [ ] Add `.github/actions/validation-authorization/action.yml`.
- [ ] Declare required and optional inputs.
- [ ] Map outputs from one `authorize` step.
- [ ] Invoke the Python CLI through `$GITHUB_ACTION_PATH`.
- [ ] Do not checkout code, query GitHub, read secrets, or interpret billing markers.
- [ ] Run action contract tests until GREEN.

## Task 4 — Document and validate

- [ ] Add `docs/VALIDATION_AUTHORIZATION.md` with caller example, digest format, failures, migration, and rollback.
- [ ] Run `python -m unittest discover -s tests -p 'test_*.py' -v`.
- [ ] Require repository-boundary checks, actionlint, and composite metadata validation.
- [ ] Open a reviewable PR referencing #113 and #114.

## Task 5 — Canary in Monitoring

- [ ] Update Monitoring PR #73 to consume the central action at the reviewed PR SHA.
- [ ] Remove the local authorization shell.
- [ ] Prove canonical `sha256:` digest acceptance.
- [ ] Run negative contract cases for skipped gate, missing digest, SHA mismatch, invalid path, and non-main ref.
- [ ] After central merge/publication, replace the temporary SHA with `@v1` and rerun.
