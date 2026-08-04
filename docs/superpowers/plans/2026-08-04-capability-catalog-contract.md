# Capability Catalog Contract Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a deterministic, machine-readable inventory of every public reusable workflow, composite action, and consumer template, with CI drift detection for additions, removals, and source changes.

**Architecture:** A small dependency-free Python module discovers the public repository surface and serializes a canonical JSON document. The committed catalog stores one entry per artifact with its kind, path, source digest, maturity, and review status. Contract tests compare the committed document against live discovery and print the canonical replacement when drift occurs.

**Tech Stack:** Python 3 standard library, JSON, SHA-256, `unittest`, GitHub Actions repository validation.

## Global Constraints

- Public workflows are `.github/workflows/_*.yml`.
- Public composite actions are `.github/actions/*/action.yml`.
- Public templates are regular files recursively under `templates/`.
- Generated output must be deterministic and end with one newline.
- Catalog entries must be sorted by repository-relative POSIX path.
- Runtime code must not import third-party packages.
- The first slice establishes inventory and drift contracts; profiles and consumer conformance rules remain separate follow-up slices of #114.
- This branch must not merge, move `v1`, deploy, provision runners, or change a consumer.

---

### Task 1: Define the missing catalog behavior

**Files:**
- Create: `tests/test_capability_catalog.py`

**Interfaces:**
- Consumes: `scripts.capability_catalog.catalog.build_catalog(root)` and `render_catalog(root)`.
- Produces: Contract tests for discovery, deterministic serialization, schema fields, and committed-catalog equality.

- [ ] Create tests that import the not-yet-existing module and require:

```python
catalog = build_catalog(ROOT)
assert catalog["schema_version"] == 1
assert catalog["artifacts"] == sorted(catalog["artifacts"], key=lambda item: item["path"])
assert {item["kind"] for item in catalog["artifacts"]} <= {"workflow", "action", "template"}
```

- [ ] Require every entry to contain exactly:

```text
path, kind, source_sha256, maturity, metadata_status
```

- [ ] Require `maturity == "stable-v1"` for workflows/actions and `maturity == "canonical-template"` for templates.
- [ ] Require `metadata_status == "unclassified"` in this first slice.
- [ ] Require `catalog/capabilities.json` to equal `render_catalog(ROOT)` byte-for-byte.
- [ ] Run the full contract suite and verify RED because the module and catalog do not exist.

---

### Task 2: Implement deterministic discovery and rendering

**Files:**
- Create: `scripts/capability_catalog/__init__.py`
- Create: `scripts/capability_catalog/catalog.py`
- Create: `scripts/capability_catalog/generate.py`
- Create: `catalog/capabilities.json`
- Test: `tests/test_capability_catalog.py`

**Interfaces:**
- Produces: `discover_public_artifacts(root: Path) -> list[tuple[str, str]]`, `build_catalog(root: Path) -> dict[str, object]`, and `render_catalog(root: Path) -> str`.

- [ ] Discover workflow paths with `(root / ".github/workflows").glob("_*.yml")`.
- [ ] Discover action paths with `(root / ".github/actions").glob("*/action.yml")`.
- [ ] Discover every regular file beneath `templates/` recursively, excluding `__pycache__` and dotfiles.
- [ ] Normalize all paths through `relative_to(root).as_posix()`.
- [ ] Compute `source_sha256` from raw file bytes.
- [ ] Sort entries by path.
- [ ] Serialize with `json.dumps(..., indent=2, sort_keys=True) + "\n"`.
- [ ] CLI usage:

```bash
python -m scripts.capability_catalog.generate
python -m scripts.capability_catalog.generate --check
```

The first command writes `catalog/capabilities.json`; `--check` exits nonzero and prints the canonical document when the committed file differs.

- [ ] Initially commit an empty schema-valid catalog, run CI, and use the test/CLI diagnostic to obtain the exact canonical catalog generated from the repository.
- [ ] Replace the empty file with the canonical output.

---

### Task 3: Verify and document the first catalog slice

**Files:**
- Modify: `README.md`
- Modify: `docs/ACTIONS_CONSOLIDATION.md`
- Verify: all tests and `actionlint`.

**Interfaces:**
- Consumes: committed catalog and generator.
- Produces: documented update/check commands and explicit follow-up boundary.

- [ ] Document the catalog path and update/check commands.
- [ ] State that `metadata_status: unclassified` is intentionally temporary until the profiles/documentation slice.
- [ ] Run `python -m unittest discover -s tests -p 'test_*.py' -v`.
- [ ] Run `python -m scripts.capability_catalog.generate --check`.
- [ ] Run `actionlint`.
- [ ] Open a draft PR with RED/GREEN evidence and keep #114 open for profiles and conformance audit.
