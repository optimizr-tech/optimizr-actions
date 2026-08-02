# Semantic Release Node 24/npm 11 Implementation Plan

> **For agentic workers:** Use TDD and preserve one independently revertible consumer migration.

**Goal:** Standardize the canonical semantic-release reusable on Node 24/npm 11 and make it safe for `infra-ops` adoption.

**Architecture:** The reusable owns runtime selection; callers own only runner labels, release configuration source, and delivery authorization. npm is installed before dependency installation. Semantic-release plugins remain ephemeral and lockfile-neutral.

## Task 1 — Add failing workflow contract

- [ ] Create `tests/test_semantic_release_runtime_contract.py`.
- [ ] Require Node default `24`, npm input/default `11`, pinned setup-node, controlled npm install before dependency installation, no package-lock regeneration, `--package-lock=false`, dry-run, release, and badge behavior.
- [ ] Run `python -m unittest tests.test_semantic_release_runtime_contract -v` and record RED.

## Task 2 — Implement controlled runtime

- [ ] Add `npm_version` input to `_semantic-release.yml`.
- [ ] Change `node_version` default to `24`.
- [ ] Add a Bash step after setup-node that validates npm version syntax, installs `npm@${NPM_VERSION}`, and prints Node/npm versions.
- [ ] Keep the existing dependency install command after runtime setup.
- [ ] Preserve ephemeral plugin installation with `--package-lock=false`.
- [ ] Run the focused contract and record GREEN.

## Task 3 — Document and validate

- [ ] Add `docs/SEMANTIC_RELEASE.md` or update the existing release documentation with Node 24/npm 11 defaults, override rules, lockfile behavior, migration, and rollback.
- [ ] Run full `python -m unittest discover`.
- [ ] Run actionlint and composite/workflow validation through PR CI.
- [ ] Open a reviewable PR closing #128.

## Task 4 — Consumer migration

- [ ] Open an `optimizr-infra-ops` issue and PR.
- [ ] Change `.github/workflows/release.yml` to call `optimizr-actions/_semantic-release.yml@v1` with Node 24/npm 11.
- [ ] Align `package.json` engine/package-manager metadata and npm 11 lockfile.
- [ ] Keep local `_semantic-release.yml` temporarily as a compatibility copy, then remove it in a second PR after canary evidence.
- [ ] Prove release dry-run, no lockfile mutation, badge update, and controlled `v1` movement.
