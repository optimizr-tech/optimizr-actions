# Portable local validation

Local-first validation is an organization capability: a consumer repository runs its authoritative gate locally and keeps secret-free evidence bound to its exact commit. `optimizr-actions` supplies the portable runner, composite adapter and versioned presets; it never owns consumer credentials or service lifecycle.

## Security model

The preset owns a repository-relative entrypoint. The action does **not** accept an arbitrary command string or caller-declared service versions. It validates and executes the reviewed entrypoint through an allowlisted interpreter (`python` or `bash`) with argv semantics.

The entrypoint receives one environment variable:

```text
OPTIMIZR_VALIDATION_METADATA_PATH
```

It must write schema-version-1 metadata after exercising the real service topology:

```json
{
  "schema_version": 1,
  "services": {
    "postgres": {
      "version": "18.1",
      "digest": "sha256:<64 lowercase hex>",
      "kind": "real"
    }
  },
  "checks": {
    "uv-lock": "passed"
  },
  "conformance": {
    "rls-fail-closed": "passed"
  }
}
```

The adapter validates this document against the selected preset. Required services must have an accepted version prefix and immutable digest. Required checks and conformance IDs must be `passed`; a forbidden service fails closed.

## Fiscal preset

`presets/fiscal.json` requires:

- Python 3.14, Git and Docker;
- `uv.lock`;
- real PostgreSQL 18, RabbitMQ 4.3, MinIO release images and Keycloak 26;
- no Redis service;
- locked uv synchronization, Ruff, format, strict mypy, Alembic, migration/RLS validation and pytest;
- separate runtime/migration database identities;
- fail-closed tenant RLS;
- real-service integration;
- MinIO Object Lock/versioning;
- recovery and negative security checks.

The Fiscal repository owns its Compose topology, credentials, test fixtures and `scripts/ci/fiscal-local-validation.py` implementation.

## Composite usage

Pin the adapter during initial adoption; switch to governed `v1` after release validation:

```yaml
- name: Run Fiscal local validation contract
  uses: optimizr-tech/optimizr-actions/.github/actions/local-validation@<COMMIT_SHA>
  with:
    preset: .github/validation/fiscal.json
    evidence: artifacts/local-validation/fiscal.json
```

The consumer copies the canonical preset or keeps an equivalent reviewed preset at the supplied repository-relative path. `command_args_json` may contain only bounded non-secret arguments; the executable itself always comes from the preset.

## Evidence

The version-2 evidence stores:

- preset and entrypoint SHA-256 hashes;
- head/base commit identity and clean-worktree state;
- Python/Git/Docker versions;
- lockfile path and SHA-256;
- entrypoint path, argv hash, exit code and duration;
- validated service versions/digests;
- check and conformance outcomes;
- explicit unresolved gaps and final result.

It does not store argv values, environment variables, credentials, connection strings, service logs, tenant data or command output. The evidence file is written atomically with mode `0600`.

## Fail-closed behavior

The adapter fails when the workspace/preset/entrypoint/lockfile is unsafe, the required Python/toolchain is missing, the worktree is dirty without an explicit development override, the entrypoint fails, metadata is absent/malformed, a service digest is not immutable, a required check is not passed or a forbidden service appears.

`allow_dirty` exists only for local development. Evidence still records that the worktree was not clean.
