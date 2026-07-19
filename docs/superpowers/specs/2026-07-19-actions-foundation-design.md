# Actions Foundation and Deploy Evidence Design

## Status

Approved on 2026-07-19 for implementation through pull requests only. No direct commits to `main`, no production deployment, no VPS mutation, and no movement of the floating `v1` tag are part of this phase.

## Problem

Portable CI/CD automation is split between `optimizr-actions` and `optimizr-infra-ops`. Some artifacts are identical, while others have already drifted. The public `optimizr-actions` repository therefore is not yet an autonomous source of truth, and production deployments do not persist a generic, sanitized record of the exact SHA and container images that were deployed.

## Responsibility boundary

### `optimizr-actions`

Owns reusable workflows, composite actions, portable validation contracts, deploy evidence schemas, tests for those contracts, and compatibility policy for the published `v1` interface.

### `optimizr-infra-ops`

Owns VPS provisioning, runner installation and registration, users, permissions, canonical paths, operational runbooks, incident procedures, and organization adoption records. Existing portable actions remain temporarily as compatibility shims until every consumer is migrated.

### Consumer repositories

Own product-specific Compose lifecycle, migrations, health assertions, fixtures, secrets, and deployment callers. The CDN is the first planned deploy-manifest consumer; Fiscal adoption follows after the shared foundation is stable.

## Delivery sequence

1. Establish repository boundaries and version the current duplication/drift inventory.
2. Add a standalone, generic deploy-manifest writer to `optimizr-actions` with executable unit tests.
3. Add policy tests that prevent new portable dependencies on `optimizr-infra-ops` while allowlisting existing migration debt.
4. In a separate PR, make the canonical deploy reusables call the deploy-manifest writer without changing existing required inputs or defaults.
5. In a separate `infra-ops` PR, deprecate duplicated portable artifacts and document migration order; do not delete compatibility paths yet.
6. In a separate CDN PR, switch only the caller reference and manifest inputs. Do not change MinIO, PostgreSQL, networking, identities, or stateful service lifecycle.

## Deploy manifest contract

Successful and failed deployment attempts are written as immutable JSON files under:

```text
<DEPLOY_PATH>/.deploy-manifests/
```

Each manifest records:

- schema version;
- status (`success` or `failure`);
- UTC timestamp;
- repository, deployed SHA and ref;
- workflow and run ID;
- environment, actor and runner name;
- updated service names;
- image names and immutable digests when available;
- sanitized healthcheck results;
- sanitized migration result;
- optional rollback reference.

The writer must not accept arbitrary objects. It validates a strict allowlist of fields, rejects multiline scalar values, rejects secret-like keys, limits value sizes, writes with `0600`, creates the directory with `0750`, uses `fsync` plus atomic replacement, and never replaces `last-successful.json` after a failed deployment.

Retention applies only to immutable timestamped manifests. `last-successful.json` is a stable copy of the most recent successful manifest and is not counted against retention.

## Security model

- Production jobs use a protected GitHub Environment and least-privilege `GITHUB_TOKEN` permissions.
- Self-hosted deploy runners must not execute untrusted pull-request code, including forked PRs.
- Consumer workflows pass only explicitly declared inputs and secrets; `secrets: inherit` is not the default pattern for deployment contracts.
- External actions remain pinned by immutable commit SHA.
- Manifest values are metadata only. Environment values, credentials, signed URLs, headers, cookies, and private material are prohibited.
- The manifest writer does not inspect or serialize the process environment.

## Versioning

The first PR adds a new optional composite action and documentation; it does not change any existing reusable workflow contract. A later integration PR may add only optional inputs with safe defaults to `v1`. Any required input, removed input, semantic default change, or changed output requires a `v2` proposal instead of silently moving `v1`.

## Testing

- Unit tests execute the Python writer in temporary directories.
- Tests cover success, failure, last-successful behavior, retention, permissions, invalid paths, symlinks, malformed JSON, secret-like fields and oversized or multiline values.
- Static workflow tests verify the composite delegates to the Python implementation and does not embed deployment logic.
- Boundary tests prevent new `optimizr-infra-ops` references outside an explicit migration allowlist.
- Consumer compatibility is evaluated in separate PRs before any production deployment.

## Out of scope

- CDN hardening PR #113;
- Object Lock, MinIO identities, recovery drills or off-host backup;
- Fiscal integration and real service conformance;
- deleting legacy compatibility artifacts from `infra-ops`;
- merging PRs, moving `v1`, or deploying to production.
