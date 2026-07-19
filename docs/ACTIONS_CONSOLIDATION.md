# Actions consolidation

## Decision

`optimizr-actions` is the canonical repository for portable GitHub Actions automation. `optimizr-infra-ops` owns VPS provisioning, runners, users, permissions, canonical paths, operational runbooks and adoption tracking.

This migration is intentionally staged. Existing paths in `optimizr-infra-ops` remain available until all known consumers move to `optimizr-actions` and compatibility is proven.

## Confirmed inventory

| Artifact | `optimizr-actions` blob | `optimizr-infra-ops` blob | Classification | Canonical direction |
|---|---|---|---|---|
| `.github/actions/python-uv-test-steps/action.yml` | `7e502cdb890ceae966cd470dbf21d487788f5780` | `7e502cdb890ceae966cd470dbf21d487788f5780` | Identical | Keep in `optimizr-actions`; migrate callers before deleting the compatibility copy |
| `.github/workflows/_python-uv-test.yml` | `3d938f56d33f88401cacc890843aa790942cb6b4` | `7facb593d9a44059526533ae89aa3486772007b7` | Divergent | Preserve the `optimizr-actions` caller contract; reconcile improvements through tests |
| `.github/workflows/_vps-self-hosted-deploy.yml` | `a048ef9ee81669d9c7d8ebd74c3d3314ed67ac6f` | `06dea45fc392a23c83be5b5361bd7f293f59a366` | Divergent | Use `optimizr-actions` as the implementation base; retain operational path policy in `infra-ops` docs |
| `.github/workflows/_vps-monorepo-deploy.yml` | `08141e98a8879bdaec9d5432de3d6d07920df6d0` | `6b62b325781115ee0e33fafc10559e46607b132b` | Divergent | Remove the internal dependency on the `infra-ops` healthcheck action before consumer migration |
| `.github/workflows/_quality-gate-pr.yml` | `115576e43cd42d39025d82f6c1e987fd63b573b4` | `3c155b54acb650e25eba87b5e59b5e443dc89080` | Divergent | Move portable quality-gate scripts and adapter ownership to `optimizr-actions` in a dedicated PR |

Blob identifiers above are evidence from the repositories at the start of this migration. Future changes must update this inventory or supersede it with a new migration record.

## Existing migration debt

The repository-boundary test currently allowlists exactly four executable references to `optimizr-infra-ops`:

1. `_python-uv-test.yml` — two calls to `python-uv-test-steps`;
2. `_vps-monorepo-deploy.yml` — one call to `wait-for-healthcheck`;
3. `_quality-gate-pr.yml` — one call to `quality-gate-scripts`.

Adding another reference fails the test. Removing a migrated reference also requires updating the allowlist, making debt reduction explicit in review.

## Migration order

1. Add and review the generic deploy-manifest writer in `optimizr-actions` without changing existing reusable workflows.
2. Make `optimizr-actions` workflows call composites from the same repository and preserve all `v1` inputs, outputs and defaults.
3. Add deploy-manifest integration to the generic and monorepo deploy workflows using optional inputs only.
4. Update `infra-ops` documentation and mark portable copies deprecated. Do not delete them while consumers remain.
5. Migrate CDN as the first production consumer through its own PR. Preserve PostgreSQL, MinIO, volumes, networks and service lifecycle.
6. Migrate remaining consumers, then remove compatibility copies in a final `infra-ops` PR.

## Versioning policy

A change is compatible with `v1` only when it:

- adds optional inputs with safe defaults;
- adds outputs without changing existing outputs;
- fixes implementation defects without changing documented caller behavior;
- keeps permissions equal or narrower;
- leaves production triggering under consumer control.

Required inputs, removed inputs, changed defaults, widened permissions or changed deployment semantics require a `v2` proposal.

## Consumer gates

Every consumer migration must prove:

- merge cleanliness against its current base;
- no execution of untrusted pull-request code on a self-hosted runner;
- least-privilege `GITHUB_TOKEN` permissions;
- explicit production environment usage;
- external action SHA pinning;
- no change to stateful-service lifecycle unless separately approved;
- local or hosted validation tied to the exact candidate SHA;
- no production deploy before explicit approval.

## Removal gates for `infra-ops`

A compatibility copy can be deleted only after:

- code search and adoption registry show zero remaining consumers;
- the replacement has been released and validated;
- rollback instructions identify the last compatible immutable SHA;
- related runbooks no longer instruct consumers to use the old path;
- the deletion is reviewed in a separate PR.
