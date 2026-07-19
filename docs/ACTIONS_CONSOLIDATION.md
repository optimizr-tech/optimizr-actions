# Actions consolidation plan

## Decision

`optimizr-actions` is the canonical source of portable reusable workflows, composite actions, validation contracts, consumer templates, and deploy-evidence schemas.

`optimizr-infra-ops` remains responsible for VPS provisioning, runner installation, users, paths, permissions, backups, operational policies, and runbooks. Consumer repositories retain product-specific service orchestration, secrets, migrations, RLS, fixtures, and smoke tests.

This boundary is compatible with the public repository policy: portable automation must not depend on private host data or production configuration.

## Confirmed drift inventory

The table records the state observed before this consolidation branch. Blob equality means identical Git blobs, not merely matching file names.

| Artifact | `optimizr-actions` blob | `optimizr-infra-ops` blob | State | Canonical direction |
|---|---|---|---|---|
| `.github/actions/python-uv-test-steps/action.yml` | `7e502cdb890ceae966cd470dbf21d487788f5780` | `7e502cdb890ceae966cd470dbf21d487788f5780` | identical | keep in actions; deprecate infra copy after consumers migrate |
| `.github/workflows/_python-uv-test.yml` | `3d938f56d33f88401cacc890843aa790942cb6b4` | `7facb593d9a44059526533ae89aa3486772007b7` | divergent | actions contract wins; preserve existing caller inputs under `v1` |
| `.github/workflows/_vps-self-hosted-deploy.yml` | `a048ef9ee81669d9c7d8ebd74c3d3314ed67ac6f` | `06dea45fc392a23c83be5b5361bd7f293f59a366` | divergent | actions implementation wins after contract tests and consumer simulation |
| `.github/workflows/_vps-monorepo-deploy.yml` | `08141e98a8879bdaec9d5432de3d6d07920df6d0` | `6b62b325781115ee0e33fafc10559e46607b132b` | divergent | consolidate in actions; remove internal dependency on infra composites |
| `.github/actions/wait-for-healthcheck/action.yml` | `5b752263c7e1367ea0071ca42e45011b743ce6f6` | pending migration inventory | actions copy exists but its usage comment still points to infra | make actions reference canonical and migrate consumers |
| `.github/workflows/_quality-gate-pr.yml` | `115576e43cd42d39025d82f6c1e987fd63b573b4` | `3c155b54acb650e25eba87b5e59b5e443dc89080` | divergent | migrate scripts/composite to actions before removing legacy token/input contract |

## Known dependency debt

The following portable contracts in `optimizr-actions` still reference `optimizr-infra-ops` and must be removed in staged changes:

- `_python-uv-test.yml` uses `python-uv-test-steps` from infra;
- `_vps-monorepo-deploy.yml` uses `wait-for-healthcheck` from infra;
- `_quality-gate-pr.yml` obtains quality-gate scripts through infra and exposes legacy `infra_ops_ref` and token inputs;
- comments in some composites still advertise infra as the consumer path.

A repository-boundary test must allow only this enumerated debt. Any new portable dependency on infra fails closed.

## Migration sequence

1. Add repository-boundary tests and document the exact allowlist.
2. Add the generic deploy-manifest composite and schema contract without wiring it into production deploys.
3. Replace internal references with `optimizr-actions` equivalents in small compatibility-preserving PRs.
4. Simulate known consumers, beginning with CDN, before moving `v1`.
5. Update consumer callers to `optimizr-actions@v1`.
6. Mark infra copies deprecated and remove them only after repository-wide consumer inventory is empty.

## `v1` policy

Compatible additions may be released through `v1`. Required input removal, renamed outputs, changed defaults, broadened permissions, or changed deployment semantics require either a deprecation period or a new major contract.

The floating tag must not move until tests, YAML validation, secret scanning, consumer simulation, and rollback review succeed.

## Phase boundaries

This phase does not:

- merge any PR;
- move `v1`;
- change production;
- restart CDN services;
- alter MinIO, PostgreSQL, networks, volumes, or identities;
- implement CDN hardening issue/PR work.

The next phase prepares CDN as the first consumer and stops before deploy approval.
