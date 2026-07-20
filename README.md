# Optimizr Actions

Reusable GitHub Actions workflows and composite actions for Optimizr projects.

## Public boundary

This repository contains only generic automation. It must never contain
credentials, private keys, host addresses, customer data, production
configuration, or private-repository dependencies. Consumer repositories own
their secrets, service lifecycle, and product-specific checks.

Optimizr-managed consumers should use the floating `v1` tag so compatible
automation fixes propagate without repository-by-repository pin updates. The
tag moves only after this repository's release validation succeeds, and every
change published within `v1` must preserve existing caller contracts. Use an
immutable commit SHA only where a consumer's threat model requires independent
review and explicit upgrades. Changes to reusable workflows, composite actions,
or canonical consumer templates trigger validation and publication of `v1`.

The self-hosted VPS deploy reusable captures status and logs from failed
one-shot Compose services, including containers that have already stopped, so
consumer runs retain the root-cause output instead of only Compose's exit code.

## Organization boundary

`optimizr-actions` is the source of truth for portable reusable workflows,
composite actions, validation contracts and deploy-evidence schemas.
`optimizr-infra-ops` owns VPS provisioning, runner registration, operational
users and permissions, canonical server paths, runbooks and adoption tracking.

The staged migration and current drift inventory are documented in
[`docs/ACTIONS_CONSOLIDATION.md`](docs/ACTIONS_CONSOLIDATION.md). Existing
compatibility paths in `optimizr-infra-ops` remain until all consumers have
migrated and rollback has been validated.

## Validation

Run the repository regression suite with:

```powershell
python -m unittest discover -v
```

The portable local validation contract and Fiscal preset are documented in
[`docs/LOCAL_VALIDATION.md`](docs/LOCAL_VALIDATION.md) once released.

The canonical semantic-release configuration emits an organization-compliant
`:bookmark_tabs: chore(release): <version> [skip ci]` commit subject.

## Security gates

The portable [`security-gate`](.github/actions/security-gate/action.yml) action
and [`_security-gate.yml`](.github/workflows/_security-gate.yml) reusable run the
same blocking Trivy policy on GitHub-hosted or trusted self-hosted runners. The
VPS deploy reusables require filesystem validation before synchronization and
built-image validation before rollout, so `[skip-tests]` cannot become a deploy
without security validation.

Inputs, exception policy, evidence, runner requirements, billing-outage
operation, migration, and rollback are documented in
[`docs/SECURITY_GATE.md`](docs/SECURITY_GATE.md).

## Security

Report vulnerabilities privately as described in
[`SECURITY.md`](SECURITY.md). Do not open public issues containing secrets,
host details, customer data, or proof-of-concept material that could expose
production systems.

## License status

The project is publicly visible, but an open-source license has not yet been
selected. No permission to reproduce, distribute, modify, or sublicense the
code is granted beyond rights that GitHub's Terms of Service provide for
viewing and forking. This status will be replaced only after the copyright and
licensing decision is reviewed.
