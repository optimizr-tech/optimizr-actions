# AGENTS.md — Agent governance for optimizr-actions

## Mission

`optimizr-actions` is the canonical source for portable Optimizr GitHub Actions workflows, composite actions, validation contracts, schemas, and compatibility tests.

Agents must:

- keep reusable contracts generic and independent from private VPS details;
- preserve backwards compatibility for all changes published under `v1`;
- pin third-party actions by immutable commit SHA;
- add or update contract tests with every behavior change;
- document inputs, outputs, permissions, failure modes, and migration impact;
- keep evidence artifacts sanitized and free of credentials or production configuration;
- prefer small, reviewable changes with explicit rollback guidance.

Agents must not:

- store host addresses, credentials, private keys, customer data, signed URLs, or production `.env` content;
- introduce dependencies on `optimizr-infra-ops` for portable workflows or composite actions;
- move the floating `v1` tag without successful release validation;
- silently break caller inputs, outputs, permissions, or default behavior;
- execute untrusted pull-request code on production self-hosted runners;
- merge, publish `v1`, deploy, restart services, or change production without explicit human approval.

## Repository boundaries

### Owned here

- `.github/workflows/_*.yml` reusable CI/CD workflows;
- `.github/actions/*/action.yml` portable composite actions;
- portable local-validation runners and presets;
- deploy-evidence schemas and writers;
- compatibility and static-policy tests;
- canonical consumer templates.

### Owned by `optimizr-infra-ops`

- VPS provisioning and operating-system policy;
- self-hosted runner installation and registry;
- deploy users, paths, permissions, firewall, backups, and operational runbooks;
- production-state inventories and incident response.

### Owned by consumers

- secrets and environment configuration;
- Compose lifecycle and service topology;
- product-specific migrations, RLS, fixtures, smoke tests, and health endpoints;
- environment protection rules and release approval.

## `v1` compatibility policy

A change may be published under `v1` only when:

1. existing required inputs remain valid;
2. existing outputs and defaults retain their meaning;
3. permissions are not broadened silently;
4. third-party actions remain SHA-pinned;
5. contract and static-policy tests pass;
6. known consumers have been inventoried;
7. rollback is documented.

Breaking changes require a new major contract or an explicit deprecation period.

## Required validation

Before opening or updating a PR:

- run `python -m unittest discover -v`;
- validate workflow and action YAML;
- run `git diff --check`;
- scan for secrets;
- compare the branch against the real target branch;
- report checks that could not be executed instead of treating them as green.

## Risk gates

Documentation, inventory, and static tests are safe. Workflow permission changes, deploy behavior changes, release-tag movement, and production execution require explicit human approval before merge or execution.
