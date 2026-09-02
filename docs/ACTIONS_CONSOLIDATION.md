# Actions consolidation

## Decision

`optimizr-actions` is the canonical repository for portable GitHub Actions automation. `optimizr-infra-ops` owns VPS provisioning, runner registration, operational users and permissions, canonical server paths, host-wide retention, runbooks and adoption tracking.

Portable workflow, composite-action, parser, policy-evaluation and evidence-generation code must be reviewable and versioned in `optimizr-actions`. A consumer must not require read access to `optimizr-infra-ops` merely to execute a portable capability.

## Current canonical inventory

| Capability | Canonical implementation | Compatibility state |
|---|---|---|
| Python UV validation steps | `.github/actions/python-uv-test-steps/action.yml` | `optimizr-actions` owns execution; private compatibility copies may remain until consumers migrate |
| Python UV reusable | `.github/workflows/_python-uv-test.yml` | runner-portable; billing marker remains caller-only |
| Generic VPS deploy | `.github/workflows/_vps-self-hosted-deploy.yml` | self-contained portable implementation |
| Monorepo VPS deploy | `.github/workflows/_vps-monorepo-deploy.yml` | healthcheck, evidence and cleanup are local to `optimizr-actions` |
| Quality-gate package | `scripts/quality_gate/` | parsers, comparison, baseline, comment and legacy interface are local |
| Quality-gate workflows | `.github/workflows/_quality-gate*.yml` | execute the exact reusable revision through `job.workflow_repository` and `job.workflow_sha` |
| Quality-gate compatibility action | `.github/actions/quality-gate-scripts/action.yml` | materializes the package shipped with the selected Actions revision; old infra-ops inputs are ignored compatibility no-ops |
| Docker/runner cleanup | `.github/actions/docker-prune-safe/action.yml` | workspace cleanup is portable; host-wide Docker prune requires an explicit trusted-runner opt-in |

## Machine-readable capability boundary

The complete public surface is tracked in `catalog/capabilities.json` and verified
against live repository discovery. The first catalog contract inventories:

- reusable workflows matching `.github/workflows/_*.yml`;
- composite actions matching `.github/actions/*/action.yml`;
- regular canonical files beneath `templates/`.

Every entry contains a deterministic SHA-256 digest of the exact source file.
Adding, removing, or changing a public artifact without regenerating the catalog
fails the repository contract suite.

Use:

```text
python -m scripts.capability_catalog.generate
python -m scripts.capability_catalog.generate --check
```

Detailed capability metadata remains explicitly `unclassified` until the next
#114 slice assigns categories, runner compatibility, trust boundaries, evidence,
permissions, migration, rollback, and known limitations. The inventory contract
therefore establishes coverage without pretending that the human classification
work is complete.

## Repository boundary

The repository-boundary contract requires **zero executable references** to `optimizr-infra-ops` under:

```text
.github/workflows/**/*.yml
.github/actions/**/action.yml
```

Documentation links, migration records and operational ownership references are allowed because they do not execute external code. Any new `uses: optimizr-tech/optimizr-infra-ops/...` reference fails the repository test.

## Exact reusable-source contract

A reusable that needs implementation files from its own repository checks out:

```yaml
repository: ${{ job.workflow_repository }}
ref: ${{ job.workflow_sha }}
```

This keeps a consumer using floating `@v1` aligned with the exact revision GitHub resolved for that run. It also allows candidate workflow revisions to be validated without silently importing an older `v1` implementation.

The resolved reusable SHA is audit evidence. It does not replace the governed floating `@v1` consumer contract.

All executable first-party references inside this repository and in its
consumer templates must use the floating `@v1` tag. An internal commit SHA is
not an approved consumer pin; immutable SHAs remain appropriate for
third-party actions and for runtime evidence such as `job.workflow_sha`.

## Compatibility policy

Existing `v1` inputs remain accepted when they can safely become compatibility no-ops. In particular, the historical quality-gate inputs and secret declaration referring to `infra-ops` remain declared temporarily so existing callers do not fail workflow validation, but they are not read and do not authorize external checkout.

A change is compatible with `v1` only when it:

- adds optional inputs with safe defaults;
- adds outputs without changing existing outputs;
- fixes implementation defects without changing documented caller behavior;
- keeps permissions equal or narrower;
- leaves production triggering under consumer control.

Required inputs, removed inputs, changed defaults, widened permissions or changed deployment semantics require a `v2` proposal.

## Consumer migration gates

Every consumer migration must prove:

- merge cleanliness against its current base;
- no execution of untrusted pull-request code on a persistent self-hosted runner;
- least-privilege `GITHUB_TOKEN` permissions;
- explicit production environment usage;
- external third-party actions pinned to immutable SHAs;
- local or hosted validation tied to the exact candidate SHA;
- no production deploy before explicit approval;
- rollback to the last reviewed compatible Actions revision.

## Compatibility-copy removal

A copy in `optimizr-infra-ops` can be deleted only after:

- code search and the adoption registry show zero remaining consumers;
- the replacement has been published and canaried;
- rollback instructions identify the last compatible immutable SHA;
- related runbooks no longer instruct consumers to use the old path;
- deletion is reviewed in a separate `infra-ops` PR.

Compatibility-copy deletion is intentionally outside this repository. The absence of runtime dependencies in `optimizr-actions` does not authorize deleting operational history or consumer fallbacks prematurely.
