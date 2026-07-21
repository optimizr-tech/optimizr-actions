# Deploy Manifest Integration Design

## Goal

Integrate the existing sanitized deploy-manifest writer into the generic and monorepo VPS reusables without changing existing callers by default.

## Revision coherence

A reusable workflow may be invoked through `v1` or an immutable SHA. The final manifest stage checks out `job.workflow_repository` at `job.workflow_sha`, then invokes the local `record-deploy-manifest` action from that checkout. Therefore workflow, collector and writer always come from one revision.

## Runtime sequence

The existing checkout, filesystem security, synchronization, networks/volumes, builds, image security, rollout, health verification, post-deploy commands, evidence upload and cleanup order is retained. Optional manifest inputs default to disabled.

When enabled, two final `if: always()` steps:

1. check out the exact reusable revision;
2. collect bounded Compose services, configured image IDs and primary health state and write success/failure evidence.

The prior job failure remains authoritative. A successful deployment updates `last-successful.json`; a failed attempt never does.

## Monorepo details

Optional builds remain non-blocking but expose an explicit `passed` or `failed` result in the manifest. Caller-owned migration commands remain unchanged; the caller may report their governed result through `deploy_manifest_migration_result` without command output entering evidence.

The legacy `optimizr-infra-ops` health action is replaced by the same bounded health wait already used by the generic reusable.

## Security

- no environment values, logs or arbitrary command output are serialized;
- Compose and Docker are executed as fixed argv;
- service/container/path values are bounded and validated;
- the deployment path and Compose file reject traversal and symlinks;
- third-party actions remain immutable-SHA pinned;
- manifests remain `0600` under a `0750` directory.
