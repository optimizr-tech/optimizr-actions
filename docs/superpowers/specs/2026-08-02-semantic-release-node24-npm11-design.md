# Semantic Release Node 24/npm 11 Design

## Problem

The canonical semantic-release reusable defaults to Node 22.14 and inherits its bundled npm. `optimizr-infra-ops` also keeps an executable local copy of that workflow and previously repaired its lockfile specifically for npm 10. This makes release behavior dependent on two drifting implementations and an obsolete runtime contract.

## Decision

`optimizr-actions/_semantic-release.yml` becomes the single executable release workflow. It defaults to Node 24 and npm 11, installs the selected npm before the caller's dependency install command, and retains ephemeral semantic-release/plugin installation with `--package-lock=false`.

`optimizr-infra-ops` will migrate to the canonical `@v1` reusable in a separate consumer PR. Its local reusable remains temporarily for rollback and is deleted only after the canary proves release, badge update, and floating-tag behavior.

## Contract

Inputs:

- `node_version`, default `24`;
- `npm_version`, default `11`;
- existing install, semantic-release, runner, config, badge, and skip inputs remain compatible.

Execution order:

1. checkout exact caller repository;
2. setup controlled Node;
3. install controlled npm and report Node/npm versions;
4. run the reviewed dependency install command;
5. resolve release config;
6. install ephemeral semantic-release runtime without modifying the lockfile;
7. dry-run;
8. release;
9. update badge when requested.

## Failure behavior

Invalid npm version syntax, runtime installation failure, lockfile mismatch, dry-run failure, or release failure blocks the workflow. No fallback to runner-bundled npm is permitted. `[skip-tests]` remains unrelated to release authorization.

## Testing

A new workflow contract test requires Node 24/npm 11 defaults, pinned setup-node, npm installation before the dependency install step, lockfile-neutral runtime installation, and preservation of dry-run/release/badge semantics. The full Actions suite and actionlint must pass.

## Rollback

Revert the Actions PR and retain the prior governed `v1` SHA. The `infra-ops` consumer migration is independently revertible until its compatibility copy is removed.
