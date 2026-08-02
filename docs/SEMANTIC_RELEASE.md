# Semantic release reusable

`_semantic-release.yml` is the canonical executable release contract for Optimizr repositories. Callers select runner labels, release configuration source, and whether badge maintenance is enabled; they do not copy the runtime implementation.

## Controlled runtime

The default release runtime is Node 24 with npm 11. The reusable installs the controlled npm version immediately after `actions/setup-node` and before the caller dependency install command. It prints only the resolved Node and npm versions.

The default dependency command remains `npm ci`. A reviewed consumer may override `install_command`, `node_version`, or `npm_version`, but the override belongs in the caller and must remain compatible with its committed lockfile.

The semantic-release runtime and plugins are installed ephemerally with `--package-lock=false`. The reusable does not regenerate `package-lock.json` and does not use `npm install --package-lock-only`.

```yaml
jobs:
  release:
    uses: optimizr-tech/optimizr-actions/.github/workflows/_semantic-release.yml@v1
    with:
      runs_on: '["self-hosted", "Linux", "service"]'
      node_version: "24"
      npm_version: "11"
      releaserc_source: canonical
      actions_ref: v1
      update_release_badge: true
    secrets: inherit
```

## Release behavior

The workflow checks out complete history, installs dependencies, resolves either the caller configuration or the canonical Optimizr configuration, installs the ephemeral release runtime, executes a dry-run, and then executes semantic-release. Badge maintenance runs only after a successful release job.

`[skip-tests]` does not authorize or suppress a release. Delivery authorization belongs to the exact-SHA validation gate and its caller. The explicit `skip` input exists only for reviewed caller policy.

## `optimizr-infra-ops` migration

`optimizr-infra-ops` must consume this reusable through governed `@v1` instead of maintaining a second executable `_semantic-release.yml`. Its compatibility copy may remain temporarily during the canary and must be removed in a separate PR after release, badge, and floating-tag behavior are proven.

## Failure and rollback

Invalid npm version syntax, Node/npm installation failure, `npm ci` mismatch, release-config resolution failure, dry-run failure, or release failure blocks the job. There is no fallback to the runner-bundled npm.

### Rollback

Revert the central PR and restore the previous governed Actions revision. Consumer migrations are independently revertible until their local compatibility copies are removed. A rollback must not silently return to a runtime that rewrites the consumer lockfile.
