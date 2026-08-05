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

## Protected main mode

Repositories with strict pull-request rulesets should enable the opt-in protected mode:

```yaml
jobs:
  release:
    uses: optimizr-tech/optimizr-actions/.github/workflows/_semantic-release.yml@v1
    with:
      runs_on: '["self-hosted", "Linux", "service"]'
      releaserc_source: canonical
      actions_ref: v1
      protected_main_mode: true
      update_release_badge: false
    secrets: inherit
```

Protected mode resolves its canonical releaserc and transformer from `job.workflow_repository` at the exact immutable `job.workflow_sha` selected by GitHub for the called reusable workflow. It does not trust a moving branch or tag for its own executable assets, even when the caller keeps `actions_ref: v1` for backward-compatible normal-mode behavior.

The transformer removes `@semantic-release/changelog` and `@semantic-release/git` from the runtime configuration, then verifies that `@semantic-release/github` remains available. Semantic-release can still analyze commits, generate release notes, create the version tag, and publish the GitHub Release, but it does not commit generated files to `main`.

`protected_main_mode` requires `releaserc_source: canonical` and is incompatible with `update_release_badge: true`. A generated `CHANGELOG.md`, package version commit, or badge change must use a separate reviewed pull request if the repository chooses to retain those versioned files. The release workflow must not receive an administrator, PAT, or GitHub Actions bypass merely to push generated commits through branch protection.

The protected transformer is fetched into `RUNNER_TEMP`; the consumer checkout never needs to contain Optimizr Actions implementation scripts.

## `optimizr-infra-ops` migration

`optimizr-infra-ops` must consume this reusable through governed `@v1` instead of maintaining a second executable `_semantic-release.yml`. Its compatibility copy may remain temporarily during the canary and must be removed in a separate PR after release, badge, and floating-tag behavior are proven.

## Failure and rollback

Invalid npm version syntax, Node/npm installation failure, `npm ci` mismatch, release-config resolution failure, protected-mode workflow identity failure, dry-run failure, or release failure blocks the job. There is no fallback to the runner-bundled npm, a mutable asset ref, or a branch-protection bypass.

### Rollback

Disable `protected_main_mode` before ruleset activation if a consumer canary reveals incompatibility, then revert the central PR or restore the previous governed Actions revision. Do not disable a live strict ruleset merely to restore automated CHANGELOG or badge commits. Consumer migrations are independently revertible until strict branch protection is applied. A rollback must not silently return to a runtime that rewrites the consumer lockfile.
