# Semantic release reusable

`_semantic-release.yml` is the canonical executable release contract for Optimizr repositories. Callers select runner labels, release configuration source, and whether badge maintenance is enabled; they do not copy the runtime implementation.

## Controlled runtime

The default release runtime is Node 24 with npm 12.0.2. The reusable installs the controlled npm version immediately after `actions/setup-node` and before the caller dependency install command. It prints only the resolved Node and npm versions.

The default dependency command remains `npm ci`. A reviewed Node consumer may override `install_command`, `node_version`, or `npm_version`, but the override belongs in the caller and must remain compatible with its committed lockfile.

## Package-less consumers

Python or other non-Node repositories can set `package_mode: package-less`. This opt-in skips the caller dependency command and npm project cache; the workflow still installs its controlled Node/npm runtime and the semantic-release runtime plus plugins selected by the caller's release configuration. The existing `node` default keeps the current Node-project behavior unchanged. A package-less caller may set `working_directory` to a subdirectory containing its `.releaserc.json`; the path must resolve inside the checkout. Node mode remains restricted to the repository root so its existing npm cache and lockfile contract do not change.

Package-less configurations must provide an explicit `plugins` array. This prevents semantic-release's implicit default plugin set (which can include the npm publisher) from being selected accidentally. An npm publisher runs only when the caller explicitly includes it in that array. No fake `package.json` or `package-lock.json` is needed.

When `preset: conventionalcommits` is configured, Node consumers continue to validate their declared and locked packages. Package-less consumers validate the installed preset and writer versions in the ephemeral semantic-release runtime against the same supported major-version pairs. The no-Node-manifest fixture lives in `tests/fixtures/package-less-release` and declares only the commit-analyzer and release-notes plugins, not the GitHub or npm publishers. The internal `.github/actions/package-less-release-validation` composite action owns package-less runtime setup, compatibility validation, and semantic-release dry-run; it never publishes a release, tag, or badge. The manually runnable and PR-triggered `semantic-release-package-less-canary.yml` checks out the candidate action with `persist-credentials: false` and `contents: read`, creates a temporary project and local bare Git remote under `RUNNER_TEMP`, and calls the composite action without its optional token input. Its canary-only mode overrides event/branch variables for the dry-run subprocess, passes `--no-ci`, and requires output proving semantic-release analyzed a release version and generated notes. It does not call `_semantic-release.yml`, change an external ref, or exercise GitHub authentication or the reusable workflow's publishing path.

For production package-less releases, `_semantic-release.yml` validates that `job.workflow_repository` is exactly `optimizr-tech/optimizr-actions` and that `job.workflow_sha` is a full commit SHA. It checks out that exact revision into a dedicated path after rejecting any pre-existing path (including a symlink), with `persist-credentials: false`, then invokes the composite action from that checkout. The reusable passes `github.token` to the composite action only for its dry-run process. The actual release and badge jobs remain outside the composite and retain their existing gates. This avoids assuming that the consumer checkout contains the shared implementation and avoids a floating-ref fallback. The existing Node path retains its inline manifest/lockfile check.

Callers may also set `validate_only: true` to run setup, changelog compatibility validation, and the semantic-release dry-run without executing the release or updating a badge. Its default is `false`; regular release behavior is unchanged.

The semantic-release runtime and plugins are installed ephemerally with `--package-lock=false`. The reusable does not regenerate `package-lock.json` and does not use `npm install --package-lock-only`.

The four default plugins (`@semantic-release/commit-analyzer`, `@semantic-release/release-notes-generator`, `@semantic-release/npm`, and `@semantic-release/github`) are provided by the pinned `semantic-release` runtime and are not installed again as independent latest packages. Reinstalling a default plugin can override the version selected by semantic-release and create an incompatible plugin/dependency combination. Additional plugins declared by the release configuration and explicit `semantic_release_extra_packages` retain the existing ephemeral installation behavior.

## Changelog preset compatibility

Consumers that set `preset: conventionalcommits` in a local `.releaserc.json` must declare and lock one of the supported pairs:

| Preset | Writer |
| --- | --- |
| `conventional-changelog-conventionalcommits` 9.x | `conventional-changelog-writer` 8.x |
| `conventional-changelog-conventionalcommits` 10.x | `conventional-changelog-writer` 9.x |

The 10.x preset is the current consumer target. It uses the modern template API and fails with the writer 8 that `@semantic-release/release-notes-generator` 14 otherwise resolves. Consumers on 10.x must therefore declare `conventional-changelog-writer` 9.x directly, add an npm override for the transitive writer, and commit the resulting lockfile without a writer 8 nested under the release-notes generator. Legacy consumers on preset 9.x may continue using the generator's transitive writer 8. The reusable checks the manifest and lockfile before the dry-run and fails with an unsupported pair instead of allowing Release to fail later.

```yaml
jobs:
  release:
    uses: optimizr-tech/optimizr-actions/.github/workflows/_semantic-release.yml@v1
    with:
      runs_on: '["self-hosted", "Linux", "service"]'
      node_version: "24"
      npm_version: "12.0.2"
      releaserc_source: canonical
      actions_ref: v1
      update_release_badge: true
    secrets: inherit
```

When `releaserc_source: canonical` is selected, the workflow fetches the public
release configuration through the unauthenticated GitHub Contents API.
Normal mode uses the exact `actions_ref` input; protected-main mode uses the
verified `job.workflow_sha` for both the configuration and transformer. The
resolver does not use the caller's `GITHUB_TOKEN` or require a cross-repository
secret. An empty ref or
failed content request stops the job; it never silently falls back to a
different ref or to the local configuration. GitHub's unauthenticated REST API
quota is per originating IP; normal mode makes one content request and
protected-main mode makes two. If that quota or network access is unavailable,
the request fails closed rather than using a caller token.

## Release behavior

The workflow checks out complete history, installs caller dependencies in the default Node mode, resolves either the caller configuration or the canonical Optimizr configuration, validates the release plan, and then executes semantic-release unless `validate_only` is set. Node mode prepares its runtime in the reusable; package-less mode delegates only setup and dry-run to the internal composite action. Badge maintenance runs only after a successful release job and is suppressed in validation-only mode.

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

Invalid package mode or release directory, untrusted/incomplete workflow identity when fetching the compatibility validator, implicit plugin defaults in package-less mode, invalid npm version syntax, Node/npm installation failure, `npm ci` mismatch in Node mode, release-config resolution failure, protected-mode workflow identity failure, changelog compatibility failure, dry-run failure, or release failure blocks the job. There is no fallback to the runner-bundled npm, a mutable asset ref, or a branch-protection bypass.

### Rollback

Disable `protected_main_mode` before ruleset activation if a consumer canary reveals incompatibility, then revert the central PR or restore the previous governed Actions revision. Do not disable a live strict ruleset merely to restore automated CHANGELOG or badge commits. Consumer migrations are independently revertible until strict branch protection is applied. A rollback must not silently return to a runtime that rewrites the consumer lockfile.
