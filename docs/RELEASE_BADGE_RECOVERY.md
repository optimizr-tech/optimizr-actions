# Release badge recovery

`_semantic-release.yml` remains the primary badge update path. `_release-badge-recovery.yml@v1` is a serialized fallback for a consumer `release` event or reviewed `workflow_dispatch`.

## Runner default and consumer migration

The optional `runner_json` input defaults to the `local-docker` group and the `self-hosted`, `Linux`, `X64`, and `local-docker` labels. Both the group and labels must match, so a runner outside the authorized `local-docker` group cannot match merely because it shares the label. InfraOps must keep production runners outside that group. This default is the Optimizr organization convention; callers in another organization must pass their own authorized group and labels.

This changes the default of the existing `@v1` contract. A caller that explicitly passes `runner_json` keeps its existing selection; the owning repository must remove that override to adopt the default. A caller that omits the input will select the `local-docker` group when it starts using the updated `@v1` tag. Do not advance the floating tag until the change is reviewed, all repository-runner checks pass, and InfraOps confirms the affected repositories are authorized for this group.

Before removing an override, the consumer owner and runner administrator must confirm repository authorization for the group and availability of a matching runner. Group membership and repository authorization limit the runner pool; labels are selection criteria, not an access-control boundary. If a different group-scoped runner is needed, `runner_json` accepts a JSON `runs-on` object, for example:

```yaml
runner_json: '{"group":"<authorized-runner-group>","labels":["self-hosted","Linux","X64","<runner-label>"]}'
```

The runner administrator must keep production credentials and deployment capabilities off the local build runner. Do not dispatch this workflow for untrusted pull-request code.

## Example using the default

```yaml
name: Recover release badge
on:
  release:
    types: [published, edited]
  workflow_dispatch:
    inputs:
      tag:
        required: false
        type: string
permissions:
  contents: write
jobs:
  badge:
    uses: optimizr-tech/optimizr-actions/.github/workflows/_release-badge-recovery.yml@v1
    with:
      tag: ${{ inputs.tag || github.event.release.tag_name }}
```

The reusable validates the branch and badge path, requires a `v`-prefixed semantic version, or selects the latest valid repository tag. Stable concurrency prevents two recovery commits from racing. The underlying composite skips no-op commits and rebases before push.

Rollback a consumer migration by restoring its previous explicit `runner_json`; keep badge rendering centralized.
