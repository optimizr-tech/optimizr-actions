# Release badge recovery

`_semantic-release.yml` remains the primary badge update path. The badge-recovery reusable workflow is a serialized fallback for a consumer `release` event or reviewed `workflow_dispatch`.

## Version compatibility and runner selection

`_release-badge-recovery.yml@v1` is retained unchanged for existing callers. Its optional `runner_json` input and default are legacy behavior; do not change that default under `v1`. New callers that remain on `v1` can pass a JSON `runs-on` object with both a runner group and label: GitHub's [`fromJSON` expression](https://docs.github.com/en/actions/reference/workflows-and-actions/expressions#functions) can evaluate JSON objects. For example:

```yaml
runner_json: '{"group":"<authorized-runner-group>","labels":"<label-in-that-group>"}'
```

For a future `@v2` release, `_release-badge-recovery-v2.yml` requires `runner_group` and `runner_label`; it has no implicit runner default and routes using both fields:

```yaml
jobs:
  recover:
    uses: optimizr-tech/optimizr-actions/.github/workflows/_release-badge-recovery-v2.yml@v2
    with:
      runner_group: "<group-authorized-for-this-repository>"
      runner_label: "<label-present-in-that-group>"
      tag: ${{ inputs.tag || github.event.release.tag_name }}
```

Replace both placeholders with values confirmed by the organization/repository runner administrators before adopting the reusable. GitHub documents that a runner must satisfy both the group and label selectors ([runner selection](https://docs.github.com/en/actions/how-tos/write-workflows/choose-where-workflows-run/choose-the-runner-for-a-job)). Runner-group membership and repository access define the pool boundary; labels alone do not prove isolation. The `@v2` reference is illustrative until a reviewed release publishes that major tag.

Consumer migration is separate work owned by each repository. Do not dispatch badge recovery or change a caller to a runner group until its repository is authorized for that group and the group membership has been reviewed.

## Existing `v1` example

The following remains a compatible call shape for current `@v1` consumers:

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
      runner_json: '{"group":"<authorized-runner-group>","labels":"<label-in-that-group>"}'
```

The reusable validates the branch and badge path, requires a `v`-prefixed semantic version, or selects the latest valid repository tag. Stable concurrency prevents two recovery commits from racing. The underlying composite skips no-op commits and rebases before push.

Rollback a future consumer migration by restoring its previous workflow reference and runner inputs; keep the badge rendering logic centralized.
