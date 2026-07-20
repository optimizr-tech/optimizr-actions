# Release badge recovery

`_semantic-release.yml` remains the primary badge update path. `_release-badge-recovery.yml` is a serialized fallback for a consumer `release` event or reviewed `workflow_dispatch`.

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

Rollback by restoring the previous small caller, not by duplicating badge rendering logic.
