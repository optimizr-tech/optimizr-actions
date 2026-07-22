# Dependabot security auto-merge

Optimizr repositories may use the reusable `_dependabot-security-automerge.yml` workflow to enable GitHub native auto-merge for verified Dependabot pull requests.

## Policy

- Patch updates are eligible by default.
- Minor updates are eligible only when the caller explicitly sets `allow_minor: true`.
- Major updates are never enabled automatically.
- The workflow enables auto-merge; it does not bypass required checks, reviews or branch protection.
- It does not approve pull requests.
- It does not check out or execute candidate pull-request code.
- It receives no production or deployment secrets.

The workflow uses the pinned `dependabot/fetch-metadata` action to verify Dependabot authorship and update type, then runs the fixed command `gh pr merge --auto --squash`.

## Consumer caller

Copy `templates/workflows/dependabot-security-automerge.yml` into the consumer repository as `.github/workflows/dependabot-security-automerge.yml`:

```yaml
name: Dependabot security auto-merge

on:
  pull_request_target:
    types: [opened, synchronize, reopened]

permissions:
  contents: write
  pull-requests: write

jobs:
  automerge:
    uses: optimizr-tech/optimizr-actions/.github/workflows/_dependabot-security-automerge.yml@v1
    with:
      allow_minor: false
```

`pull_request_target` is used only for base-branch automation that needs the write token. The reusable never checks out the pull-request branch, evaluates repository-provided commands, runs on self-hosted infrastructure or inherits secrets.

## Required repository settings

Before adoption:

1. Enable Dependabot alerts and security updates.
2. Add `.github/dependabot.yml` for every supported package ecosystem when organization-controlled schedules, grouping or labels are required.
3. Enable GitHub auto-merge.
4. Protect the deployment branch and require the repository's CI and security checks before merge.
5. Keep deployment workflows triggered by the protected branch rather than by the Dependabot PR itself.

A repository using a merge queue requires a separately reviewed token strategy. The first release intentionally uses only the built-in token and does not introduce a custom GitHub App.

## Security-update scope

Dependabot security updates are the primary remediation path when Trivy identifies a fix that requires changing a manifest, lockfile, Dockerfile or GitHub Actions reference. The reusable determines eligibility from verified Dependabot metadata and semantic update level. It does not inspect vulnerability descriptions or accept CVE data as shell input.

Repositories that also enable Dependabot version updates may therefore auto-merge eligible patch updates under the same protected checks. Set `allow_minor: false` unless the repository has sufficient compatibility tests for minor updates.

## Failure behavior

If metadata verification fails, the update type is not eligible, auto-merge is disabled, or required checks fail, the pull request remains open. No deployment is triggered and no exception is created automatically.

## Rollback

Remove or disable the consumer caller. Dependabot continues to open update pull requests, while merges return to manual review. Security detection and deploy gates remain enabled independently.
