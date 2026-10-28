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

`pull_request_target` is used only for base-branch automation that needs the write token. The reusable never checks out the pull-request branch, evaluates repository-provided commands or inherits secrets.

## Runner selection and compatibility

| Input | Default | Meaning |
| --- | --- | --- |
| `runner_json` | `["ubuntu-latest"]` | Compatibility default; explicit self-hosted selection requires a JSON object containing exactly `group` and a string-array `labels` |
| `self_hosted_mode` | `none` | Hosted compatibility mode; use `metadata-pr` for self-hosted API-only automation |
| `allow_minor` | `false` | Existing update eligibility policy, unchanged |

Existing `v1` callers retain their hosted default. This additive contract does
not establish an organization-wide ban on hosted execution. A consumer owner
must opt in after the runner administrator approves the group:

```yaml
    with:
      runner_json: '{"group":"<authorized-metadata-group>","labels":["self-hosted","Linux","<metadata-label>"]}'
      self_hosted_mode: metadata-pr
      allow_minor: false
```

The self-hosted path accepts only `pull_request_target`; a candidate-controlled
`pull_request` caller must not route this privileged job to a persistent runner.
The first step rejects malformed selectors, missing group/Linux/self-hosted
labels, unsupported modes and events before fetching metadata. JSON parsing
and runner scheduling precede that step, so this guard is not an admission
fence. Both group and labels must match; labels alone do not provide access
control. See [GitHub runner selection](https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#jobsjob_idruns-on)
and [privileged event security](https://docs.github.com/en/actions/reference/security/secure-use).

Administrative approval belongs to the runner owner. Restrict repository access
and approved workflow/ref access to this specific reusable, verify the group
contains no production runner, and provision Bash, Python 3, GitHub CLI and an
Actions runner supporting the pinned Node 24 action. Do not widen a metadata
group's allowlist automatically: this workflow has `contents: write` and
`pull-requests: write`, unlike read-only PR metadata validation. It receives
the scoped built-in token and no inherited production/deployment secrets.
Protect the base workflow and maintain branch rules requiring checks/reviews.

This is auto-merge metadata automation, not the dynamic Dependabot updater.
It grants no permission to execute dependency install hooks or PR code on
`local-docker`. A dedicated isolated ephemeral pool remains necessary for
self-hosted updater execution where GitHub supports it; changing this caller
does not change Dependabot updater settings or preserve alerts by itself.
Without an approved matching group, keep this caller disabled and merge
manually; do not fall back to hosted or a production runner under a no-hosted
policy. Vulnerability alerts are managed independently and must stay enabled.

Known consumer inventory for review: InfraOps, Serve, Keycloak and Certbot call
this reusable at `v1`; the Fiscal audit found no caller. Each owner must review
the published revision and opt in separately. No group, label, setting, caller,
floating tag or enabled auto-merge request is changed by this source patch.

## Required repository settings

Before adoption:

1. Keep Dependabot alerts enabled. Enable security updates only after the updater execution path is approved under the repository's runner policy.
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

For a no-hosted consumer, rollback means disabling the caller or reverting to
its previously approved self-hosted revision; removing the new inputs would
restore hosted execution and violates that policy. Disabling the workflow does
not revoke auto-merge requests already enabled on open PRs: inspect those PRs
and have the repository owner disable auto-merge individually when required.
Source rollback does not install runner changes or alter updater settings.
