# Development workflow

This repository is the source of truth for reusable automation contracts. A
change should be developed from the current remote `main`, reviewed as a small
PR, validated by the hosted repository workflows and only then released
through the compatibility `v1` tag.

## Start from a current isolated checkout

Do not develop directly on `main` or on a stale local branch:

```powershell
git fetch origin main --prune
git worktree add .worktrees/<name> -b codex/<name> origin/main
Set-Location .worktrees/<name>
python -m scripts.dev.preflight
```

The preflight command is read-only. It rejects a protected branch, a detached
HEAD and a branch behind `origin/main`. It does not fetch, rebase, clean files
or change tags. A dirty worktree is reported but allowed while work is in
progress.

## Validation and release gate

The local preflight is available for contributors who want fast feedback:

```powershell
python -m scripts.dev.preflight validate
```

It performs the preflight and then runs, in order:

1. `python -m unittest discover -v`;
2. `python -m compileall -q scripts tests`;
3. `git diff --check` for unstaged changes;
4. `git diff --cached --check` for staged changes;
5. `git diff --check origin/main HEAD` for committed branch changes.

The complete local command requires Python, Git, Docker and the Docker Compose
CLI plugin. If a tool is unavailable, the command stops before the suite and
reports the missing prerequisite. This is an environmental blocker, not a
passing validation result. Hosted workflow results remain the release evidence.

Focused tests remain appropriate during development:

```powershell
python -m unittest tests.test_<contract> -v
```

`Validate pull request` runs two checks. Read-only PR metadata validation
runs through the published `_pr-metadata.yml@refs/tags/v1` contract on the
restricted owner self-hosted runner group (`local-docker-owner`), which admits
only that definition and this repository's trusted-main definition; the job
stays API-only and never checks out candidate code. The candidate's full
portable-contract suite, actionlint and composite-action metadata validation
run on `ubuntu-latest` with read-only permissions and persisted checkout
credentials disabled, on an isolated, disposable hosted runner, never on the
persistent self-hosted pool. This preserves pre-merge candidate evidence
without exposing that pool to public fork code.

After a human-reviewed merge, `Validate and move v1 compatibility tag` checks
the exact trusted `main` revision on the restricted owner self-hosted runner
(`local-docker-owner` group). The catalog, full Python contract suite,
actionlint, YAML metadata and revision/diff checks must all succeed before
`v1` can move. Only `main` push/dispatch and the existing merged-PR recovery
path are accepted. Local Windows results must keep platform limitations
visible, especially for symlink, Unix-mode and Docker tests.

The trusted-main job provisions Python 3.14 and installs the pinned
`requirements-ci.txt` dependencies in a run/attempt-specific virtualenv under
`runner.temp`. It does not depend on packages installed in the runner's system
Python or modify the system environment.

This owner-repository route depends on the InfraOps-authorized restricted
runner group (`local-docker-owner`): the public repository is allowed, only the
two approved workflow definitions can use its single-job runner, and the shared
consumer pool (`local-docker`) is not reachable from this repository. Other
repositories may use self-hosted runners under their own trust and operational
contracts; this change does not alter those consumer workflows. InfraOps issues
#160 and #480 remain owned by InfraOps and must be reconciled by that
repository's owner with this public-repository policy. Any branch protection
rule must use the metadata check for PRs and retain full trusted-main
validation as a prerequisite to publishing `v1`.

## Owner runner prerequisites

The restricted owner runner (`wsl-ci-2`, group `local-docker-owner`) is a
persistent self-hosted Linux runner. The owner workflows rely on these tools
being present in the runner distro, pinned and provisioned by InfraOps (role
`persistent_runner` in `optimizr-infra-ops`):

- `git`, `bash` and `python3` for the trusted-event guard and scope steps;
- Docker (daemon reachable at the runner's default socket) for the actionlint
  and composite-metadata container steps - both run as the runner user
  (`--user "$(id -u):$(id -g)"`) because the 0700 checkout is not readable by
  container root through the Docker Desktop mount;
- `gh` CLI (pinned as `runner_gh_version` in InfraOps `dev_wsl.yml`, installed
  from the official release package with a reviewed checksum) for the `gh api`
  calls in the scope and tag-move steps;
- `uv` is provisioned per job by `astral-sh/setup-uv`; no system Python
  packages are installed by the workflows.

If a prerequisite is missing the run fails closed - there is no hosted
fallback. The 2026-10-06 incidents failed with `gh: command not found` and a
container permission error until InfraOps fixed the environment; see
optimizr-infra-ops#480 for the trust-boundary and runner inventory.

## PR and release checkpoints

Every behavior change should include a meaningful regression test, contract
documentation, affected-consumer inventory and rollback guidance. Generated
catalogs must be regenerated and checked before the PR is opened. After merge,
confirm the release validation and `v1` SHA before adapting consumers; use one
non-legacy consumer as a canary before broader adoption.

## pnpm isolation on persistent runners

Every pnpm action bootstrap uses an explicit destination under `runner.temp`,
identified by workflow run, attempt and job. No portable workflow installs the
executable in the shared `~/setup-pnpm` home. Matrix jobs execute exclusively
on each runner; separate runners must have distinct temporary directories.

The quality-gate collectors also create a matrix-indexed package store and
export `PNPM_CONFIG_STORE_DIR` through `GITHUB_ENV` before pnpm installation.
Bootstrap, dependency installation, `dlx` and setup-node cache discovery inherit
the same value. The store is initialized at step scope because `runner` is not
available in job-level `env` expressions; see the [GitHub context availability
reference](https://docs.github.com/en/actions/reference/workflows-and-actions/contexts#context-availability).
Node/pnpm versions, caller inputs, report semantics and trust gates are unchanged.
Repository validation uses the same step-scoped export for its non-matrix
package store, so repository-owned frontend installs inherit isolation too.
Rollback is a reviewed revert and normal validated `v1` publication; never delete
persistent host caches to hide a bootstrap regression.
