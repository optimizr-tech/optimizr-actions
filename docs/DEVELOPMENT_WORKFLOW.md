# Development workflow

This repository is the source of truth for reusable automation contracts. A
change should be developed from the current remote `main`, validated locally,
reviewed as a small PR and only then released through the compatibility `v1`
tag.

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

## Validate before requesting review

Run the canonical local validation entrypoint:

```powershell
python -m scripts.dev.preflight validate
```

It performs the preflight and then runs, in order:

1. `python -m unittest discover -v`;
2. `python -m compileall -q scripts tests`;
3. `git diff --check` for unstaged changes;
4. `git diff --cached --check` for staged changes;
5. `git diff --check origin/main HEAD` for committed branch changes.

The complete command requires Python, Git, Docker and the Docker Compose CLI
plugin. If a tool is unavailable, the command stops before the suite and
reports the missing prerequisite. This is an environmental blocker, not a
passing validation result.

Focused tests remain appropriate during development:

```powershell
python -m unittest tests.test_<contract> -v
```

The hosted `Validate pull request` workflow remains the authoritative Linux
check. Local Windows results must keep platform limitations visible, especially
for symlink, Unix-mode and Docker tests.

## PR and release checkpoints

Every behavior change should include a meaningful regression test, contract
documentation, affected-consumer inventory and rollback guidance. Generated
catalogs must be regenerated and checked before the PR is opened. After merge,
confirm the release validation and `v1` SHA before adapting consumers; use one
non-legacy consumer as a canary before broader adoption.
