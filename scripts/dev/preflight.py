"""Check a development checkout and run the canonical local validation suite."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Mapping, Sequence


@dataclass(frozen=True)
class CheckResult:
    name: str
    ok: bool
    detail: str


@dataclass(frozen=True)
class GitState:
    branch: str
    base_ref: str
    ahead: int
    behind: int
    dirty: bool


def validate_git_state(
    state: GitState,
    *,
    protected_branches: Sequence[str] = ("main", "master"),
) -> CheckResult:
    if not state.branch:
        return CheckResult(
            "git branch",
            False,
            "detached HEAD; create a feature branch before making changes",
        )
    if state.branch.lower() in {branch.lower() for branch in protected_branches}:
        return CheckResult(
            "git branch",
            False,
            f"protected branch '{state.branch}'; create a feature branch",
        )
    if state.behind:
        return CheckResult(
            "git baseline",
            False,
            f"{state.branch} is {state.behind} commit(s) behind {state.base_ref}; "
            f"run 'git fetch origin main' and rebase before continuing",
        )
    dirty = "dirty worktree is allowed during development" if state.dirty else "clean worktree"
    return CheckResult(
        "git baseline",
        True,
        f"{state.branch} is {state.ahead} commit(s) ahead of {state.base_ref}; {dirty}",
    )


def validate_tools(
    available: Mapping[str, bool],
    *,
    required: Sequence[str],
) -> CheckResult:
    missing = [tool for tool in required if not available.get(tool, False)]
    if missing:
        return CheckResult(
            "required tools",
            False,
            "unavailable: " + ", ".join(missing),
        )
    return CheckResult("required tools", True, "available: " + ", ".join(required))


def validation_commands(*, python_executable: str, base_ref: str) -> list[list[str]]:
    return [
        [python_executable, "-m", "unittest", "discover", "-v"],
        [python_executable, "-m", "compileall", "-q", "scripts", "tests"],
        ["git", "diff", "--check"],
        ["git", "diff", "--cached", "--check"],
        ["git", "diff", "--check", base_ref, "HEAD"],
    ]


def _run(
    workspace: Path,
    command: Sequence[str],
    *,
    capture_output: bool = True,
    timeout: float | None = 15,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(command),
        cwd=workspace,
        check=False,
        capture_output=capture_output,
        text=True,
        timeout=timeout,
    )


def _git_output(workspace: Path, *arguments: str) -> str:
    try:
        result = _run(workspace, ["git", *arguments])
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"git {' '.join(arguments)} timed out") from exc
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise RuntimeError(f"git {' '.join(arguments)} failed: {detail}")
    return result.stdout.strip()


def read_git_state(workspace: Path, base_ref: str) -> GitState:
    branch = _git_output(workspace, "branch", "--show-current")
    dirty = bool(_git_output(workspace, "status", "--porcelain", "--untracked-files=all"))
    divergence = _git_output(workspace, "rev-list", "--left-right", "--count", f"{base_ref}...HEAD")
    values = divergence.split()
    if len(values) != 2 or not all(value.isdigit() for value in values):
        raise RuntimeError(f"could not parse divergence from {base_ref}: {divergence!r}")
    behind, ahead = (int(value) for value in values)
    return GitState(
        branch=branch,
        base_ref=base_ref,
        ahead=ahead,
        behind=behind,
        dirty=dirty,
    )


def _tool_available(tool: str) -> bool:
    if tool == "python":
        return True
    if tool == "docker-compose":
        if shutil.which("docker") is None:
            return False
        try:
            result = subprocess.run(
                ["docker", "compose", "version"],
                capture_output=True,
                text=True,
                check=False,
                timeout=15,
            )
        except (OSError, subprocess.TimeoutExpired):
            return False
        return result.returncode == 0
    return shutil.which(tool) is not None


def _print_result(result: CheckResult) -> None:
    status = "PASS" if result.ok else "FAIL"
    print(f"[{status}] {result.name}: {result.detail}")


def run_preflight(workspace: Path, *, base_ref: str, require_runtime_tools: bool) -> int:
    results: list[CheckResult] = []
    try:
        state = read_git_state(workspace, base_ref)
        results.append(validate_git_state(state))
    except (OSError, RuntimeError) as exc:
        results.append(CheckResult("git baseline", False, str(exc)))

    required = ("python", "git")
    if require_runtime_tools:
        required += ("docker", "docker-compose")
    available = {tool: _tool_available(tool) for tool in required}
    results.append(validate_tools(available, required=required))

    for result in results:
        _print_result(result)
    return 0 if all(result.ok for result in results) else 2


def run_validation(workspace: Path, *, base_ref: str) -> int:
    preflight_status = run_preflight(
        workspace,
        base_ref=base_ref,
        require_runtime_tools=True,
    )
    if preflight_status:
        return preflight_status

    status = 0
    for command in validation_commands(python_executable=sys.executable, base_ref=base_ref):
        print(f"\n$ {' '.join(command)}")
        result = _run(workspace, command, capture_output=False, timeout=None)
        status = status or result.returncode
    return status


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", nargs="?", choices=("check", "validate"), default="check")
    parser.add_argument("--workspace", type=Path, default=Path.cwd())
    parser.add_argument("--base-ref", default="origin/main")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    workspace = args.workspace.resolve(strict=True)
    if args.command == "validate":
        return run_validation(workspace, base_ref=args.base_ref)
    return run_preflight(workspace, base_ref=args.base_ref, require_runtime_tools=False)


if __name__ == "__main__":
    raise SystemExit(main())
