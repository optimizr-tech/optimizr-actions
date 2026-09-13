#!/usr/bin/env python3
"""Execute repository-owned validation scripts without shell interpolation."""

from __future__ import annotations

import argparse
import base64
import hashlib
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from typing import Any, Sequence

SHA_RE = re.compile(r"^[0-9a-f]{40}$")
RETRYABLE_EXIT_CODE = 75
MAX_RETRY_ATTEMPTS = 3
MAX_RETRY_BACKOFF_SECONDS = 60


class ValidationError(ValueError):
    """Raised when a repository validation contract is unsafe or invalid."""


def parse_args_json(value: str) -> list[str]:
    try:
        parsed = json.loads(value or "[]")
    except json.JSONDecodeError as exc:
        raise ValidationError(f"args_json must be valid JSON: {exc}") from exc
    if not isinstance(parsed, list) or len(parsed) > 64:
        raise ValidationError("args_json must be an array with at most 64 entries")
    result: list[str] = []
    for item in parsed:
        if not isinstance(item, str) or len(item) > 4096 or "\0" in item:
            raise ValidationError("every argument must be a bounded string without NUL bytes")
        result.append(item)
    return result


def _contains_symlink(workspace: Path, relative: Path) -> bool:
    current = workspace
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            return True
    return False


def resolve_script(workspace: Path, script_path: str) -> Path:
    workspace = workspace.resolve(strict=True)
    relative = Path(script_path)
    if not script_path or relative.is_absolute() or ".." in relative.parts:
        raise ValidationError("script_path must be a non-empty relative path inside the workspace")
    if _contains_symlink(workspace, relative):
        raise ValidationError("script_path must not contain symbolic links")
    candidate = (workspace / relative).resolve(strict=True)
    if not candidate.is_relative_to(workspace):
        raise ValidationError("script_path resolves outside the workspace")
    if not candidate.is_file():
        raise ValidationError("script_path must resolve to a regular file")
    if not os.access(candidate, os.X_OK):
        raise ValidationError("script_path must be executable")
    return candidate


def _version(argv: Sequence[str]) -> str | None:
    try:
        proc = subprocess.run(
            list(argv), check=False, capture_output=True, text=True, timeout=10
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    text = (proc.stdout or proc.stderr).strip().splitlines()
    return text[0][:300] if text else None


def collect_image_identities(image_refs: Sequence[str]) -> list[dict[str, str]]:
    identities: list[dict[str, str]] = []
    for image_ref in image_refs:
        identity = None
        for command in (
            ["docker", "image", "inspect", "--format", "{{.Id}}", image_ref],
            ["sudo", "-n", "docker", "image", "inspect", "--format", "{{.Id}}", image_ref],
        ):
            try:
                proc = subprocess.run(command, check=False, capture_output=True, text=True, timeout=15)
            except (FileNotFoundError, subprocess.TimeoutExpired):
                continue
            candidate = proc.stdout.strip()
            if proc.returncode == 0 and re.fullmatch(r"sha256:[0-9a-f]{64}", candidate):
                identity = candidate
                break
        if identity is None:
            raise ValidationError("image_refs_json contains an image without an immutable local identity")
        identities.append({
            "alias_sha256": hashlib.sha256(image_ref.encode("utf-8")).hexdigest(),
            "identity": identity,
        })
    return identities


def collect_versions() -> dict[str, str]:
    versions = {
        "python": sys.version.split()[0],
        "git": _version(["git", "--version"]) or "unavailable",
    }
    docker = _version(["docker", "--version"])
    compose = _version(["docker", "compose", "version"])
    if docker:
        versions["docker"] = docker
    if compose:
        versions["docker_compose"] = compose
    return versions


def _git_output(
    workspace: Path,
    *arguments: str,
    env: dict[str, str] | None = None,
) -> str:
    run_kwargs: dict[str, Any] = {
        "cwd": workspace,
        "check": False,
        "capture_output": True,
        "text": True,
        "timeout": 15,
    }
    if env is not None:
        run_kwargs["env"] = env
    try:
        completed = subprocess.run(["git", *arguments], **run_kwargs)
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        raise ValidationError(
            f"checkout integrity could not execute git {arguments[0]}"
        ) from exc
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "").strip()
        raise ValidationError(
            f"checkout integrity git {' '.join(arguments)} failed"
            + (f": {detail[:300]}" if detail else "")
        )
    return (completed.stdout or "").strip()


def _workspace_failure(workspace: Path, reason: str) -> ValidationError:
    runner = os.environ.get("RUNNER_NAME", "unknown")
    return ValidationError(
        "checkout integrity failed "
        f"(runner={runner}, workspace={workspace}): {reason}"
    )


def _validate_workspace_inputs(
    expected_sha: str,
    required_paths: Sequence[str],
) -> None:
    if not SHA_RE.fullmatch(expected_sha):
        raise ValidationError("expected_sha must be a lowercase 40-character commit SHA")
    if len(required_paths) > 64:
        raise ValidationError("required_paths must contain at most 64 entries")
    if any(not isinstance(path, str) or len(path) > 4096 for path in required_paths):
        raise ValidationError("required_paths entries must be bounded strings")


def _workspace_context(workspace: Path, expected_sha: str) -> tuple[Path, str]:
    try:
        resolved_workspace = workspace.resolve(strict=True)
    except OSError as exc:
        raise _workspace_failure(workspace, "workspace does not exist") from exc
    if not resolved_workspace.is_dir():
        raise _workspace_failure(resolved_workspace, "workspace is not a directory")

    actual_sha = _git_output(resolved_workspace, "rev-parse", "HEAD")
    if actual_sha != expected_sha:
        raise _workspace_failure(
            resolved_workspace,
            f"HEAD {actual_sha or '<empty>'} does not match expected SHA {expected_sha}",
        )

    git_root_text = _git_output(resolved_workspace, "rev-parse", "--show-toplevel")
    try:
        git_root = Path(git_root_text).resolve(strict=True)
    except OSError as exc:
        raise _workspace_failure(resolved_workspace, "git root is not materialized") from exc
    if git_root != resolved_workspace:
        raise _workspace_failure(
            resolved_workspace,
            f"git root is {git_root}, not the requested workspace",
        )

    status = _git_output(
        resolved_workspace,
        "status",
        "--porcelain",
        "--untracked-files=all",
    )
    if status:
        raise _workspace_failure(resolved_workspace, "checkout is not clean")
    return resolved_workspace, actual_sha


def _required_paths(
    workspace: Path,
    required_paths: Sequence[str],
    *,
    allow_missing: bool = False,
) -> tuple[list[str], list[str]]:
    normalized_paths: list[str] = []
    missing_paths: list[str] = []
    for path in required_paths:
        relative = Path(path)
        if (
            not path
            or relative.is_absolute()
            or ".." in relative.parts
            or _contains_symlink(workspace, relative)
        ):
            raise _workspace_failure(
                workspace,
                f"required checkout path is unsafe: {path or '<empty>'}",
            )
        candidate = (workspace / relative).resolve(strict=False)
        if not candidate.is_relative_to(workspace):
            raise _workspace_failure(
                workspace,
                f"required checkout path escapes workspace: {path}",
            )
        if not candidate.exists():
            if not allow_missing:
                raise _workspace_failure(
                    workspace,
                    f"required checkout path is missing: {path}",
                )
            missing_paths.append(path)
        normalized_paths.append(path)
    return normalized_paths, missing_paths


def verify_workspace(
    *,
    workspace: Path,
    expected_sha: str,
    required_paths: Sequence[str] = (),
) -> dict[str, Any]:
    """Verify that checkout materialized the expected clean repository tree."""
    _validate_workspace_inputs(expected_sha, required_paths)
    resolved_workspace, actual_sha = _workspace_context(workspace, expected_sha)
    normalized_paths, _ = _required_paths(resolved_workspace, required_paths)

    return {
        "status": "passed",
        "expected_sha": expected_sha,
        "actual_sha": actual_sha,
        "workspace": str(resolved_workspace),
        "runner": os.environ.get("RUNNER_NAME", "unknown"),
        "required_paths": normalized_paths,
    }


def repair_workspace(
    *,
    workspace: Path,
    expected_sha: str,
    required_paths: Sequence[str] = (),
    github_token: str = "",
) -> dict[str, Any]:
    """Materialize missing tracked files in an already trusted clean worktree."""
    _validate_workspace_inputs(expected_sha, required_paths)
    resolved_workspace, _ = _workspace_context(workspace, expected_sha)
    _, missing_paths = _required_paths(
        resolved_workspace,
        required_paths,
        allow_missing=True,
    )
    if not missing_paths:
        raise _workspace_failure(
            resolved_workspace,
            "repair requires at least one missing required checkout path",
        )
    if not github_token:
        raise _workspace_failure(
            resolved_workspace,
            "repair requires a GitHub token before fetching missing objects",
        )
    git_env = _ephemeral_git_auth_env(github_token)

    # These commands only materialize tracked files after the SHA, Git root and
    # clean-worktree checks above have passed. They do not delete untracked data
    # or change HEAD; a failed repair remains a closed validation failure.
    _git_output(
        resolved_workspace,
        "sparse-checkout",
        "disable",
        env=git_env,
    )
    _git_output(
        resolved_workspace,
        "checkout",
        "--force",
        expected_sha,
        "--",
        ".",
        env=git_env,
    )
    result = verify_workspace(
        workspace=resolved_workspace,
        expected_sha=expected_sha,
        required_paths=required_paths,
    )
    result["repair"] = "applied"
    result["repaired_paths"] = missing_paths
    return result


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def _failure_kind(exit_code: int, timed_out: bool) -> str:
    if exit_code == 0:
        return "none"
    if timed_out:
        return "timeout"
    if exit_code == RETRYABLE_EXIT_CODE:
        return "retryable_dependency"
    return "command_failed"


def run_validation(
    *,
    workspace: Path,
    script_path: str,
    args: Sequence[str],
    evidence_path: Path,
    repository: str,
    head_sha: str,
    base_sha: str,
    timeout_seconds: int,
    image_refs: Sequence[str] = (),
    retry_attempts: int = 1,
    retry_backoff_seconds: int = 5,
) -> int:
    if not SHA_RE.fullmatch(head_sha):
        raise ValidationError("head_sha must be a lowercase 40-character commit SHA")
    if base_sha and not SHA_RE.fullmatch(base_sha):
        raise ValidationError("base_sha must be empty or a lowercase 40-character commit SHA")
    if timeout_seconds < 1 or timeout_seconds > 3600:
        raise ValidationError("timeout_seconds must be between 1 and 3600")
    if retry_attempts < 1 or retry_attempts > MAX_RETRY_ATTEMPTS:
        raise ValidationError(
            f"retry_attempts must be between 1 and {MAX_RETRY_ATTEMPTS}"
        )
    if retry_backoff_seconds < 0 or retry_backoff_seconds > MAX_RETRY_BACKOFF_SECONDS:
        raise ValidationError(
            "retry_backoff_seconds must be between 0 and "
            f"{MAX_RETRY_BACKOFF_SECONDS}"
        )
    script = resolve_script(workspace, script_path)
    started = time.monotonic()
    exit_code = 1
    timed_out = False
    attempts: list[dict[str, Any]] = []
    for attempt_number in range(1, retry_attempts + 1):
        attempt_started = time.monotonic()
        timed_out = False
        try:
            completed = subprocess.run(
                [str(script), *args],
                cwd=workspace,
                check=False,
                timeout=timeout_seconds,
            )
            exit_code = completed.returncode
        except subprocess.TimeoutExpired:
            timed_out = True
            exit_code = 124
        attempts.append(
            {
                "attempt": attempt_number,
                "exit_code": exit_code,
                "timed_out": timed_out,
                "duration_ms": int((time.monotonic() - attempt_started) * 1000),
                "failure_kind": _failure_kind(exit_code, timed_out),
            }
        )
        if exit_code != RETRYABLE_EXIT_CODE or attempt_number == retry_attempts:
            break
        delay_seconds = retry_backoff_seconds * attempt_number
        print(
            "repository validation returned the reserved transient dependency "
            f"status; retrying in {delay_seconds}s "
            f"(attempt {attempt_number + 1}/{retry_attempts})",
            file=sys.stderr,
        )
        time.sleep(delay_seconds)
    duration_ms = int((time.monotonic() - started) * 1000)
    failure_kind = _failure_kind(exit_code, timed_out)
    payload = {
        "schema_version": 1,
        "repository": repository,
        "head_sha": head_sha,
        "base_sha": base_sha or None,
        "command": {
            "executable": script_path,
            "argument_count": len(args),
            "argument_sha256": [hashlib.sha256(item.encode("utf-8")).hexdigest() for item in args],
            "shell": False,
        },
        "images": collect_image_identities(image_refs),
        "tools": collect_versions(),
        "result": {
            "exit_code": exit_code,
            "timed_out": timed_out,
            "duration_ms": duration_ms,
            "status": "passed" if exit_code == 0 else "failed",
            "failure_kind": failure_kind,
            "attempt_count": len(attempts),
            "attempts": attempts,
            "retry_attempts": retry_attempts,
            "retryable_exit_code": RETRYABLE_EXIT_CODE,
            "retry_exhausted": exit_code == RETRYABLE_EXIT_CODE,
        },
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }
    _write_json(evidence_path, payload)
    return exit_code


def _ephemeral_git_auth_env(github_token: str) -> dict[str, str]:
    """Return a subprocess-only Git config that authenticates without persistence."""
    if (
        not isinstance(github_token, str)
        or not github_token.strip()
        or len(github_token) > 4096
        or any(character.isspace() or ord(character) < 32 for character in github_token)
    ):
        raise ValidationError(
            "github_token must be a non-empty bounded value without whitespace or control characters"
        )
    env = os.environ.copy()
    env.pop("VALIDATION_GITHUB_TOKEN", None)
    env.pop("GITHUB_TOKEN", None)
    try:
        config_index = int(env.get("GIT_CONFIG_COUNT", "0"))
    except ValueError as exc:
        raise ValidationError("GIT_CONFIG_COUNT must be an integer") from exc
    if config_index < 0 or config_index > 64:
        raise ValidationError("GIT_CONFIG_COUNT is outside the supported range")

    basic_credential = base64.b64encode(
        f"x-access-token:{github_token}".encode("utf-8")
    ).decode("ascii")
    env["GIT_CONFIG_COUNT"] = str(config_index + 1)
    env[f"GIT_CONFIG_KEY_{config_index}"] = "http.https://github.com/.extraheader"
    env[f"GIT_CONFIG_VALUE_{config_index}"] = f"AUTHORIZATION: basic {basic_credential}"
    return env


def verify_trusted_candidate(
    workspace: Path,
    candidate_sha: str,
    trusted_ref: str,
    *,
    github_token: str = "",
) -> None:
    if not SHA_RE.fullmatch(candidate_sha):
        raise ValidationError("candidate_sha must be a lowercase 40-character commit SHA")
    if not trusted_ref.startswith("refs/heads/"):
        raise ValidationError("trusted_ref must be a full branch ref")
    remote_ref = "origin/" + trusted_ref.removeprefix("refs/heads/")
    fetch_kwargs: dict[str, Any] = {"cwd": workspace, "check": True}
    if github_token:
        fetch_kwargs["env"] = _ephemeral_git_auth_env(github_token)
    subprocess.run(
        ["git", "fetch", "--no-tags", "origin", trusted_ref],
        **fetch_kwargs,
    )
    result = subprocess.run(
        ["git", "merge-base", "--is-ancestor", candidate_sha, remote_ref],
        cwd=workspace,
        check=False,
    )
    if result.returncode != 0:
        raise ValidationError(f"candidate {candidate_sha} is not reachable from {trusted_ref}")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run")
    run.add_argument("--workspace", required=True)
    run.add_argument("--script-path", required=True)
    run.add_argument("--args-json", default="[]")
    run.add_argument("--evidence", required=True)
    run.add_argument("--repository", required=True)
    run.add_argument("--head-sha", required=True)
    run.add_argument("--base-sha", default="")
    run.add_argument("--timeout-seconds", type=int, default=900)
    run.add_argument("--retry-attempts", type=int, default=1)
    run.add_argument("--retry-backoff-seconds", type=int, default=5)
    run.add_argument("--image-refs-json", default="[]")
    trust = sub.add_parser("check-trust")
    trust.add_argument("--workspace", required=True)
    trust.add_argument("--candidate-sha", required=True)
    trust.add_argument("--trusted-ref", default="refs/heads/main")
    check_workspace = sub.add_parser("check-workspace")
    check_workspace.add_argument("--workspace", required=True)
    check_workspace.add_argument("--expected-sha", required=True)
    check_workspace.add_argument("--required-path", action="append", default=[])
    check_workspace.add_argument("--required-paths-json", default="[]")
    repair_workspace_parser = sub.add_parser("repair-workspace")
    repair_workspace_parser.add_argument("--workspace", required=True)
    repair_workspace_parser.add_argument("--expected-sha", required=True)
    repair_workspace_parser.add_argument("--required-path", action="append", default=[])
    repair_workspace_parser.add_argument("--required-paths-json", default="[]")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "check-trust":
            verify_trusted_candidate(
                Path(args.workspace),
                args.candidate_sha,
                args.trusted_ref,
                github_token=os.environ.get("VALIDATION_GITHUB_TOKEN", ""),
            )
            return 0
        if args.command == "check-workspace":
            print(
                json.dumps(
                    verify_workspace(
                        workspace=Path(args.workspace),
                        expected_sha=args.expected_sha,
                        required_paths=[
                            *args.required_path,
                            *parse_args_json(args.required_paths_json),
                        ],
                    ),
                    sort_keys=True,
                )
            )
            return 0
        if args.command == "repair-workspace":
            print(
                json.dumps(
                    repair_workspace(
                        workspace=Path(args.workspace),
                        expected_sha=args.expected_sha,
                        required_paths=[
                            *args.required_path,
                            *parse_args_json(args.required_paths_json),
                        ],
                        github_token=os.environ.get("VALIDATION_GITHUB_TOKEN", ""),
                    ),
                    sort_keys=True,
                )
            )
            return 0
        status = run_validation(
            workspace=Path(args.workspace),
            script_path=args.script_path,
            args=parse_args_json(args.args_json),
            evidence_path=Path(args.evidence),
            repository=args.repository,
            head_sha=args.head_sha,
            base_sha=args.base_sha,
            timeout_seconds=args.timeout_seconds,
            image_refs=parse_args_json(args.image_refs_json),
            retry_attempts=args.retry_attempts,
            retry_backoff_seconds=args.retry_backoff_seconds,
        )
        return status
    except (ValidationError, OSError, subprocess.CalledProcessError) as exc:
        print(f"repository validation error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
