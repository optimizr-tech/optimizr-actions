#!/usr/bin/env python3
"""Execute repository-owned validation scripts without shell interpolation."""

from __future__ import annotations

import argparse
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


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


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
) -> int:
    if not SHA_RE.fullmatch(head_sha):
        raise ValidationError("head_sha must be a lowercase 40-character commit SHA")
    if base_sha and not SHA_RE.fullmatch(base_sha):
        raise ValidationError("base_sha must be empty or a lowercase 40-character commit SHA")
    if timeout_seconds < 1 or timeout_seconds > 3600:
        raise ValidationError("timeout_seconds must be between 1 and 3600")
    script = resolve_script(workspace, script_path)
    started = time.monotonic()
    exit_code = 1
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
    duration_ms = int((time.monotonic() - started) * 1000)
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
        },
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }
    _write_json(evidence_path, payload)
    return exit_code


def verify_trusted_candidate(workspace: Path, candidate_sha: str, trusted_ref: str) -> None:
    if not SHA_RE.fullmatch(candidate_sha):
        raise ValidationError("candidate_sha must be a lowercase 40-character commit SHA")
    if not trusted_ref.startswith("refs/heads/"):
        raise ValidationError("trusted_ref must be a full branch ref")
    remote_ref = "origin/" + trusted_ref.removeprefix("refs/heads/")
    subprocess.run(["git", "fetch", "--no-tags", "origin", trusted_ref], cwd=workspace, check=True)
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
    run.add_argument("--image-refs-json", default="[]")
    trust = sub.add_parser("check-trust")
    trust.add_argument("--workspace", required=True)
    trust.add_argument("--candidate-sha", required=True)
    trust.add_argument("--trusted-ref", default="refs/heads/main")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "check-trust":
            verify_trusted_candidate(Path(args.workspace), args.candidate_sha, args.trusted_ref)
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
        )
        return status
    except (ValidationError, OSError, subprocess.CalledProcessError) as exc:
        print(f"repository validation error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
