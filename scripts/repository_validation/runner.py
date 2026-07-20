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
REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


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


def resolve_evidence_path(workspace: Path, value: str | Path) -> Path:
    workspace = workspace.resolve(strict=True)
    raw = Path(value)
    candidate = raw if raw.is_absolute() else workspace / raw
    resolved = candidate.resolve(strict=False)
    if not resolved.is_relative_to(workspace):
        raise ValidationError("evidence path must remain inside the workspace")
    relative = resolved.relative_to(workspace)
    if _contains_symlink(workspace, relative):
        raise ValidationError("evidence path must not contain symbolic links")
    return resolved


def _version(argv: Sequence[str]) -> str | None:
    try:
        proc = subprocess.run(
            list(argv), check=False, capture_output=True, text=True, timeout=10
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    text = (proc.stdout or proc.stderr).strip().splitlines()
    return text[0][:300] if text else None


def _docker_inspect(image_ref: str) -> list[dict[str, Any]]:
    for command in (
        ["docker", "image", "inspect", image_ref],
        ["sudo", "-n", "docker", "image", "inspect", image_ref],
    ):
        try:
            proc = subprocess.run(command, check=False, capture_output=True, text=True, timeout=15)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
        if proc.returncode != 0:
            continue
        try:
            value = json.loads(proc.stdout)
        except json.JSONDecodeError:
            continue
        if isinstance(value, list) and all(isinstance(item, dict) for item in value):
            return value
    raise ValidationError("image_refs_json contains an image that cannot be inspected")


def collect_image_identities(image_refs: Sequence[str]) -> list[dict[str, str]]:
    identities: list[dict[str, str]] = []
    if len(image_refs) > 32:
        raise ValidationError("image_refs_json supports at most 32 images")
    for image_ref in image_refs:
        if not image_ref or len(image_ref) > 512 or "\0" in image_ref:
            raise ValidationError("image references must be bounded non-empty strings")
        inspected = _docker_inspect(image_ref)
        identity = ""
        kind = ""
        for item in inspected:
            for repo_digest in item.get("RepoDigests", []) or []:
                if isinstance(repo_digest, str) and "@" in repo_digest:
                    digest = repo_digest.rsplit("@", 1)[1]
                    if DIGEST_RE.fullmatch(digest):
                        identity = digest
                        kind = "repository_digest"
                        break
            if identity:
                break
        if not identity:
            for item in inspected:
                candidate = item.get("Id")
                if isinstance(candidate, str) and DIGEST_RE.fullmatch(candidate):
                    identity = candidate
                    kind = "local_image_id"
                    break
        if not identity:
            raise ValidationError("image_refs_json contains an image without an immutable identity")
        identities.append(
            {
                "alias_sha256": hashlib.sha256(image_ref.encode("utf-8")).hexdigest(),
                "identity": identity,
                "identity_kind": kind,
            }
        )
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


def collect_workspace_state(workspace: Path) -> dict[str, Any]:
    proc = subprocess.run(
        ["git", "status", "--porcelain=v1", "-z", "--untracked-files=all"],
        cwd=workspace,
        check=False,
        capture_output=True,
    )
    if proc.returncode != 0:
        raise ValidationError("workspace must be a Git repository with readable status")
    entries = [entry for entry in proc.stdout.split(b"\0") if entry]
    return {
        "clean": not entries,
        "changed_entries": len(entries),
        "status_sha256": hashlib.sha256(proc.stdout).hexdigest(),
    }


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
    workspace = workspace.resolve(strict=True)
    if not REPOSITORY_RE.fullmatch(repository) or len(repository) > 200:
        raise ValidationError("repository must use the bounded owner/name form")
    if not SHA_RE.fullmatch(head_sha):
        raise ValidationError("head_sha must be a lowercase 40-character commit SHA")
    if base_sha and not SHA_RE.fullmatch(base_sha):
        raise ValidationError("base_sha must be empty or a lowercase 40-character commit SHA")
    if timeout_seconds < 1 or timeout_seconds > 3600:
        raise ValidationError("timeout_seconds must be between 1 and 3600")
    script = resolve_script(workspace, script_path)
    evidence_path = resolve_evidence_path(workspace, evidence_path)
    before = collect_workspace_state(workspace)
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
    after = collect_workspace_state(workspace)
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
        "workspace": {
            "clean_before": before["clean"],
            "clean_after": after["clean"],
            "changed_entries_before": before["changed_entries"],
            "changed_entries_after": after["changed_entries"],
            "status_sha256_before": before["status_sha256"],
            "status_sha256_after": after["status_sha256"],
        },
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
    if not re.fullmatch(r"refs/heads/[A-Za-z0-9._/-]+", trusted_ref) or ".." in trusted_ref:
        raise ValidationError("trusted_ref must be a safe full branch ref")
    branch = trusted_ref.removeprefix("refs/heads/")
    remote_ref = f"refs/remotes/origin/{branch}"
    subprocess.run(
        ["git", "fetch", "--no-tags", "origin", f"+{trusted_ref}:{remote_ref}"],
        cwd=workspace,
        check=True,
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
