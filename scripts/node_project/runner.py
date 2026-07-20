#!/usr/bin/env python3
"""Execute bounded npm/pnpm validation phases without shell interpolation."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import time
from typing import Any, Mapping, Sequence

NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$")
SCRIPT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9:_-]{0,79}$")
LOCKFILES = {"npm": "package-lock.json", "pnpm": "pnpm-lock.yaml"}
PHASE_FIELDS = ("lint_script", "format_script", "typecheck_script", "test_script", "build_script")
MAX_ARTIFACT_PATHS = 20


class ProjectError(ValueError):
    """Raised when a project specification violates the reusable contract."""


@dataclass(frozen=True)
class ProjectSpec:
    name: str
    working_directory: str
    package_manager: str
    install: bool = True
    lockfile: str = ""
    lint_script: str = ""
    format_script: str = ""
    typecheck_script: str = ""
    test_script: str = ""
    build_script: str = ""
    artifact_paths: tuple[str, ...] = ()

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> "ProjectSpec":
        if not isinstance(raw, Mapping):
            raise ProjectError("project specification must be an object")
        name = raw.get("name")
        if not isinstance(name, str) or not NAME_RE.fullmatch(name):
            raise ProjectError("project name must be a bounded identifier")
        manager = raw.get("package_manager")
        if manager not in LOCKFILES:
            raise ProjectError("package_manager must be npm or pnpm")
        workdir = _relative_string(raw.get("working_directory", "."), "working_directory")
        install = raw.get("install", True)
        if not isinstance(install, bool):
            raise ProjectError("install must be boolean")
        lockfile = _relative_string(raw.get("lockfile") or LOCKFILES[manager], "lockfile")
        values: dict[str, str] = {}
        for field in PHASE_FIELDS:
            value = raw.get(field, "")
            if value in (None, ""):
                values[field] = ""
            elif not isinstance(value, str) or not SCRIPT_RE.fullmatch(value):
                raise ProjectError(f"{field} must be an allowlisted package-script identifier")
            else:
                values[field] = value
        artifact_paths = raw.get("artifact_paths", [])
        if artifact_paths is None:
            artifact_paths = []
        if not isinstance(artifact_paths, list) or len(artifact_paths) > MAX_ARTIFACT_PATHS:
            raise ProjectError(f"artifact_paths must contain at most {MAX_ARTIFACT_PATHS} paths")
        normalized_artifacts = tuple(_relative_string(item, "artifact path") for item in artifact_paths)
        return cls(
            name=name,
            working_directory=workdir,
            package_manager=manager,
            install=install,
            lockfile=lockfile,
            artifact_paths=normalized_artifacts,
            **values,
        )


def _relative_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 512:
        raise ProjectError(f"{label} must be a bounded non-empty string")
    if any(ord(char) < 32 for char in value) or "\\" in value:
        raise ProjectError(f"{label} contains unsupported characters")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts:
        raise ProjectError(f"{label} must remain repository relative")
    normalized = path.as_posix()
    if normalized in {"", "."}:
        return "."
    return normalized


def validate_relative_path(root: Path, relative: str, *, must_exist: bool) -> Path:
    root = root.resolve(strict=True)
    normalized = _relative_string(relative, "path")
    candidate = root if normalized == "." else root / normalized
    try:
        resolved = candidate.resolve(strict=must_exist)
    except OSError as exc:
        raise ProjectError(f"path is unavailable: {normalized}") from exc
    if not resolved.is_relative_to(root):
        raise ProjectError("path resolves outside the workspace")
    current = candidate
    while current != root:
        if current.is_symlink():
            raise ProjectError(f"symbolic links are not allowed: {normalized}")
        current = current.parent
    return resolved


def _reject_tree_symlinks(path: Path) -> None:
    if path.is_symlink():
        raise ProjectError(f"artifact is a symbolic link: {path.name}")
    if path.is_dir():
        for child in path.rglob("*"):
            if child.is_symlink():
                raise ProjectError(f"artifact tree contains a symbolic link: {child.name}")


def _copy_artifacts(spec: ProjectSpec, project_dir: Path, destination: Path) -> list[str]:
    copied: list[str] = []
    collected = destination / "collected"
    for relative in spec.artifact_paths:
        source = validate_relative_path(project_dir, relative, must_exist=True)
        _reject_tree_symlinks(source)
        target = collected / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        if source.is_dir():
            shutil.copytree(source, target, dirs_exist_ok=True)
        elif source.is_file():
            shutil.copy2(source, target)
        else:
            raise ProjectError(f"artifact must be a file or directory: {relative}")
        copied.append(relative)
    return copied


def _write_evidence(destination: Path, payload: Mapping[str, Any]) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    path = destination / "evidence.json"
    if path.is_symlink():
        raise ProjectError("evidence path must not be a symbolic link")
    temporary = path.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def execute_project(spec: ProjectSpec, *, workspace: Path, evidence_root: Path) -> dict[str, Any]:
    workspace = workspace.resolve(strict=True)
    evidence_root = evidence_root.resolve(strict=False)
    if not evidence_root.is_relative_to(workspace):
        raise ProjectError("evidence root must remain inside the workspace")
    if evidence_root.exists() and evidence_root.is_symlink():
        raise ProjectError("evidence root must not be a symbolic link")
    project_dir = validate_relative_path(workspace, spec.working_directory, must_exist=True)
    if not project_dir.is_dir():
        raise ProjectError("working_directory must be a directory")
    package_json = validate_relative_path(project_dir, "package.json", must_exist=True)
    if not package_json.is_file() or package_json.is_symlink():
        raise ProjectError("package.json must be a regular non-symlink file")
    if spec.install:
        lockfile = validate_relative_path(project_dir, spec.lockfile, must_exist=True)
        if not lockfile.is_file() or lockfile.is_symlink():
            raise ProjectError("lockfile must be a regular non-symlink file")

    destination = evidence_root / spec.name
    started = time.monotonic()
    phases: list[dict[str, Any]] = []
    commands: list[tuple[str, list[str]]] = []
    if spec.install:
        commands.append(("install", ["ci"] if spec.package_manager == "npm" else ["install", "--frozen-lockfile"]))
    for field in PHASE_FIELDS:
        script = getattr(spec, field)
        if script:
            commands.append((field.removesuffix("_script"), ["run", script]))

    for phase, arguments in commands:
        phase_started = time.monotonic()
        completed = subprocess.run(
            [spec.package_manager, *arguments],
            cwd=project_dir,
            check=False,
            env=os.environ.copy(),
        )
        phases.append({
            "name": phase,
            "exit_code": completed.returncode,
            "duration_ms": int((time.monotonic() - phase_started) * 1000),
        })
        if completed.returncode != 0:
            payload = {
                "schema_version": 1,
                "name": spec.name,
                "working_directory": spec.working_directory,
                "package_manager": spec.package_manager,
                "phases": phases,
                "artifacts": [],
                "result": "failed",
                "duration_ms": int((time.monotonic() - started) * 1000),
            }
            _write_evidence(destination, payload)
            raise ProjectError(f"{phase} failed with exit code {completed.returncode}")

    copied = _copy_artifacts(spec, project_dir, destination)
    payload = {
        "schema_version": 1,
        "name": spec.name,
        "working_directory": spec.working_directory,
        "package_manager": spec.package_manager,
        "phases": phases,
        "artifacts": copied,
        "result": "passed",
        "duration_ms": int((time.monotonic() - started) * 1000),
    }
    _write_evidence(destination, payload)
    return payload


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--project-json", required=True)
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--evidence-root", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        raw = json.loads(args.project_json)
        spec = ProjectSpec.from_mapping(raw)
        execute_project(
            spec,
            workspace=Path(args.workspace),
            evidence_root=Path(args.evidence_root),
        )
        return 0
    except (json.JSONDecodeError, ProjectError, OSError) as exc:
        print(f"node project validation error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
