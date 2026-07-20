#!/usr/bin/env python3
"""Deploy a one-shot static builder through candidate and rollback volumes."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import time
from typing import Any, Mapping, Sequence

SHA_RE = re.compile(r"^[0-9a-f]{40}$")
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$")
VOLUME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$")
MOUNT_RE = re.compile(r"^/[A-Za-z0-9_./-]{1,255}$")
MAX_MANIFEST_BYTES = 1024 * 1024
MAX_OUTPUTS = 50
COMMAND_TIMEOUT = 1200


class DeployError(ValueError):
    """Raised when the deployment contract or runtime operation fails."""


def _relative(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 512 or "\\" in value or any(ord(c) < 32 for c in value):
        raise DeployError(f"{label} must be a bounded repository-relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts:
        raise DeployError(f"{label} must remain repository relative")
    normalized = path.as_posix()
    return "." if normalized in {"", "."} else normalized


@dataclass(frozen=True)
class DeploySpec:
    service_name: str
    source_path: str
    deploy_root: str
    allowed_root: str
    compose_file: str
    builder_service: str
    static_volume: str
    output_mount_path: str
    required_outputs: tuple[str, ...]

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> "DeploySpec":
        if not isinstance(raw, Mapping) or raw.get("version") != 1:
            raise DeployError("manifest must be an object with version 1")
        service = raw.get("service_name")
        builder = raw.get("builder_service")
        volume = raw.get("static_volume")
        if not isinstance(service, str) or not NAME_RE.fullmatch(service):
            raise DeployError("service_name must be a bounded identifier")
        if not isinstance(builder, str) or not NAME_RE.fullmatch(builder):
            raise DeployError("builder_service must be a bounded identifier")
        if not isinstance(volume, str) or not VOLUME_RE.fullmatch(volume):
            raise DeployError("static_volume must be a bounded Docker volume name")
        deploy_root = raw.get("deploy_root")
        allowed_root = raw.get("allowed_root")
        if not isinstance(deploy_root, str) or not Path(deploy_root).is_absolute():
            raise DeployError("deploy_root must be absolute")
        if not isinstance(allowed_root, str) or not Path(allowed_root).is_absolute():
            raise DeployError("allowed_root must be absolute")
        mount = raw.get("output_mount_path")
        if not isinstance(mount, str) or not MOUNT_RE.fullmatch(mount) or ".." in PurePosixPath(mount).parts:
            raise DeployError("output_mount_path must be a bounded absolute container path")
        outputs = raw.get("required_outputs")
        if not isinstance(outputs, list) or not 1 <= len(outputs) <= MAX_OUTPUTS:
            raise DeployError(f"required_outputs must contain 1-{MAX_OUTPUTS} paths")
        normalized_outputs = tuple(_relative(item, "required output") for item in outputs)
        return cls(
            service_name=service,
            source_path=_relative(raw.get("source_path", "."), "source_path"),
            deploy_root=deploy_root,
            allowed_root=allowed_root,
            compose_file=_relative(raw.get("compose_file", "docker-compose.yml"), "compose_file"),
            builder_service=builder,
            static_volume=volume,
            output_mount_path=mount.rstrip("/"),
            required_outputs=normalized_outputs,
        )


def load_manifest(path: Path) -> DeploySpec:
    if not path.is_file() or path.is_symlink():
        raise DeployError("manifest must be a regular non-symlink file")
    if path.stat().st_size > MAX_MANIFEST_BYTES:
        raise DeployError(f"manifest exceeds {MAX_MANIFEST_BYTES} bytes")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise DeployError("manifest is not valid UTF-8 JSON") from exc
    return DeploySpec.from_mapping(data)


def _reject_symlink_tree(root: Path) -> None:
    if root.is_symlink():
        raise DeployError("source path must not be a symlink")
    for path in root.rglob("*"):
        if path.is_symlink():
            raise DeployError("source tree must not contain symlinks")


def _workspace_source(workspace: Path, relative: str) -> Path:
    workspace = workspace.resolve(strict=True)
    candidate = workspace if relative == "." else workspace / relative
    resolved = candidate.resolve(strict=True)
    if not resolved.is_relative_to(workspace) or not resolved.is_dir():
        raise DeployError("source_path must resolve to a repository directory")
    _reject_symlink_tree(candidate)
    return resolved


def _deployment_paths(spec: DeploySpec) -> tuple[Path, Path]:
    allowed = Path(spec.allowed_root)
    deploy = Path(spec.deploy_root)
    if not allowed.is_dir() or allowed.is_symlink():
        raise DeployError("allowed_root must be an existing non-symlink directory")
    allowed_resolved = allowed.resolve(strict=True)
    parent = deploy.parent.resolve(strict=True)
    if not parent.is_relative_to(allowed_resolved):
        raise DeployError("deploy_root must remain inside allowed_root")
    if deploy.exists() and (deploy.is_symlink() or not deploy.is_dir()):
        raise DeployError("deploy_root must be a directory or absent")
    return allowed_resolved, parent / deploy.name


def _write_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise DeployError("evidence path must not be a symlink")
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def _docker_prefix(mode: str) -> list[str]:
    if mode == "direct":
        return ["docker"]
    if mode == "sudo":
        return ["sudo", "docker"]
    raise DeployError("docker_mode must be direct or sudo")


def _run(prefix: list[str], args: list[str], *, env: Mapping[str, str] | None = None, capture: bool = False, required: bool = True) -> subprocess.CompletedProcess[str]:
    try:
        completed = subprocess.run(
            [*prefix, *args],
            check=False,
            text=True,
            capture_output=capture,
            timeout=COMMAND_TIMEOUT,
            env=dict(env) if env is not None else os.environ.copy(),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        if required:
            raise DeployError(f"Docker command unavailable: {type(exc).__name__}") from exc
        return subprocess.CompletedProcess([*prefix, *args], 127, "", "")
    if required and completed.returncode != 0:
        raise DeployError(f"Docker command failed with exit code {completed.returncode}")
    return completed


def _volume_mount(volume: str, path: str, read_only: bool = False) -> str:
    return f"{volume}:{path}{':ro' if read_only else ''}"


def _verify_outputs(prefix: list[str], image_id: str, volume: str, mount: str, outputs: Sequence[str]) -> None:
    for relative in outputs:
        target = f"{mount}/{relative}" if relative != "." else mount
        _run(prefix, ["run", "--rm", "--entrypoint", "test", "-v", _volume_mount(volume, mount, True), image_id, "-e", target])


def _clear_volume(prefix: list[str], image_id: str, volume: str, mount: str) -> None:
    _run(prefix, ["run", "--rm", "--entrypoint", "find", "-v", _volume_mount(volume, mount), image_id, mount, "-mindepth", "1", "-delete"])


def _copy_volume(prefix: list[str], image_id: str, source: str, destination: str) -> None:
    _run(prefix, [
        "run", "--rm", "--entrypoint", "cp",
        "-v", _volume_mount(source, "/source", True),
        "-v", _volume_mount(destination, "/destination"),
        image_id, "-a", "/source/.", "/destination/",
    ])


def deploy_static_site(*, spec: DeploySpec, workspace: Path, deployed_sha: str, docker_mode: str, evidence_path: Path) -> dict[str, Any]:
    if not SHA_RE.fullmatch(deployed_sha):
        raise DeployError("deployed_sha must be a lowercase 40-character SHA")
    started = time.monotonic()
    source = _workspace_source(workspace, spec.source_path)
    allowed, deploy_root = _deployment_paths(spec)
    suffix = deployed_sha[:12]
    stage = allowed / f".{deploy_root.name}.candidate-{suffix}"
    source_backup = allowed / f".{deploy_root.name}.backup-{suffix}"
    candidate_volume = f"{spec.static_volume}-candidate-{suffix}"
    backup_volume = f"{spec.static_volume}-backup-{suffix}"
    prefix = _docker_prefix(docker_mode)
    image_id = ""
    stable_changed = False
    source_moved = False
    phase = "initialize"

    for path in (stage, source_backup):
        if path.exists():
            if path.is_symlink() or not path.is_dir():
                raise DeployError("staging paths must be directories")
            shutil.rmtree(path)
    shutil.copytree(source, stage)
    compose = stage / spec.compose_file
    if not compose.is_file() or compose.is_symlink():
        shutil.rmtree(stage, ignore_errors=True)
        raise DeployError("compose_file must be a regular staged file")

    compose_env = os.environ.copy()
    compose_env["STATIC_VOLUME_NAME"] = candidate_volume
    base_compose = ["compose", "--project-directory", str(stage), "-f", str(compose)]
    try:
        phase = "prepare-volumes"
        _run(prefix, ["volume", "rm", "-f", candidate_volume, backup_volume], required=False)
        for volume in (candidate_volume, spec.static_volume, backup_volume):
            _run(prefix, ["volume", "create", volume])

        phase = "build"
        _run(prefix, [*base_compose, "build", spec.builder_service], env=compose_env)
        _run(prefix, [*base_compose, "run", "--rm", "--no-deps", spec.builder_service], env=compose_env)
        image_result = _run(prefix, [*base_compose, "images", "-q", spec.builder_service], env=compose_env, capture=True)
        image_id = image_result.stdout.strip().splitlines()[0] if image_result.stdout.strip() else ""
        if not re.fullmatch(r"sha256:[0-9A-Za-z_.:-]{3,200}", image_id):
            raise DeployError("builder image identity is missing or invalid")
        _verify_outputs(prefix, image_id, candidate_volume, spec.output_mount_path, spec.required_outputs)

        phase = "backup-volume"
        _copy_volume(prefix, image_id, spec.static_volume, backup_volume)

        phase = "promote-volume"
        stable_changed = True
        _clear_volume(prefix, image_id, spec.static_volume, spec.output_mount_path)
        _copy_volume(prefix, image_id, candidate_volume, spec.static_volume)
        _verify_outputs(prefix, image_id, spec.static_volume, spec.output_mount_path, spec.required_outputs)

        phase = "promote-source"
        if deploy_root.exists():
            os.replace(deploy_root, source_backup)
            source_moved = True
        os.replace(stage, deploy_root)
        if source_backup.exists():
            shutil.rmtree(source_backup)
        source_moved = False

        phase = "cleanup"
        _run(prefix, ["volume", "rm", "-f", candidate_volume, backup_volume], required=False)
        payload = {
            "schema_version": 1,
            "service_name": spec.service_name,
            "deployed_sha": deployed_sha,
            "builder_image_id": image_id,
            "required_output_hashes": [hashlib.sha256(path.encode("utf-8")).hexdigest() for path in spec.required_outputs],
            "result": "passed",
            "duration_ms": int((time.monotonic() - started) * 1000),
            "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        }
        _write_json(evidence_path, payload)
        return payload
    except (DeployError, OSError) as exc:
        if stable_changed and image_id:
            try:
                _clear_volume(prefix, image_id, spec.static_volume, spec.output_mount_path)
                _copy_volume(prefix, image_id, backup_volume, spec.static_volume)
            except DeployError:
                phase = f"{phase}-rollback-failed"
        if source_moved and source_backup.exists() and not deploy_root.exists():
            os.replace(source_backup, deploy_root)
        if stage.exists():
            shutil.rmtree(stage, ignore_errors=True)
        _run(prefix, ["volume", "rm", "-f", candidate_volume, backup_volume], required=False)
        payload = {
            "schema_version": 1,
            "service_name": spec.service_name,
            "deployed_sha": deployed_sha,
            "builder_image_id": image_id or None,
            "result": "failed",
            "failure_phase": phase,
            "duration_ms": int((time.monotonic() - started) * 1000),
            "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        }
        _write_json(evidence_path, payload)
        raise DeployError(f"static-site deployment failed during {phase}") from exc


def _repo_path(workspace: Path, relative: str) -> Path:
    if not relative or relative.startswith("/") or "\\" in relative or ".." in Path(relative).parts:
        raise DeployError("manifest_path must be repository relative")
    candidate = workspace / relative
    resolved = candidate.resolve(strict=True)
    if not resolved.is_relative_to(workspace) or candidate.is_symlink():
        raise DeployError("manifest_path resolves outside workspace or through a symlink")
    return resolved


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest-path", required=True)
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--deployed-sha", required=True)
    parser.add_argument("--docker-mode", default="sudo")
    parser.add_argument("--evidence-path", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        workspace = Path(args.workspace).resolve(strict=True)
        manifest = _repo_path(workspace, args.manifest_path)
        evidence = workspace / args.evidence_path
        evidence_resolved = evidence.resolve(strict=False)
        if not evidence_resolved.is_relative_to(workspace):
            raise DeployError("evidence_path must remain inside workspace")
        deploy_static_site(
            spec=load_manifest(manifest),
            workspace=workspace,
            deployed_sha=args.deployed_sha,
            docker_mode=args.docker_mode,
            evidence_path=evidence_resolved,
        )
        return 0
    except (DeployError, OSError) as exc:
        print(f"static-site deployment error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
