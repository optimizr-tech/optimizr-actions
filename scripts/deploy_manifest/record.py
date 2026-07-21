"""Collect sanitized Docker deployment state and write a deploy manifest."""

from __future__ import annotations

import argparse
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
from typing import Any, Sequence

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.deploy_manifest.write import ManifestConfig, write_manifest

_SERVICE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_CONTAINER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_ALLOWED_DOCKER_MODES = {"direct", "sudo"}
_COMMAND_TIMEOUT = 60


class CollectionError(ValueError):
    """Raised when deployment metadata cannot be safely collected."""


def _docker_prefix(mode: str) -> list[str]:
    if mode not in _ALLOWED_DOCKER_MODES:
        raise CollectionError("docker_mode must be direct or sudo")
    return ["docker"] if mode == "direct" else ["sudo", "docker"]


def _compose_path(deploy_path: Path, compose_file: str) -> Path:
    if not isinstance(compose_file, str) or not compose_file or "\\" in compose_file:
        raise CollectionError("compose_file must be repository relative")
    pure = PurePosixPath(compose_file)
    if pure.is_absolute() or ".." in pure.parts:
        raise CollectionError("compose_file must remain below deploy_path")
    candidate = deploy_path / pure.as_posix()
    resolved = candidate.resolve(strict=True)
    root = deploy_path.resolve(strict=True)
    if not resolved.is_relative_to(root) or candidate.is_symlink() or not resolved.is_file():
        raise CollectionError("compose_file must be a regular non-symlink file below deploy_path")
    return resolved


def _run(argv: Sequence[str], *, cwd: Path) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            list(argv),
            cwd=cwd,
            check=False,
            capture_output=True,
            text=True,
            timeout=_COMMAND_TIMEOUT,
            env=os.environ.copy(),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CollectionError(f"command unavailable: {type(exc).__name__}") from exc


def _split_services(raw: str) -> list[str]:
    services = raw.split()
    if len(services) > 100:
        raise CollectionError("services exceeds 100 entries")
    if any(not _SERVICE_RE.fullmatch(service) for service in services):
        raise CollectionError("services contains an invalid Compose service name")
    return list(dict.fromkeys(services))


def collect_state(
    *,
    deploy_path: Path,
    compose_file: str,
    container_name: str,
    services: str,
    docker_mode: str,
    runner: Any = _run,
) -> tuple[list[str], list[dict[str, str]], list[dict[str, str]]]:
    deploy_root = deploy_path.resolve(strict=True)
    compose = _compose_path(deploy_root, compose_file)
    prefix = _docker_prefix(docker_mode)
    compose_prefix = [*prefix, "compose", "-f", str(compose)]

    selected_services = _split_services(services)
    if not selected_services:
        completed = runner([*compose_prefix, "config", "--services"], cwd=deploy_root)
        if completed.returncode == 0:
            selected_services = _split_services(completed.stdout)

    image_refs: list[str] = []
    completed = runner([*compose_prefix, "config", "--images"], cwd=deploy_root)
    if completed.returncode == 0:
        for line in completed.stdout.splitlines():
            image_ref = line.strip()
            if image_ref and len(image_ref) <= 512 and image_ref not in image_refs:
                image_refs.append(image_ref)

    images: list[dict[str, str]] = []
    for image_ref in image_refs:
        inspected = runner(
            [*prefix, "image", "inspect", "--format", "{{.Id}}", image_ref],
            cwd=deploy_root,
        )
        digest = inspected.stdout.strip() if inspected.returncode == 0 else "unknown"
        if not _DIGEST_RE.fullmatch(digest):
            digest = "unknown"
        images.append({"image": image_ref, "digest": digest})

    healthchecks: list[dict[str, str]] = []
    if container_name:
        if not _CONTAINER_RE.fullmatch(container_name):
            raise CollectionError("container_name must be a bounded Docker identifier")
        inspected = runner(
            [
                *prefix,
                "inspect",
                "--format",
                "{{.State.Running}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}",
                container_name,
            ],
            cwd=deploy_root,
        )
        state = inspected.stdout.strip() if inspected.returncode == 0 else ""
        healthchecks.append(
            {
                "name": "primary-container",
                "status": "passed" if state == "true|healthy" else "failed",
                "target": container_name,
            }
        )

    return selected_services, images, healthchecks


def _environment_default(name: str, fallback: str = "unknown") -> str:
    return os.environ.get(name) or fallback


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--deploy-path", type=Path, required=True)
    parser.add_argument("--compose-file", required=True)
    parser.add_argument("--container-name", required=True)
    parser.add_argument("--services", default="")
    parser.add_argument("--docker-mode", choices=sorted(_ALLOWED_DOCKER_MODES), default="sudo")
    parser.add_argument("--status", choices=("success", "failure"), required=True)
    parser.add_argument(
        "--migration-result",
        choices=("passed", "failed", "skipped", "not-reported"),
        default="not-reported",
    )
    parser.add_argument(
        "--optional-build-result",
        choices=("passed", "failed", "skipped", "not-reported"),
        default="not-reported",
    )
    parser.add_argument("--retention", type=int, default=50)
    parser.add_argument("--environment", default="production")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        services, images, healthchecks = collect_state(
            deploy_path=args.deploy_path,
            compose_file=args.compose_file,
            container_name=args.container_name,
            services=args.services,
            docker_mode=args.docker_mode,
        )
        result = write_manifest(
            ManifestConfig(
                deploy_path=args.deploy_path,
                status=args.status,
                repository=_environment_default("GITHUB_REPOSITORY"),
                deployed_sha=_environment_default("GITHUB_SHA"),
                deployed_ref=_environment_default("GITHUB_REF"),
                environment=args.environment,
                workflow=_environment_default("GITHUB_WORKFLOW"),
                run_id=_environment_default("GITHUB_RUN_ID"),
                actor=_environment_default("GITHUB_ACTOR"),
                runner_name=_environment_default("RUNNER_NAME"),
                services=services,
                images=images,
                healthchecks=healthchecks,
                migration_result=args.migration_result,
                optional_build_result=args.optional_build_result,
                retention=args.retention,
            )
        )
        print(f"manifest_path={result.manifest_path}")
        print(f"last_successful_path={result.last_successful_path}")
        return 0
    except (CollectionError, OSError, ValueError) as exc:
        print(f"deploy manifest recording error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
