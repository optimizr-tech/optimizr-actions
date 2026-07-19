"""Write strict, sanitized and atomic deployment evidence."""

from __future__ import annotations

import argparse
import datetime as dt
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import tempfile
from typing import Any, Sequence


_SCHEMA_VERSION = "1.0"
_MAX_SCALAR_LENGTH = 512
_SERVICE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_SAFE_SEGMENT_RE = re.compile(r"[^0-9A-Za-z._-]")
_SECRET_VALUE_PATTERNS = (
    re.compile(
        r"(?i)(?:password|passwd|secret|token|authorization|cookie|private[_ .-]?key)\s*[:=]"
    ),
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/-]+=*"),
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    re.compile(r"(?i)(?:x-amz-signature|x-goog-signature|signature|signed_url|sig)=([^&\s]+)"),
    re.compile(r"(?i)(?:^|[/\\])\.env(?:$|[./\\])"),
)
_IMAGE_KEYS = frozenset({"image", "digest"})
_HEALTHCHECK_KEYS = frozenset({"name", "status", "target"})
_HEALTHCHECK_STATUSES = frozenset({"passed", "failed", "skipped"})
_MIGRATION_RESULTS = frozenset({"passed", "failed", "skipped", "not-reported"})
_DEPLOY_STATUSES = frozenset({"success", "failure"})


@dataclass(frozen=True)
class ManifestConfig:
    """Validated inputs used to produce one immutable manifest."""

    deploy_path: Path
    status: str
    repository: str
    deployed_sha: str
    deployed_ref: str
    environment: str
    workflow: str
    run_id: str
    actor: str
    runner_name: str
    services: Sequence[str]
    images: Sequence[dict[str, str]]
    healthchecks: Sequence[dict[str, str]]
    migration_result: str = "not-reported"
    rollback_of: str | None = None
    retention: int = 50
    now: dt.datetime | None = None


@dataclass(frozen=True)
class ManifestResult:
    """Filesystem paths written by :func:`write_manifest`."""

    manifest_path: Path
    last_successful_path: Path


def _validate_scalar(name: str, value: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a string")
    if not allow_empty and not value:
        raise ValueError(f"{name} must not be empty")
    if "\n" in value or "\r" in value:
        raise ValueError(f"{name} must be a single-line value")
    if len(value) > _MAX_SCALAR_LENGTH:
        raise ValueError(f"{name} exceeds {_MAX_SCALAR_LENGTH} characters")
    if any(pattern.search(value) for pattern in _SECRET_VALUE_PATTERNS):
        raise ValueError(f"{name} contains prohibited secret-like data")
    return value


def _validate_deploy_path(path: Path) -> Path:
    if not path.is_absolute():
        raise ValueError("deploy_path must be absolute")
    if path.parent == path:
        raise ValueError("deploy_path must not be a filesystem root")
    if not path.exists() or not path.is_dir():
        raise ValueError("deploy_path must be an existing directory")

    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        if current.exists() and current.is_symlink():
            raise ValueError("deploy_path must not contain symlink components")

    return path


def _validate_services(services: Sequence[str]) -> list[str]:
    validated: list[str] = []
    for service in services:
        if not isinstance(service, str) or not _SERVICE_RE.fullmatch(service):
            raise ValueError("service names must use letters, digits, dot, underscore or hyphen")
        validated.append(service)
    return validated


def _validate_images(images: Sequence[dict[str, str]]) -> list[dict[str, str]]:
    validated: list[dict[str, str]] = []
    for image in images:
        if not isinstance(image, dict) or set(image) != _IMAGE_KEYS:
            raise ValueError("each image requires exactly image and digest keys")
        image_name = _validate_scalar("image", image["image"])
        digest = _validate_scalar("digest", image["digest"])
        if digest != "unknown" and not _DIGEST_RE.fullmatch(digest):
            raise ValueError("digest must be unknown or a lowercase sha256 digest")
        validated.append({"image": image_name, "digest": digest})
    return validated


def _validate_healthchecks(
    healthchecks: Sequence[dict[str, str]],
) -> list[dict[str, str]]:
    validated: list[dict[str, str]] = []
    for healthcheck in healthchecks:
        if not isinstance(healthcheck, dict) or set(healthcheck) != _HEALTHCHECK_KEYS:
            raise ValueError("each healthcheck requires exactly name, status and target keys")
        name = _validate_scalar("healthcheck.name", healthcheck["name"])
        status = _validate_scalar("healthcheck.status", healthcheck["status"])
        target = _validate_scalar("healthcheck.target", healthcheck["target"])
        if status not in _HEALTHCHECK_STATUSES:
            raise ValueError("healthcheck status must be passed, failed or skipped")
        validated.append({"name": name, "status": status, "target": target})
    return validated


def _atomic_write(path: Path, content: bytes) -> None:
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
        os.chmod(path, 0o600)

        directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        directory_fd = os.open(path.parent, directory_flags)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if os.path.exists(temporary_name):
            os.unlink(temporary_name)


def _safe_filename_segment(value: str, fallback: str) -> str:
    sanitized = _SAFE_SEGMENT_RE.sub("-", value)
    return sanitized or fallback


def _manifest_bytes(payload: dict[str, Any]) -> bytes:
    return (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")


def write_manifest(config: ManifestConfig) -> ManifestResult:
    """Validate metadata and atomically write one deployment manifest."""

    deploy_path = _validate_deploy_path(Path(config.deploy_path))
    if config.status not in _DEPLOY_STATUSES:
        raise ValueError("status must be success or failure")
    if not isinstance(config.retention, int) or isinstance(config.retention, bool):
        raise ValueError("retention must be an integer")
    if not 1 <= config.retention <= 500:
        raise ValueError("retention must be between 1 and 500")

    repository = _validate_scalar("repository", config.repository)
    deployed_sha = _validate_scalar("deployed_sha", config.deployed_sha)
    deployed_ref = _validate_scalar("deployed_ref", config.deployed_ref)
    environment = _validate_scalar("environment", config.environment)
    workflow = _validate_scalar("workflow", config.workflow)
    run_id = _validate_scalar("run_id", config.run_id)
    actor = _validate_scalar("actor", config.actor)
    runner_name = _validate_scalar("runner_name", config.runner_name)
    rollback_of = (
        _validate_scalar("rollback_of", config.rollback_of)
        if config.rollback_of is not None
        else None
    )
    if config.migration_result not in _MIGRATION_RESULTS:
        raise ValueError("migration_result is not an allowed value")

    services = _validate_services(config.services)
    images = _validate_images(config.images)
    healthchecks = _validate_healthchecks(config.healthchecks)

    now = config.now or dt.datetime.now(dt.timezone.utc)
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("now must be timezone-aware")
    now = now.astimezone(dt.timezone.utc).replace(microsecond=0)
    timestamp = now.isoformat().replace("+00:00", "Z")
    compact_timestamp = now.strftime("%Y%m%dT%H%M%SZ")

    payload: dict[str, Any] = {
        "schema_version": _SCHEMA_VERSION,
        "status": config.status,
        "deployed_at": timestamp,
        "repository": repository,
        "deployed_sha": deployed_sha,
        "deployed_ref": deployed_ref,
        "workflow": workflow,
        "run_id": run_id,
        "environment": environment,
        "actor": actor,
        "runner_name": runner_name,
        "services": services,
        "images": images,
        "healthchecks": healthchecks,
        "migration_result": config.migration_result,
        "rollback_of": rollback_of,
    }
    content = _manifest_bytes(payload)

    manifest_dir = deploy_path / ".deploy-manifests"
    manifest_dir.mkdir(mode=0o750, exist_ok=True)
    if manifest_dir.is_symlink():
        raise ValueError("manifest directory must not be a symlink")
    os.chmod(manifest_dir, 0o750)

    safe_sha = _safe_filename_segment(deployed_sha[:12], "unknown")
    safe_run = _safe_filename_segment(run_id, "unknown")
    manifest_path = manifest_dir / f"{compact_timestamp}-{safe_sha}-{safe_run}.json"
    if manifest_path.exists():
        raise ValueError("immutable manifest path already exists")
    _atomic_write(manifest_path, content)

    last_successful_path = manifest_dir / "last-successful.json"
    if config.status == "success":
        _atomic_write(last_successful_path, content)

    immutable = sorted(
        (
            path
            for path in manifest_dir.glob("*.json")
            if path.name != last_successful_path.name
        ),
        key=lambda path: path.name,
        reverse=True,
    )
    for expired in immutable[config.retention :]:
        expired.unlink()

    return ManifestResult(
        manifest_path=manifest_path,
        last_successful_path=last_successful_path,
    )


def _parse_json_list(name: str, raw: str) -> list[Any]:
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{name} must be valid JSON") from exc
    if not isinstance(value, list):
        raise ValueError(f"{name} must be a JSON array")
    return value


def _environment_default(name: str, fallback: str = "unknown") -> str:
    return os.environ.get(name) or fallback


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--deploy-path", type=Path, required=True)
    parser.add_argument("--status", choices=sorted(_DEPLOY_STATUSES), required=True)
    parser.add_argument("--repository", default=_environment_default("GITHUB_REPOSITORY"))
    parser.add_argument("--deployed-sha", default=_environment_default("GITHUB_SHA"))
    parser.add_argument("--deployed-ref", default=_environment_default("GITHUB_REF"))
    parser.add_argument("--environment", default="production")
    parser.add_argument("--workflow", default=_environment_default("GITHUB_WORKFLOW"))
    parser.add_argument("--run-id", default=_environment_default("GITHUB_RUN_ID"))
    parser.add_argument("--actor", default=_environment_default("GITHUB_ACTOR"))
    parser.add_argument("--runner-name", default=_environment_default("RUNNER_NAME"))
    parser.add_argument("--services-json", default="[]")
    parser.add_argument("--images-json", default="[]")
    parser.add_argument("--healthchecks-json", default="[]")
    parser.add_argument("--migration-result", choices=sorted(_MIGRATION_RESULTS), default="not-reported")
    parser.add_argument("--rollback-of")
    parser.add_argument("--retention", type=int, default=50)
    args = parser.parse_args(argv)

    config = ManifestConfig(
        deploy_path=args.deploy_path,
        status=args.status,
        repository=args.repository,
        deployed_sha=args.deployed_sha,
        deployed_ref=args.deployed_ref,
        environment=args.environment,
        workflow=args.workflow,
        run_id=args.run_id,
        actor=args.actor,
        runner_name=args.runner_name,
        services=_parse_json_list("services_json", args.services_json),
        images=_parse_json_list("images_json", args.images_json),
        healthchecks=_parse_json_list("healthchecks_json", args.healthchecks_json),
        migration_result=args.migration_result,
        rollback_of=args.rollback_of,
        retention=args.retention,
    )
    result = write_manifest(config)
    print(f"manifest_path={result.manifest_path}")
    print(f"last_successful_path={result.last_successful_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
