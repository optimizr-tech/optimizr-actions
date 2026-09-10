"""Build a protected, provider-neutral rollback plan from approved evidence."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import json
from pathlib import Path
import re

from .request import RequestError, parse_request


class RollbackError(ValueError):
    """Raised when a rollback target cannot be approved safely."""


SHA_RE = re.compile(r"^[0-9a-f]{40}$")
SERVICE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
SNAPSHOT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*\.tar\.gz$")
SECRET_LIKE_RE = re.compile(
    r"(?i)(?:password|passwd|secret|token|authorization|cookie|"
    r"private[_ .-]?key)\s*[:=]|-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"
)


@dataclass(frozen=True)
class RollbackSpec:
    """Explicit roots and human authorization for one rollback plan."""

    manifest_path: Path
    manifest_root: Path
    snapshot_root: Path
    service: str
    confirmation: str
    operator: str
    reason: str


@dataclass(frozen=True)
class RollbackPlan:
    """Validated, non-mutating rollback target for a trusted host adapter."""

    repository: str
    service: str
    candidate_sha: str
    trusted_ref: str
    compose_file: str
    container_name: str
    adapter: str
    manifest_path: Path
    snapshot_path: Path
    operator: str
    reason: str


def _single_line(name: str, value: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise RollbackError(f"{name} must be a non-empty trimmed string")
    if "\n" in value or "\r" in value:
        raise RollbackError(f"{name} must be single-line")
    if len(value) > 256:
        raise RollbackError(f"{name} exceeds 256 characters")
    if SECRET_LIKE_RE.search(value):
        raise RollbackError(f"{name} contains prohibited secret-like data")
    return value


def _reject_symlink_components(path: Path) -> None:
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        if current.exists() and current.is_symlink():
            raise RollbackError("rollback path must not contain symlink components")


def _existing_root(path: Path, label: str) -> Path:
    if not isinstance(path, Path) or not path.is_absolute():
        raise RollbackError(f"{label} must be absolute")
    _reject_symlink_components(path)
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise RollbackError(f"{label} could not be resolved") from exc
    if not resolved.is_dir():
        raise RollbackError(f"{label} must be an existing directory")
    return resolved


def _file_below(path: Path, root: Path, label: str) -> Path:
    if not isinstance(path, Path) or not path.is_absolute():
        raise RollbackError(f"{label} must be absolute")
    _reject_symlink_components(path)
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise RollbackError(f"{label} could not be resolved") from exc
    if root == resolved or root not in resolved.parents:
        raise RollbackError(f"{label} must remain below its declared root")
    if not resolved.is_file() or resolved.is_symlink():
        raise RollbackError(f"{label} must be a regular file")
    return resolved


def _load_manifest(path: Path) -> dict[str, object]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RollbackError("rollback manifest must contain valid UTF-8 JSON") from exc
    if not isinstance(payload, dict):
        raise RollbackError("rollback manifest must be a JSON object")
    if (
        payload.get("schema_version") != 1
        or payload.get("status") != "success"
        or payload.get("ready") is not True
        or payload.get("failure_reason") is not None
    ):
        raise RollbackError("rollback manifest is not an approved successful delivery")
    return payload


def _request_from_manifest(payload: Mapping[str, object]):
    request_payload = {
        field: payload.get(field)
        for field in (
            "repository",
            "service",
            "candidate_sha",
            "trusted_ref",
            "compose_file",
            "container_name",
            "adapter",
        )
    }
    try:
        return parse_request(request_payload)
    except (RequestError, TypeError, ValueError) as exc:
        raise RollbackError("rollback manifest request is invalid") from exc


def _snapshot_from_manifest(
    payload: Mapping[str, object],
    snapshot_root: Path,
) -> Path:
    sync = payload.get("sync")
    if not isinstance(sync, Mapping):
        raise RollbackError("rollback manifest has no synchronization evidence")
    if not all(isinstance(sync.get(field), bool) for field in (
        "changed",
        "snapshot_created",
        "synced",
    )):
        raise RollbackError("rollback synchronization evidence is invalid")
    if not all(sync.get(field) is True for field in (
        "changed",
        "snapshot_created",
        "synced",
    )):
        raise RollbackError("rollback manifest has no approved snapshot")
    snapshot_name = sync.get("snapshot_name")
    if not isinstance(snapshot_name, str) or not SNAPSHOT_RE.fullmatch(snapshot_name):
        raise RollbackError("rollback snapshot name is unsafe")
    snapshot_path = snapshot_root / snapshot_name
    _reject_symlink_components(snapshot_path)
    try:
        resolved = snapshot_path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise RollbackError("rollback snapshot could not be resolved") from exc
    if snapshot_root == resolved or snapshot_root not in resolved.parents:
        raise RollbackError("rollback snapshot must remain below its declared root")
    if not resolved.is_file() or resolved.is_symlink():
        raise RollbackError("rollback snapshot must be a regular file")
    return resolved


def build_rollback_plan(spec: RollbackSpec) -> RollbackPlan:
    """Validate an approved manifest and return a plan without changing the host."""

    if not isinstance(spec, RollbackSpec):
        raise RollbackError("rollback specification is invalid")
    if not isinstance(spec.service, str) or not SERVICE_RE.fullmatch(spec.service):
        raise RollbackError("service must be a bounded identifier")
    operator = _single_line("operator", spec.operator)
    reason = _single_line("reason", spec.reason)
    manifest_root = _existing_root(spec.manifest_root, "manifest root")
    snapshot_root = _existing_root(spec.snapshot_root, "snapshot root")
    manifest_path = _file_below(spec.manifest_path, manifest_root, "manifest path")
    payload = _load_manifest(manifest_path)
    request = _request_from_manifest(payload)
    if request.service != spec.service:
        raise RollbackError("rollback service does not match the approved manifest")
    expected_confirmation = f"ROLLBACK {request.service} {request.candidate_sha}"
    if spec.confirmation != expected_confirmation:
        raise RollbackError("confirmation must match the exact service and SHA")
    snapshot_path = _snapshot_from_manifest(payload, snapshot_root)
    return RollbackPlan(
        repository=request.repository,
        service=request.service,
        candidate_sha=request.candidate_sha,
        trusted_ref=request.trusted_ref,
        compose_file=request.compose_file,
        container_name=request.container_name,
        adapter=request.adapter,
        manifest_path=manifest_path,
        snapshot_path=snapshot_path,
        operator=operator,
        reason=reason,
    )


def confirmation_for(plan: RollbackPlan) -> str:
    """Return the literal confirmation required for a validated rollback plan."""

    if not isinstance(plan, RollbackPlan):
        raise RollbackError("rollback plan is invalid")
    return f"ROLLBACK {plan.service} {plan.candidate_sha}"
