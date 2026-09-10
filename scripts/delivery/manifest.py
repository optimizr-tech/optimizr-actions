"""Write a sanitized manifest for one provider-neutral delivery result."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import datetime as dt
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import tempfile
from typing import Any

from .executor import DeliveryExecutorResult
from .gate_evidence import (
    GateEvidence,
    GateEvidenceError,
    GateEvaluation,
    evaluate_gate_evidence,
)
from .request import RequestError, canonicalize_request, parse_request
from .snapshot_sync import SyncResult


class DeliveryManifestError(ValueError):
    """Raised when a delivery result cannot be recorded safely."""


SHA_RE = re.compile(r"^[0-9a-f]{40}$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
SNAPSHOT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*\.tar\.gz$")
SECRET_LIKE_RE = re.compile(
    r"(?i)(?:password|passwd|secret|token|authorization|cookie|"
    r"private[_ .-]?key)\s*[:=]|-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"
)
IMAGE_KEYS = frozenset({"image", "digest"})


@dataclass(frozen=True)
class DeliveryManifestSpec:
    """Explicit metadata and destination for one immutable delivery manifest."""

    result: DeliveryExecutorResult
    path: Path
    environment: str
    workflow: str
    run_id: str
    actor: str
    runner_name: str
    images: Sequence[Mapping[str, str]] = ()
    rollback_of: str | None = None
    now: dt.datetime | None = None


def _scalar(name: str, value: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise DeliveryManifestError(f"{name} must be a string")
    if not allow_empty and not value:
        raise DeliveryManifestError(f"{name} must not be empty")
    if "\n" in value or "\r" in value:
        raise DeliveryManifestError(f"{name} must be single-line")
    if len(value) > 512:
        raise DeliveryManifestError(f"{name} exceeds 512 characters")
    if SECRET_LIKE_RE.search(value):
        raise DeliveryManifestError(f"{name} contains prohibited secret-like data")
    return value


def _reject_symlink_components(path: Path) -> None:
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        if current.exists() and current.is_symlink():
            raise DeliveryManifestError("manifest path must not contain symlink components")


def _manifest_path(path: Path) -> Path:
    if not isinstance(path, Path) or not path.is_absolute():
        raise DeliveryManifestError("manifest path must be absolute")
    if path.parent == path:
        raise DeliveryManifestError("manifest path must not be a filesystem root")
    _reject_symlink_components(path)
    if not path.parent.exists() or not path.parent.is_dir():
        raise DeliveryManifestError("manifest parent must be an existing directory")
    if path.exists():
        raise DeliveryManifestError("manifest path already exists")
    return path


def _validate_result(result: DeliveryExecutorResult) -> tuple[dict[str, str], list[dict[str, str]]]:
    if not isinstance(result, DeliveryExecutorResult):
        raise DeliveryManifestError("delivery result is invalid")
    try:
        request = parse_request(result.request)
    except (RequestError, TypeError, ValueError) as exc:
        raise DeliveryManifestError("delivery result request is invalid") from exc
    if canonicalize_request(request) != result.request:
        raise DeliveryManifestError("delivery result request is not canonical")
    if result.head_sha != request.candidate_sha or not SHA_RE.fullmatch(result.head_sha):
        raise DeliveryManifestError("delivery result SHA does not match the request")
    if result.trusted_ref != request.trusted_ref:
        raise DeliveryManifestError("delivery result trusted ref does not match the request")
    if not isinstance(result.preflight, GateEvaluation) or (
        result.postflight is not None and not isinstance(result.postflight, GateEvaluation)
    ):
        raise DeliveryManifestError("delivery result gate evaluation is invalid")
    expected_ready = result.preflight.passed and result.postflight is not None and result.postflight.passed
    if result.ready != expected_ready:
        raise DeliveryManifestError("delivery result ready state is inconsistent")
    expected_evidence = (
        *result.preflight.evidence,
        *(result.postflight.evidence if result.postflight is not None else ()),
    )
    if tuple(result.evidence) != expected_evidence:
        raise DeliveryManifestError("delivery result evidence is inconsistent")
    evidence: list[dict[str, str]] = []
    for entry in result.evidence:
        if not isinstance(entry, Mapping):
            raise DeliveryManifestError("delivery evidence must be objects")
        try:
            gate = GateEvidence(**dict(entry))
            checked = evaluate_gate_evidence([gate], required_gates=(gate.name,))
        except (GateEvidenceError, TypeError) as exc:
            raise DeliveryManifestError("delivery evidence is invalid") from exc
        if not checked.evidence or checked.evidence[0] != dict(entry):
            raise DeliveryManifestError("delivery evidence is not canonical")
        evidence.append(dict(entry))
    if result.postflight is None and result.sync is not None:
        raise DeliveryManifestError("failed preflight cannot contain synchronization")
    if result.sync is not None:
        if not isinstance(result.sync, SyncResult):
            raise DeliveryManifestError("delivery synchronization result is invalid")
        if not all(isinstance(value, bool) for value in (
            result.sync.changed,
            result.sync.snapshot_created,
            result.sync.synced,
        )):
            raise DeliveryManifestError("delivery synchronization flags are invalid")
        if (
            isinstance(result.sync.changed_entries, bool)
            or not isinstance(result.sync.changed_entries, int)
            or result.sync.changed_entries < 0
        ):
            raise DeliveryManifestError("delivery synchronization count is invalid")
        if result.sync.snapshot_name is not None and not SNAPSHOT_RE.fullmatch(
            result.sync.snapshot_name
        ):
            raise DeliveryManifestError("delivery synchronization snapshot is invalid")
        if result.sync.synced and not result.sync.changed:
            raise DeliveryManifestError("delivery synchronization state is inconsistent")
    if result.failure_reason is not None:
        _scalar("failure_reason", result.failure_reason)
    if result.ready and result.failure_reason is not None:
        raise DeliveryManifestError("ready delivery cannot contain a failure reason")
    return canonicalize_request(request), evidence


def _validate_images(images: Sequence[Mapping[str, str]]) -> list[dict[str, str]]:
    try:
        entries = tuple(images)
    except TypeError as exc:
        raise DeliveryManifestError("images must be a sequence") from exc
    validated: list[dict[str, str]] = []
    for image in entries:
        if not isinstance(image, Mapping) or set(image) != IMAGE_KEYS:
            raise DeliveryManifestError("each image requires exactly image and digest")
        name = _scalar("image", image["image"])
        digest = _scalar("digest", image["digest"])
        if digest != "unknown" and not DIGEST_RE.fullmatch(digest):
            raise DeliveryManifestError("image digest must be unknown or an immutable SHA-256")
        validated.append({"image": name, "digest": digest})
    return validated


def _timestamp(value: dt.datetime | None) -> str:
    now = value or dt.datetime.now(dt.timezone.utc)
    if not isinstance(now, dt.datetime):
        raise DeliveryManifestError("now must be a datetime")
    if now.tzinfo is None or now.utcoffset() is None:
        raise DeliveryManifestError("now must be timezone-aware")
    return now.astimezone(dt.timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def _write_atomic(path: Path, content: bytes) -> None:
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        os.chmod(temporary, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    finally:
        if temporary.exists():
            temporary.unlink()


def write_delivery_manifest(spec: DeliveryManifestSpec) -> Path:
    """Atomically write one sanitized, immutable manifest for a delivery result."""

    if not isinstance(spec, DeliveryManifestSpec):
        raise DeliveryManifestError("manifest specification is invalid")
    path = _manifest_path(spec.path)
    request, evidence = _validate_result(spec.result)
    payload: dict[str, Any] = {
        "schema_version": 1,
        "generated_at": _timestamp(spec.now),
        "status": "success" if spec.result.ready else "failure",
        "ready": spec.result.ready,
        "repository": request["repository"],
        "service": request["service"],
        "candidate_sha": request["candidate_sha"],
        "trusted_ref": request["trusted_ref"],
        "adapter": request["adapter"],
        "compose_file": request["compose_file"],
        "container_name": request["container_name"],
        "environment": _scalar("environment", spec.environment),
        "workflow": _scalar("workflow", spec.workflow),
        "run_id": _scalar("run_id", spec.run_id),
        "actor": _scalar("actor", spec.actor),
        "runner_name": _scalar("runner_name", spec.runner_name),
        "images": _validate_images(spec.images),
        "gates": evidence,
        "rollback_of": (
            _scalar("rollback_of", spec.rollback_of)
            if spec.rollback_of is not None
            else None
        ),
        "failure_reason": (
            _scalar("failure_reason", spec.result.failure_reason)
            if spec.result.failure_reason is not None
            else None
        ),
    }
    sync = spec.result.sync
    payload["sync"] = (
        {
            "changed": sync.changed,
            "changed_entries": sync.changed_entries,
            "snapshot_created": sync.snapshot_created,
            "snapshot_name": sync.snapshot_name,
            "synced": sync.synced,
        }
        if sync is not None
        else None
    )
    content = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
    _write_atomic(path, content)
    return path
