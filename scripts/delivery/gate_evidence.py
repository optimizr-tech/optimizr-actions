"""Evaluate required delivery gates and emit sanitized evidence."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
import re


class GateEvidenceError(ValueError):
    """Raised when gate evidence is invalid or cannot be evaluated safely."""


DEFAULT_REQUIRED_GATES = (
    "filesystem",
    "compose",
    "security",
    "rollout",
    "health",
)
KNOWN_GATES = frozenset((*DEFAULT_REQUIRED_GATES, "migration", "rollback", "smoke"))
ALLOWED_STATUSES = frozenset(("passed", "failed", "skipped"))
SAFE_NAME_RE = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
SECRET_LIKE_RE = re.compile(
    r"(?i)(?:password|passwd|secret|token|authorization|cookie|"
    r"private[_ .-]?key)\s*[:=]"
    r"|-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"
    r"|\bbearer\s+[A-Za-z0-9._~+/-]+=*"
    r"|(?:^|[/\\])\.env(?:$|[./\\])"
    r"|https?://[^/\s@]+:[^/\s@]+@"
    r"|(?:[?&](?:token|sig|signature|key|secret|password)=[^&\s]+)"
)


@dataclass(frozen=True)
class GateEvidence:
    """Sanitized result supplied by a provider-specific gate runner."""

    name: str
    status: str
    target: str
    reason: str = ""


@dataclass(frozen=True)
class GateEvaluation:
    """Fail-closed decision and evidence safe for a deployment manifest."""

    passed: bool
    failure_reason: str | None
    evidence: tuple[dict[str, str], ...]


def _safe_scalar(name: str, value: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise GateEvidenceError(f"{name} must be a string")
    if not allow_empty and not value:
        raise GateEvidenceError(f"{name} must not be empty")
    if "\n" in value or "\r" in value:
        raise GateEvidenceError(f"{name} must be single-line")
    if len(value) > 512:
        raise GateEvidenceError(f"{name} exceeds 512 characters")
    if SECRET_LIKE_RE.search(value):
        raise GateEvidenceError(f"{name} contains prohibited secret-like data")
    return value


def _validate_gate_name(name: str) -> str:
    if not isinstance(name, str) or not SAFE_NAME_RE.fullmatch(name):
        raise GateEvidenceError("gate names must be bounded lowercase identifiers")
    if name not in KNOWN_GATES:
        raise GateEvidenceError("gate name is not a supported delivery gate")
    return name


def _validate_required_gates(required_gates: Sequence[str]) -> tuple[str, ...]:
    try:
        required = tuple(required_gates)
    except TypeError as exc:
        raise GateEvidenceError("required gates must be a sequence") from exc
    if not required:
        raise GateEvidenceError("at least one required gate must be declared")
    if len(set(required)) != len(required):
        raise GateEvidenceError("required gates must be unique")
    return tuple(_validate_gate_name(name) for name in required)


def _sanitized_evidence(gate: GateEvidence) -> dict[str, str]:
    name = _validate_gate_name(gate.name)
    if gate.status not in ALLOWED_STATUSES:
        raise GateEvidenceError("gate status must be passed, failed or skipped")
    target = _safe_scalar("gate target", gate.target)
    reason = _safe_scalar("gate reason", gate.reason, allow_empty=True)
    result = {"name": name, "status": gate.status, "target": target}
    if reason:
        result["reason"] = reason
    return result


def evaluate_gate_evidence(
    gates: Sequence[GateEvidence],
    *,
    required_gates: Sequence[str] = DEFAULT_REQUIRED_GATES,
) -> GateEvaluation:
    """Require every declared gate and refuse skipped or failed required gates."""

    required = _validate_required_gates(required_gates)
    try:
        entries = tuple(gates)
    except TypeError as exc:
        raise GateEvidenceError("gate evidence must be a sequence") from exc

    evidence_by_name: dict[str, dict[str, str]] = {}
    for gate in entries:
        if not isinstance(gate, GateEvidence):
            raise GateEvidenceError("gate evidence must use GateEvidence values")
        evidence = _sanitized_evidence(gate)
        if evidence["name"] in evidence_by_name:
            raise GateEvidenceError("gate evidence names must be unique")
        evidence_by_name[evidence["name"]] = evidence

    missing = next((name for name in required if name not in evidence_by_name), None)
    if missing is not None:
        return GateEvaluation(
            False,
            f"missing required gate: {missing}",
            tuple(evidence_by_name.values()),
        )

    skipped = next(
        (name for name in required if evidence_by_name[name]["status"] == "skipped"),
        None,
    )
    if skipped is not None:
        return GateEvaluation(
            False,
            f"required gate skipped: {skipped}",
            tuple(evidence_by_name.values()),
        )

    failed = next(
        (
            name
            for name, evidence in evidence_by_name.items()
            if evidence["status"] == "failed"
        ),
        None,
    )
    if failed is not None:
        reason = evidence_by_name[failed].get("reason") or "gate failed"
        return GateEvaluation(
            False,
            f"{failed}: {reason}",
            tuple(evidence_by_name.values()),
        )

    ordered_names = [
        *required,
        *(name for name in evidence_by_name if name not in required),
    ]
    return GateEvaluation(
        True,
        None,
        tuple(evidence_by_name[name] for name in ordered_names),
    )
