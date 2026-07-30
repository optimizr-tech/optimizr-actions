"""Validate immutable remediation-window lifecycle revisions."""

from __future__ import annotations

from datetime import datetime, timezone
import re
from typing import Any, Mapping

_RFC3339_Z = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")
_ALLOWED_ENTRY_STATUSES = {"active", "resolved", "reintroduced"}
_ALLOWED_HISTORY_ACTIONS = {"extended", "resolved", "reintroduced"}


class RemediationLifecycleError(ValueError):
    """Raised when lifecycle history can reset or contradict reviewed state."""


def _required_text(payload: Mapping[str, Any], field: str, *, label: str) -> str:
    value = payload.get(field)
    if not isinstance(value, str) or not value.strip():
        raise RemediationLifecycleError(f"{label} field {field} is required")
    return value.strip()


def _parse_utc(text: str, *, label: str) -> datetime:
    if not isinstance(text, str) or _RFC3339_Z.fullmatch(text) is None:
        raise RemediationLifecycleError(f"{label} must use RFC3339 UTC timestamps")
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise RemediationLifecycleError(f"{label} must use RFC3339 UTC timestamps") from exc
    return parsed.astimezone(timezone.utc)


def _format_utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def normalize_lifecycle(
    entry: Mapping[str, Any],
    *,
    first_seen: datetime,
    original_deadline: datetime,
    reference: datetime,
) -> dict[str, Any]:
    """Return normalized immutable lifecycle state for one reviewed policy entry."""
    status = _required_text(entry, "status", label="policy entry")
    if status not in _ALLOWED_ENTRY_STATUSES:
        raise RemediationLifecycleError("policy entry status is not allowed")

    raw_history = entry.get("history")
    if raw_history is None:
        if status != "active":
            raise RemediationLifecycleError(
                "resolved or reintroduced status requires explicit history"
            )
        return {
            "status": "active",
            "original_deadline_at": _format_utc(original_deadline),
            "effective_deadline_at": _format_utc(original_deadline),
            "history": [],
            "revision_count": 0,
        }
    if not isinstance(raw_history, list) or not raw_history:
        raise RemediationLifecycleError("policy entry history must be a non-empty array")

    tracked_deadline = original_deadline
    tracked_status = "active"
    previous_reviewed_at: datetime | None = None
    history: list[dict[str, str]] = []
    for index, revision in enumerate(raw_history):
        if not isinstance(revision, Mapping):
            raise RemediationLifecycleError(f"policy entry history[{index}] must be an object")
        label = f"history[{index}]"
        action = _required_text(revision, "action", label=label)
        if action not in _ALLOWED_HISTORY_ACTIONS:
            raise RemediationLifecycleError(f"{label}.action is not allowed")
        revision_first_seen = _parse_utc(
            _required_text(revision, "first_seen_at", label=label),
            label=f"{label}.first_seen_at",
        )
        previous_deadline = _parse_utc(
            _required_text(revision, "previous_deadline_at", label=label),
            label=f"{label}.previous_deadline_at",
        )
        deadline = _parse_utc(
            _required_text(revision, "deadline_at", label=label),
            label=f"{label}.deadline_at",
        )
        reviewed_at = _parse_utc(
            _required_text(revision, "reviewed_at", label=label),
            label=f"{label}.reviewed_at",
        )
        reviewed_by = _required_text(revision, "reviewed_by", label=label)
        reason = _required_text(revision, "reason", label=label)

        if revision_first_seen != first_seen:
            raise RemediationLifecycleError("policy entry history must preserve first_seen_at")
        if previous_deadline != tracked_deadline:
            raise RemediationLifecycleError(
                "policy entry history previous deadline must match prior state"
            )
        if reviewed_at > reference:
            raise RemediationLifecycleError(
                "policy entry history reviewed_at must not be in the future"
            )
        if previous_reviewed_at is not None and reviewed_at <= previous_reviewed_at:
            raise RemediationLifecycleError(
                "policy entry history reviews must be strictly chronological"
            )

        if action == "extended":
            if tracked_status != "active":
                raise RemediationLifecycleError("only an active policy entry may be extended")
            if deadline <= previous_deadline:
                raise RemediationLifecycleError(
                    "extended deadline must be after previous deadline"
                )
            tracked_deadline = deadline
        elif action == "resolved":
            if tracked_status != "active":
                raise RemediationLifecycleError("only an active policy entry may be resolved")
            if deadline != previous_deadline:
                raise RemediationLifecycleError(
                    "resolved revision must preserve the deadline"
                )
            tracked_status = "resolved"
        else:
            if tracked_status != "resolved":
                raise RemediationLifecycleError(
                    "reintroduced revision must follow resolved state"
                )
            if deadline != previous_deadline:
                raise RemediationLifecycleError(
                    "reintroduced revision must preserve the deadline"
                )
            tracked_status = "reintroduced"

        previous_reviewed_at = reviewed_at
        history.append(
            {
                "action": action,
                "first_seen_at": _format_utc(revision_first_seen),
                "previous_deadline_at": _format_utc(previous_deadline),
                "deadline_at": _format_utc(deadline),
                "reviewed_at": _format_utc(reviewed_at),
                "reviewed_by": reviewed_by,
                "reason": reason,
            }
        )

    if tracked_status != status:
        raise RemediationLifecycleError(
            "policy status must match the final history action"
        )
    return {
        "status": status,
        "original_deadline_at": _format_utc(original_deadline),
        "effective_deadline_at": _format_utc(tracked_deadline),
        "history": history,
        "revision_count": len(history),
    }
