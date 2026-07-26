"""Canonical security classifications shared by deploy actions and evidence."""

from __future__ import annotations

from typing import Final


SECURITY_CLASSIFICATIONS: Final[frozenset[str]] = frozenset(
    {
        "clean",
        "actionable_vulnerability",
        "unfixed_warning",
        "misconfiguration_detected",
        "secret_detected",
        "scanner_error",
        "not-run",
    }
)
SECURITY_CLASSIFICATION_INPUTS: Final[frozenset[str]] = SECURITY_CLASSIFICATIONS | {
    "gate_error"
}
_ALIASES: Final[dict[str, str]] = {"gate_error": "scanner_error"}


def normalize_security_classification(raw: str) -> str:
    """Return a canonical classification while accepting legacy aliases."""
    if raw in SECURITY_CLASSIFICATIONS:
        return raw
    if raw in _ALIASES:
        return _ALIASES[raw]
    raise ValueError("security classification is not allowed")
