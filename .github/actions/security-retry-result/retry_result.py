"""Classify one bounded image-remediation retry without promoting stale images."""

from __future__ import annotations

import os
import re
from pathlib import Path
import sys
from typing import TypedDict

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.security_gate.classifications import (  # noqa: E402
    SECURITY_CLASSIFICATIONS,
    normalize_security_classification,
)

_IMAGE_ID = re.compile(r"sha256:[0-9a-fA-F]{64}\Z")
_COUNT_KEYS = (
    "fixable_vulnerability_count",
    "unfixed_vulnerability_count",
    "misconfiguration_count",
    "secret_count",
)


class RetryResult(TypedDict):
    initial_result: str
    rebuild_attempted: bool
    rebuild_result: str
    final_result: str
    passed: bool
    fixable_vulnerability_count: int
    unfixed_vulnerability_count: int
    misconfiguration_count: int
    secret_count: int
    compatibility_allowed: bool


def _classification(raw: str) -> str:
    try:
        normalized = normalize_security_classification(raw)
    except ValueError:
        return "scanner_error"
    return (
        normalized
        if normalized in SECURITY_CLASSIFICATIONS - {"not-run"}
        else "scanner_error"
    )


def _compatibility_allowed(
    *,
    final_result: str,
    rebuild_attempted: bool,
    rebuild_result: str,
    counts: dict[str, int],
) -> bool:
    """Keep the legacy bypass narrow and explicitly non-security-sensitive."""
    if counts["misconfiguration_count"] or counts["secret_count"]:
        return False
    if (
        final_result == "unfixed_warning"
        and rebuild_result in {"skipped", "no_change"}
        and counts["fixable_vulnerability_count"] == 0
        and counts["unfixed_vulnerability_count"] > 0
    ):
        return True
    return (
        final_result == "actionable_vulnerability"
        and rebuild_attempted
        and rebuild_result == "no_change"
        and counts["fixable_vulnerability_count"] > 0
    )


def _refs(raw: str) -> frozenset[str] | None:
    refs = tuple(ref.strip() for ref in raw.splitlines() if ref.strip())
    if any(_IMAGE_ID.fullmatch(ref) is None for ref in refs):
        return None
    return frozenset(refs)


def _counts(values: tuple[int, int, int, int]) -> dict[str, int]:
    return dict(zip(_COUNT_KEYS, values, strict=True))


def evaluate_retry(
    *,
    initial_outcome: str,
    initial_classification: str,
    rebuild_outcome: str,
    final_outcome: str,
    final_classification: str,
    retry_enabled: bool,
    initial_refs: str,
    remediated_refs: str,
    initial_counts: tuple[int, int, int, int] = (0, 0, 0, 0),
    final_counts: tuple[int, int, int, int] = (0, 0, 0, 0),
) -> RetryResult:
    """Return sanitized retry evidence and whether the candidate may promote."""
    initial = _classification(initial_classification)
    before = _refs(initial_refs)
    after = _refs(remediated_refs)
    initial_evidence = _counts(initial_counts)
    final_evidence = _counts(final_counts)

    if before is None or after is None:
        attempted = initial == "actionable_vulnerability" and retry_enabled
        evidence = initial_evidence
        return {
            "initial_result": initial,
            "rebuild_attempted": attempted,
            "rebuild_result": "failed" if attempted else "skipped",
            "final_result": "scanner_error",
            "passed": False,
            "compatibility_allowed": _compatibility_allowed(
                final_result="scanner_error",
                rebuild_attempted=attempted,
                rebuild_result="failed" if attempted else "skipped",
                counts=evidence,
            ),
            **evidence,
        }

    if initial_outcome == "success":
        if initial not in {"clean", "unfixed_warning"} or not before:
            return {
                "initial_result": initial,
                "rebuild_attempted": False,
                "rebuild_result": "skipped",
                "final_result": "scanner_error",
                "passed": False,
                "compatibility_allowed": False,
                **initial_evidence,
            }
        return {
            "initial_result": initial,
            "rebuild_attempted": False,
            "rebuild_result": "skipped",
            "final_result": initial,
            "passed": True,
            "compatibility_allowed": _compatibility_allowed(
                final_result=initial,
                rebuild_attempted=False,
                rebuild_result="skipped",
                counts=initial_evidence,
            ),
            **initial_evidence,
        }

    if initial != "actionable_vulnerability" or not retry_enabled:
        return {
            "initial_result": initial,
            "rebuild_attempted": False,
            "rebuild_result": "skipped",
            "final_result": initial,
            "passed": False,
            "compatibility_allowed": _compatibility_allowed(
                final_result=initial,
                rebuild_attempted=False,
                rebuild_result="skipped",
                counts=initial_evidence,
            ),
            **initial_evidence,
        }

    if rebuild_outcome != "success":
        return {
            "initial_result": initial,
            "rebuild_attempted": True,
            "rebuild_result": "failed",
            "final_result": "scanner_error",
            "passed": False,
            "compatibility_allowed": False,
            **initial_evidence,
        }

    if not before or not after:
        return {
            "initial_result": initial,
            "rebuild_attempted": True,
            "rebuild_result": "failed",
            "final_result": "scanner_error",
            "passed": False,
            "compatibility_allowed": False,
            **initial_evidence,
        }
    if before == after:
        return {
            "initial_result": initial,
            "rebuild_attempted": True,
            "rebuild_result": "no_change",
            "final_result": initial,
            "passed": False,
            "compatibility_allowed": _compatibility_allowed(
                final_result=initial,
                rebuild_attempted=True,
                rebuild_result="no_change",
                counts=initial_evidence,
            ),
            **initial_evidence,
        }

    final = _classification(final_classification)
    if final_outcome == "success" and final in {"clean", "unfixed_warning"}:
        return {
            "initial_result": initial,
            "rebuild_attempted": True,
            "rebuild_result": "passed",
            "final_result": final,
            "passed": True,
            "compatibility_allowed": _compatibility_allowed(
                final_result=final,
                rebuild_attempted=True,
                rebuild_result="passed",
                counts=final_evidence,
            ),
            **final_evidence,
        }

    return {
        "initial_result": initial,
        "rebuild_attempted": True,
        "rebuild_result": "failed",
        "final_result": final,
        "passed": False,
        "compatibility_allowed": _compatibility_allowed(
            final_result=final,
            rebuild_attempted=True,
            rebuild_result="failed",
            counts=final_evidence,
        ),
        **final_evidence,
    }


def _env_bool(name: str) -> bool:
    return os.environ.get(name, "") == "true"


def _env_count(name: str) -> int:
    raw = os.environ.get(name, "0")
    try:
        value = int(raw)
    except ValueError:
        return 0
    return value if value >= 0 else 0


def _env_counts(prefix: str) -> tuple[int, int, int, int]:
    return tuple(
        _env_count(f"{prefix}_{name.upper()}") for name in _COUNT_KEYS
    )  # type: ignore[return-value]


def main() -> int:
    result = evaluate_retry(
        initial_outcome=os.environ.get("INITIAL_OUTCOME", ""),
        initial_classification=os.environ.get("INITIAL_CLASSIFICATION", ""),
        rebuild_outcome=os.environ.get("REBUILD_OUTCOME", ""),
        final_outcome=os.environ.get("FINAL_OUTCOME", ""),
        final_classification=os.environ.get("FINAL_CLASSIFICATION", ""),
        retry_enabled=_env_bool("RETRY_ENABLED"),
        initial_refs=os.environ.get("INITIAL_REFS", ""),
        remediated_refs=os.environ.get("REMEDIATED_REFS", ""),
        initial_counts=_env_counts("INITIAL"),
        final_counts=_env_counts("FINAL"),
    )
    for key in (
        "initial_result",
        "rebuild_attempted",
        "rebuild_result",
        "final_result",
        "passed",
        "compatibility_allowed",
        *_COUNT_KEYS,
    ):
        value = str(result[key]).lower() if isinstance(result[key], bool) else result[key]
        print(f"{key}={value}")
    # This action classifies and publishes evidence; the caller enforces it.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
