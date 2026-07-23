"""Classify one bounded image-remediation retry without promoting stale images."""

from __future__ import annotations

import os
import re
from typing import TypedDict


_CLASSIFICATIONS = {
    "clean",
    "actionable_vulnerability",
    "unfixed_warning",
    "misconfiguration_detected",
    "secret_detected",
    "scanner_error",
}
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


def _classification(raw: str) -> str:
    if raw == "gate_error":
        return "scanner_error"
    return raw if raw in _CLASSIFICATIONS else "scanner_error"


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
        return {
            "initial_result": initial,
            "rebuild_attempted": attempted,
            "rebuild_result": "failed" if attempted else "skipped",
            "final_result": "scanner_error",
            "passed": False,
            **initial_evidence,
        }

    if initial_outcome == "success":
        if initial not in {"clean", "unfixed_warning"} or not before:
            return {
                "initial_result": initial,
                "rebuild_attempted": False,
                "rebuild_result": "skipped",
                "final_result": "scanner_error",
                "passed": False,
                **initial_evidence,
            }
        return {
            "initial_result": initial,
            "rebuild_attempted": False,
            "rebuild_result": "skipped",
            "final_result": initial,
            "passed": True,
            **initial_evidence,
        }

    if initial != "actionable_vulnerability" or not retry_enabled:
        return {
            "initial_result": initial,
            "rebuild_attempted": False,
            "rebuild_result": "skipped",
            "final_result": initial,
            "passed": False,
            **initial_evidence,
        }

    if rebuild_outcome != "success":
        return {
            "initial_result": initial,
            "rebuild_attempted": True,
            "rebuild_result": "failed",
            "final_result": "scanner_error",
            "passed": False,
            **initial_evidence,
        }

    if not before or not after:
        return {
            "initial_result": initial,
            "rebuild_attempted": True,
            "rebuild_result": "failed",
            "final_result": "scanner_error",
            "passed": False,
            **initial_evidence,
        }
    if before == after:
        return {
            "initial_result": initial,
            "rebuild_attempted": True,
            "rebuild_result": "no_change",
            "final_result": initial,
            "passed": False,
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
            **final_evidence,
        }

    return {
        "initial_result": initial,
        "rebuild_attempted": True,
        "rebuild_result": "failed",
        "final_result": final,
        "passed": False,
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
        *_COUNT_KEYS,
    ):
        value = str(result[key]).lower() if isinstance(result[key], bool) else result[key]
        print(f"{key}={value}")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
