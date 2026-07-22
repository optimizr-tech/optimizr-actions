"""Classify one bounded image-remediation retry without promoting stale images."""

from __future__ import annotations

import os
from typing import TypedDict


_CLASSIFICATIONS = {
    "clean",
    "actionable_vulnerability",
    "unfixed_warning",
    "gate_error",
}


class RetryResult(TypedDict):
    initial_result: str
    rebuild_attempted: bool
    rebuild_result: str
    final_result: str
    passed: bool


def _classification(raw: str) -> str:
    return raw if raw in _CLASSIFICATIONS else "gate_error"


def _refs(raw: str) -> frozenset[str]:
    return frozenset(ref.strip() for ref in raw.splitlines() if ref.strip())


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
) -> RetryResult:
    """Return sanitized retry evidence and whether the candidate may promote.

    A successful Compose command establishes only command execution. Remediation
    succeeds only when the immutable image set changed and its final security
    gate passed.
    """
    initial = _classification(initial_classification)
    if initial_outcome == "success":
        return {
            "initial_result": initial,
            "rebuild_attempted": False,
            "rebuild_result": "skipped",
            "final_result": initial,
            "passed": True,
        }

    if initial != "actionable_vulnerability" or not retry_enabled:
        return {
            "initial_result": initial,
            "rebuild_attempted": False,
            "rebuild_result": "skipped",
            "final_result": initial,
            "passed": False,
        }

    if rebuild_outcome != "success":
        return {
            "initial_result": initial,
            "rebuild_attempted": True,
            "rebuild_result": "failed",
            "final_result": "gate_error",
            "passed": False,
        }

    before = _refs(initial_refs)
    after = _refs(remediated_refs)
    if not before or not after:
        return {
            "initial_result": initial,
            "rebuild_attempted": True,
            "rebuild_result": "failed",
            "final_result": "gate_error",
            "passed": False,
        }
    if before == after:
        return {
            "initial_result": initial,
            "rebuild_attempted": True,
            "rebuild_result": "no_change",
            "final_result": initial,
            "passed": False,
        }

    final = _classification(final_classification)
    if final_outcome == "success" and final in {"clean", "unfixed_warning"}:
        return {
            "initial_result": initial,
            "rebuild_attempted": True,
            "rebuild_result": "passed",
            "final_result": final,
            "passed": True,
        }

    return {
        "initial_result": initial,
        "rebuild_attempted": True,
        "rebuild_result": "failed",
        "final_result": final,
        "passed": False,
    }


def _env_bool(name: str) -> bool:
    return os.environ.get(name, "") == "true"


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
    )
    for key in (
        "initial_result",
        "rebuild_attempted",
        "rebuild_result",
        "final_result",
        "passed",
    ):
        value = str(result[key]).lower() if isinstance(result[key], bool) else result[key]
        print(f"{key}={value}")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
