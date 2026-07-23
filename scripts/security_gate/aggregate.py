"""Aggregate sanitized Trivy summaries into GitHub Action outputs."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any, Mapping, Sequence


class AggregateError(ValueError):
    """Raised when sanitized security summaries violate the contract."""


def _non_negative_int(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise AggregateError(f"{field} must be a non-negative integer")
    return value


def _load_summary(path: Path) -> Mapping[str, Any]:
    if not path.is_file() or path.is_symlink():
        raise AggregateError("summary must be a regular non-symlink file")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AggregateError("summary must be valid UTF-8 JSON") from exc
    if not isinstance(payload, Mapping):
        raise AggregateError("summary must be a JSON object")
    if payload.get("schema_version") != 1:
        raise AggregateError("unsupported summary schema version")
    return payload


def aggregate_summaries(
    paths: Sequence[Path], *, gate_error: bool = False
) -> dict[str, Any]:
    """Combine bounded count-only summaries into one deployment classification."""
    if not paths:
        raise AggregateError("at least one summary is required")

    totals = {
        "fixable_vulnerability_count": 0,
        "unfixed_vulnerability_count": 0,
        "misconfiguration_count": 0,
        "secret_count": 0,
    }
    for path in paths:
        payload = _load_summary(path)
        vulnerabilities = payload.get("vulnerabilities")
        if not isinstance(vulnerabilities, Mapping):
            raise AggregateError("vulnerabilities must be an object")
        totals["fixable_vulnerability_count"] += _non_negative_int(
            vulnerabilities.get("fixable"), "vulnerabilities.fixable"
        )
        totals["unfixed_vulnerability_count"] += _non_negative_int(
            vulnerabilities.get("unfixed"), "vulnerabilities.unfixed"
        )
        totals["misconfiguration_count"] += _non_negative_int(
            payload.get("misconfigurations"), "misconfigurations"
        )
        totals["secret_count"] += _non_negative_int(
            payload.get("secrets"), "secrets"
        )

    if gate_error:
        classification = "scanner_error"
    elif totals["secret_count"]:
        classification = "secret_detected"
    elif totals["misconfiguration_count"]:
        classification = "misconfiguration_detected"
    elif totals["fixable_vulnerability_count"]:
        classification = "actionable_vulnerability"
    elif totals["unfixed_vulnerability_count"]:
        classification = "unfixed_warning"
    else:
        classification = "clean"

    return {"classification": classification, **totals}


def _write_github_output(path: Path, aggregate: Mapping[str, Any]) -> None:
    if path.is_symlink():
        raise AggregateError("GitHub output must not be a symlink")
    with path.open("a", encoding="utf-8") as handle:
        for key in (
            "classification",
            "fixable_vulnerability_count",
            "unfixed_vulnerability_count",
            "misconfiguration_count",
            "secret_count",
        ):
            handle.write(f"{key}={aggregate[key]}\n")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--summary", action="append", type=Path, required=True)
    parser.add_argument("--github-output", type=Path, required=True)
    parser.add_argument("--gate-error", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        aggregate = aggregate_summaries(args.summary, gate_error=args.gate_error)
        _write_github_output(args.github_output, aggregate)
        return 0
    except (AggregateError, OSError, KeyError) as exc:
        print(f"security summary aggregate error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
