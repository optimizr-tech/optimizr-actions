"""Apply a reviewed, expiring vulnerability baseline to a Trivy JSON report."""

from __future__ import annotations

import argparse
from copy import deepcopy
from datetime import date, datetime, timezone
import json
from pathlib import Path
import sys
from typing import Any, Mapping, Sequence


class BaselineError(ValueError):
    """Raised when a reviewed vulnerability baseline is invalid."""


def _load_json(path: Path, label: str) -> Mapping[str, Any]:
    if not path.is_file() or path.is_symlink():
        raise BaselineError(f"{label} must be a regular non-symlink file")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BaselineError(f"{label} must be valid UTF-8 JSON") from exc
    if not isinstance(payload, Mapping):
        raise BaselineError(f"{label} must be a JSON object")
    return payload


def _required_text(payload: Mapping[str, Any], field: str) -> str:
    value = payload.get(field)
    if not isinstance(value, str) or not value.strip():
        raise BaselineError(f"baseline field {field} is required")
    return value.strip()


def _finding_fingerprint(target: str, finding: Mapping[str, Any]) -> tuple[str, ...]:
    fields = (
        str(target or "").strip(),
        str(finding.get("VulnerabilityID") or "").strip(),
        str(finding.get("PkgName") or "").strip(),
        str(finding.get("InstalledVersion") or "").strip(),
        str(finding.get("FixedVersion") or "").strip(),
    )
    if any(not value for value in fields):
        raise BaselineError("Trivy vulnerability is missing baseline fingerprint fields")
    return fields


def _baseline_fingerprint(entry: Mapping[str, Any], index: int) -> tuple[str, ...]:
    names = ("target", "id", "package", "installed_version", "fixed_version")
    values: list[str] = []
    for name in names:
        value = entry.get(name)
        if not isinstance(value, str) or not value.strip():
            raise BaselineError(f"baseline findings[{index}].{name} is required")
        values.append(value.strip())
    return tuple(values)


def _atomic_write(path: Path, payload: Mapping[str, Any]) -> None:
    if path.is_symlink():
        raise BaselineError(f"output must not be a symlink: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def apply_baseline(
    report_path: Path,
    baseline_path: Path,
    output_path: Path,
    summary_path: Path,
    *,
    today: date | None = None,
) -> dict[str, Any]:
    """Remove only exact reviewed fingerprints and return bounded baseline state."""
    report = _load_json(report_path, "Trivy report")
    baseline = _load_json(baseline_path, "baseline")
    if baseline.get("version") != 1:
        raise BaselineError("baseline version must be 1")

    owner = _required_text(baseline, "owner")
    reviewed_at_text = _required_text(baseline, "reviewed_at")
    expires_text = _required_text(baseline, "expires")
    statement = _required_text(baseline, "statement")
    control = _required_text(baseline, "compensating_control")
    try:
        reviewed_at = date.fromisoformat(reviewed_at_text)
        expires = date.fromisoformat(expires_text)
    except ValueError as exc:
        raise BaselineError("baseline dates must use YYYY-MM-DD") from exc
    reference = today or datetime.now(timezone.utc).date()
    if reviewed_at > reference:
        raise BaselineError("baseline reviewed_at must not be in the future")
    if expires < reference:
        raise BaselineError(f"baseline expired on {expires_text}")

    raw_findings = baseline.get("findings")
    if not isinstance(raw_findings, list) or not raw_findings:
        raise BaselineError("baseline findings must be a non-empty array")
    approved: set[tuple[str, ...]] = set()
    for index, item in enumerate(raw_findings):
        if not isinstance(item, Mapping):
            raise BaselineError(f"baseline findings[{index}] must be an object")
        fingerprint = _baseline_fingerprint(item, index)
        if fingerprint in approved:
            raise BaselineError(f"duplicate baseline fingerprint at findings[{index}]")
        approved.add(fingerprint)

    filtered = deepcopy(report)
    raw_results = filtered.get("Results", [])
    if raw_results is None:
        raw_results = []
        filtered["Results"] = raw_results
    if not isinstance(raw_results, list):
        raise BaselineError("Trivy Results must be an array")

    matched: set[tuple[str, ...]] = set()
    remaining = 0
    for result in raw_results:
        if not isinstance(result, dict):
            raise BaselineError("Trivy Results entries must be objects")
        target = str(result.get("Target") or "").strip()
        vulnerabilities = result.get("Vulnerabilities", []) or []
        if not isinstance(vulnerabilities, list):
            raise BaselineError("Trivy Vulnerabilities must be an array")
        retained: list[Mapping[str, Any]] = []
        for finding in vulnerabilities:
            if not isinstance(finding, Mapping):
                raise BaselineError("Trivy vulnerability entries must be objects")
            fingerprint = _finding_fingerprint(target, finding)
            if fingerprint in approved:
                matched.add(fingerprint)
            else:
                retained.append(finding)
        result["Vulnerabilities"] = retained
        remaining += len(retained)

        for field in ("Misconfigurations", "Secrets"):
            findings = result.get(field, []) or []
            if not isinstance(findings, list):
                raise BaselineError(f"Trivy {field} must be an array")
            remaining += len(findings)

    stale = approved - matched
    if stale:
        raise BaselineError(
            f"baseline contains {len(stale)} fingerprint(s) absent from the current report"
        )

    summary = {
        "schema_version": 1,
        "status": "validated",
        "owner": owner,
        "reviewed_at": reviewed_at_text,
        "expires": expires_text,
        "statement": statement,
        "compensating_control": control,
        "approved": len(approved),
        "matched": len(matched),
        "remaining": remaining,
    }
    _atomic_write(output_path, filtered)
    _atomic_write(summary_path, summary)
    return summary


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--summary-output", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        result = apply_baseline(
            args.report,
            args.baseline,
            args.output,
            args.summary_output,
        )
        print(
            "::notice title=Reviewed vulnerability baseline::"
            f"matched={result['matched']} remaining={result['remaining']} "
            f"expires={result['expires']}"
        )
        return 0 if result["remaining"] == 0 else 1
    except (BaselineError, OSError, KeyError) as exc:
        print(f"security baseline error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
