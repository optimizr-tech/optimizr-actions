"""Summarize Trivy findings without exposing vulnerability details."""

from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import sys
from typing import Any, Mapping, Sequence


class TrivyReportError(ValueError):
    """Raised when a Trivy JSON report violates the expected bounded shape."""


def _load_report(path: Path) -> Mapping[str, Any]:
    if not path.is_file() or path.is_symlink():
        raise TrivyReportError("Trivy report must be a regular non-symlink file")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TrivyReportError("Trivy report is not valid UTF-8 JSON") from exc
    if not isinstance(payload, Mapping):
        raise TrivyReportError("Trivy report must be a JSON object")
    return payload


def summarize_trivy_report(report_path: Path) -> dict[str, Any]:
    """Return sanitized counts for actionable and signal-only Trivy findings."""
    report = _load_report(report_path)
    raw_results = report.get("Results", [])
    if raw_results is None:
        raw_results = []
    if not isinstance(raw_results, list):
        raise TrivyReportError("Trivy Results must be an array")

    severities: Counter[str] = Counter()
    fixable = 0
    unfixed = 0
    misconfigurations = 0
    secrets = 0

    for result in raw_results:
        if not isinstance(result, Mapping):
            raise TrivyReportError("Trivy Results entries must be objects")

        vulnerabilities = result.get("Vulnerabilities", []) or []
        if not isinstance(vulnerabilities, list):
            raise TrivyReportError("Trivy Vulnerabilities must be an array")
        for finding in vulnerabilities:
            if not isinstance(finding, Mapping):
                raise TrivyReportError("Trivy vulnerability entries must be objects")
            severity = str(finding.get("Severity") or "UNKNOWN").upper()
            severities[severity] += 1
            fixed_version = finding.get("FixedVersion")
            if isinstance(fixed_version, str) and fixed_version.strip():
                fixable += 1
            else:
                unfixed += 1

        configs = result.get("Misconfigurations", []) or []
        if not isinstance(configs, list):
            raise TrivyReportError("Trivy Misconfigurations must be an array")
        misconfigurations += len(configs)

        secret_findings = result.get("Secrets", []) or []
        if not isinstance(secret_findings, list):
            raise TrivyReportError("Trivy Secrets must be an array")
        secrets += len(secret_findings)

    total = fixable + unfixed
    return {
        "schema_version": 1,
        "vulnerabilities": {
            "total": total,
            "fixable": fixable,
            "unfixed": unfixed,
            "by_severity": dict(sorted(severities.items())),
        },
        "misconfigurations": misconfigurations,
        "secrets": secrets,
        "policy": {
            "fixable_vulnerabilities": "blocking",
            "unfixed_vulnerabilities": "signal-only",
            "misconfigurations": "blocking",
            "secrets": "blocking",
        },
    }


def _atomic_write(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise TrivyReportError("summary output must not be a symlink")
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def _append_github_summary(path: Path, summary: Mapping[str, Any]) -> None:
    vulnerabilities = summary["vulnerabilities"]
    lines = [
        "### Trivy security gate",
        "",
        "| Finding class | Count | Policy |",
        "|---|---:|---|",
        f"| Vulnerabilities with a fix | {vulnerabilities['fixable']} | Blocking |",
        f"| Vulnerabilities without a fix | {vulnerabilities['unfixed']} | Signal only |",
        f"| Misconfigurations | {summary['misconfigurations']} | Blocking |",
        f"| Secrets | {summary['secrets']} | Blocking |",
        "",
    ]
    with path.open("a", encoding="utf-8") as handle:
        handle.write("\n".join(lines))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--github-summary", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        summary = summarize_trivy_report(args.report)
        _atomic_write(args.output, summary)
        if args.github_summary:
            _append_github_summary(args.github_summary, summary)
        unfixed = summary["vulnerabilities"]["unfixed"]
        if unfixed:
            print(
                "::warning title=Trivy vulnerabilities without fixes::"
                f"{unfixed} finding(s) have no available fixed version and are signal-only. "
                "They remain in the complete reports and evidence artifact."
            )
        return 0
    except (TrivyReportError, OSError, KeyError) as exc:
        print(f"Trivy report summary error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
