"""Build sanitized output from ZAP baseline JSON reports."""

from __future__ import annotations

import html
import json
import os
from pathlib import Path
import re
import sys


ROOT = Path.cwd()
RAW = ROOT / ".dast-baseline" / "raw"
REPORTS = ROOT / ".dast-baseline" / "reports"
LEVELS = {"3": "high", "2": "medium", "1": "low", "0": "informational"}
ORDER = ("high", "medium", "low", "informational")
THRESHOLDS = {"high": 3, "medium": 2, "low": 1, "informational": 0}


def configured_rules(path: str) -> dict[str, str]:
    result: dict[str, str] = {}
    if not path:
        return result
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        fields = re.split(r"\s+", line.strip(), maxsplit=2)
        if len(fields) >= 2 and fields[0].isdigit() and fields[1] in {"IGNORE", "WARN", "FAIL"}:
            result[fields[0]] = fields[1]
    return result


def main() -> int:
    REPORTS.mkdir(parents=True, exist_ok=True)
    threshold = os.environ.get("FAIL_ON", "high").lower()
    if threshold not in THRESHOLDS:
        raise SystemExit("fail_on must be high, medium, low, or informational")
    overrides = configured_rules(os.environ.get("RULES_FILE", ""))
    counts = {level: 0 for level in ORDER}
    findings: list[dict[str, object]] = []
    gate_failed = os.environ.get("SCANNER_FAILED") == "1"

    report_files = sorted(RAW.glob("raw-*.json"))
    if not report_files:
        gate_failed = True
    for report in report_files:
        data = json.loads(report.read_text(encoding="utf-8"))
        sites = data.get("site", [])
        if isinstance(sites, dict):
            sites = [sites]
        for site in sites:
            for alert in site.get("alerts", []):
                plugin_id = str(alert.get("pluginId", "unknown"))
                configured = overrides.get(plugin_id)
                if configured == "IGNORE":
                    continue
                risk_code = str(alert.get("riskcode", "0"))
                try:
                    numeric_risk = int(risk_code)
                except ValueError:
                    numeric_risk = 0
                level = LEVELS.get(str(numeric_risk), "informational")
                counts[level] += 1
                findings.append({
                    "rule_id": plugin_id,
                    "name": str(alert.get("name", "Unknown alert"))[:200],
                    "risk": level,
                    "instances": len(alert.get("instances", [])),
                })
                if configured == "FAIL" or (
                    configured != "WARN" and numeric_risk >= THRESHOLDS[threshold]
                ):
                    gate_failed = True

    payload = {"schema_version": 1, "counts": counts, "findings": findings}
    (REPORTS / "report.json").write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    rows = "\n".join(
        f"<tr><td>{html.escape(str(item['risk']))}</td><td>{html.escape(str(item['rule_id']))}</td>"
        f"<td>{html.escape(str(item['name']))}</td><td>{item['instances']}</td></tr>"
        for item in findings
    )
    page = (
        "<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><title>Sanitized ZAP baseline</title>"
        "<h1>Sanitized ZAP baseline</h1><ul>"
        + "".join(f"<li>{level}: {counts[level]}</li>" for level in ORDER)
        + "</ul><table><thead><tr><th>Risk</th><th>Rule</th><th>Alert</th><th>Instances</th></tr></thead>"
        f"<tbody>{rows}</tbody></table></html>\n"
    )
    (REPORTS / "report.html").write_text(page, encoding="utf-8")

    summary = Path(os.environ.get("GITHUB_STEP_SUMMARY", ".dast-baseline/summary.md"))
    summary.parent.mkdir(parents=True, exist_ok=True)
    summary.write_text(
        "## Passive DAST baseline\n\n"
        + "\n".join(f"- {level.title()}: {counts[level]}" for level in ORDER)
        + f"\n- Gate threshold: {threshold}\n- Scanner error: {'yes' if os.environ.get('SCANNER_FAILED') == '1' else 'no'}\n",
        encoding="utf-8",
    )
    with open(os.environ.get("GITHUB_OUTPUT", ".dast-baseline/outputs.txt"), "a", encoding="utf-8") as output:
        for level, count in counts.items():
            output.write(f"{level}_count={count}\n")
    return 1 if gate_failed else 0


if __name__ == "__main__":
    sys.exit(main())
