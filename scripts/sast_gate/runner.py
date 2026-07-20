#!/usr/bin/env python3
"""Run controlled local Semgrep profiles with expiring exact baselines."""

from __future__ import annotations

import argparse
from datetime import date, datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import re
from typing import Any, Iterable, Sequence

PROFILES = {
    "python": ["python.yml"],
    "typescript": ["typescript.yml"],
    "all": ["python.yml", "typescript.yml"],
}


class SastError(ValueError):
    """Raised when a SAST profile, baseline, or report is invalid."""


def profile_configs(profile: str) -> list[str]:
    if profile not in PROFILES:
        raise SastError(f"profile must be one of: {', '.join(PROFILES)}")
    return list(PROFILES[profile])


def _read_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SastError(f"invalid JSON file {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise SastError(f"JSON root must be an object: {path}")
    return data


def load_baseline(path: Path | None, today: str | None = None) -> set[tuple[str, str, str]]:
    if path is None:
        return set()
    data = _read_json(path)
    if data.get("version") != 1 or not isinstance(data.get("findings"), list):
        raise SastError("baseline must use version 1 and contain a findings array")
    current = date.fromisoformat(today) if today else datetime.now(timezone.utc).date()
    result: set[tuple[str, str, str]] = set()
    for entry in data["findings"]:
        if not isinstance(entry, dict):
            raise SastError("baseline findings must be objects")
        required = ("rule_id", "path", "fingerprint", "owner", "statement", "expires")
        if any(not isinstance(entry.get(key), str) or not entry[key].strip() for key in required):
            raise SastError("baseline findings require rule_id, path, fingerprint, owner, statement and expires")
        if Path(entry["path"]).is_absolute() or ".." in Path(entry["path"]).parts:
            raise SastError("baseline paths must be repository relative")
        if date.fromisoformat(entry["expires"]) < current:
            raise SastError(f"expired SAST baseline: {entry['rule_id']} {entry['path']}")
        result.add((entry["rule_id"], entry["path"], entry["fingerprint"]))
    return result


def _fingerprint(finding: dict[str, Any]) -> str:
    extra = finding.get("extra") if isinstance(finding.get("extra"), dict) else {}
    supplied = extra.get("fingerprint")
    if isinstance(supplied, str) and supplied:
        return supplied
    start = finding.get("start") if isinstance(finding.get("start"), dict) else {}
    raw = "|".join([
        str(finding.get("check_id", "")),
        str(finding.get("path", "")),
        str(start.get("line", "")),
        str(start.get("col", "")),
    ])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _sanitize(finding: dict[str, Any]) -> dict[str, str]:
    extra = finding.get("extra") if isinstance(finding.get("extra"), dict) else {}
    metadata = extra.get("metadata") if isinstance(extra.get("metadata"), dict) else {}
    return {
        "rule_id": str(finding.get("check_id", "")),
        "path": str(finding.get("path", "")),
        "fingerprint": _fingerprint(finding),
        "severity": str(extra.get("severity", "WARNING")).upper(),
        "category": str(metadata.get("category", "security")),
    }


def filter_findings(findings: Iterable[dict[str, Any]], baseline: set[tuple[str, str, str]], *, blocking_severities: set[str]) -> dict[str, list[dict[str, str]]]:
    blocking: list[dict[str, str]] = []
    suppressed: list[dict[str, str]] = []
    informational: list[dict[str, str]] = []
    for raw in findings:
        item = _sanitize(raw)
        key = (item["rule_id"], item["path"], item["fingerprint"])
        if key in baseline:
            suppressed.append(item)
        elif item["severity"] in blocking_severities:
            blocking.append(item)
        else:
            informational.append(item)
    return {"blocking": blocking, "suppressed": suppressed, "informational": informational}


def sanitize_semgrep_json(report: dict[str, Any]) -> dict[str, Any]:
    cleaned = json.loads(json.dumps(report))
    for finding in cleaned.get("results", []) or []:
        if not isinstance(finding, dict):
            continue
        extra = finding.get("extra")
        if isinstance(extra, dict):
            for key in ("lines", "metavars", "fixed_lines", "dataflow_trace", "rendered_fix"):
                extra.pop(key, None)
    return cleaned


def sanitize_sarif(report: dict[str, Any]) -> dict[str, Any]:
    def clean(value: Any) -> Any:
        if isinstance(value, list):
            return [clean(item) for item in value]
        if isinstance(value, dict):
            result = {}
            for key, item in value.items():
                if key in {"snippet", "contextRegion", "artifactContent", "fixes", "replacement", "insertedContent"}:
                    continue
                result[key] = clean(item)
            return result
        return value
    cleaned = clean(report)
    if not isinstance(cleaned, dict):
        raise SastError("sanitized SARIF root must remain an object")
    return cleaned


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_semgrep(
    *, root: Path, rules_dir: Path, profile: str, baseline_path: Path | None,
    evidence_dir: Path, semgrep: str, semgrep_version: str, repository: str, head_sha: str,
) -> int:
    if not repository or len(repository) > 200 or "\n" in repository:
        raise SastError("repository must be a bounded non-empty identifier")
    if not re.fullmatch(r"[0-9a-f]{40}", head_sha):
        raise SastError("head_sha must be a lowercase 40-character commit SHA")
    configs = [rules_dir / name for name in profile_configs(profile)]
    for config in configs:
        if not config.is_file() or not config.resolve().is_relative_to(rules_dir.resolve()):
            raise SastError(f"missing local rule profile: {config}")
    evidence_dir.mkdir(parents=True, exist_ok=True)
    json_report = evidence_dir / "semgrep.json"
    sarif_report = evidence_dir / "semgrep.sarif"
    common = [semgrep, "scan", "--metrics=off", "--disable-version-check", "--no-rewrite-rule-ids"]
    config_args: list[str] = []
    for config in configs:
        config_args.extend(["--config", str(config)])
    first = subprocess.run([*common, *config_args, "--json", "--output", str(json_report), str(root)], cwd=root, check=False)
    if first.returncode != 0:
        raise SastError(f"Semgrep JSON scan failed with exit code {first.returncode}")
    second = subprocess.run([*common, *config_args, "--sarif", "--output", str(sarif_report), str(root)], cwd=root, check=False)
    if second.returncode != 0:
        raise SastError(f"Semgrep SARIF scan failed with exit code {second.returncode}")
    report = sanitize_semgrep_json(_read_json(json_report))
    json_report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    sarif = sanitize_sarif(_read_json(sarif_report))
    sarif_report.write_text(json.dumps(sarif, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    findings = report.get("results", [])
    if not isinstance(findings, list):
        raise SastError("Semgrep report results must be an array")
    baseline = load_baseline(baseline_path)
    decision = filter_findings(findings, baseline, blocking_severities={"ERROR"})
    payload = {
        "schema_version": 1,
        "repository": repository,
        "head_sha": head_sha,
        "profile": profile,
        "rules": {path.name: _sha256(path) for path in configs},
        "semgrep_version": semgrep_version,
        "reports": {"json_sha256": _sha256(json_report), "sarif_sha256": _sha256(sarif_report)},
        "decision": decision,
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }
    (evidence_dir / "evidence.json").write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0 if not decision["blocking"] else 1


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True)
    parser.add_argument("--rules-dir", required=True)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--baseline", default="")
    parser.add_argument("--evidence-dir", required=True)
    parser.add_argument("--semgrep", default="semgrep")
    parser.add_argument("--semgrep-version", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--head-sha", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        baseline = Path(args.baseline) if args.baseline else None
        return run_semgrep(
            root=Path(args.root).resolve(), rules_dir=Path(args.rules_dir).resolve(), profile=args.profile,
            baseline_path=baseline, evidence_dir=Path(args.evidence_dir), semgrep=args.semgrep,
            semgrep_version=args.semgrep_version, repository=args.repository, head_sha=args.head_sha,
        )
    except (SastError, OSError, subprocess.CalledProcessError) as exc:
        print(f"SAST gate error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
