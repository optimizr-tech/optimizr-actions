#!/usr/bin/env python3
"""Run controlled local Semgrep profiles with expiring exact baselines."""

from __future__ import annotations

import argparse
from datetime import date, datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
from typing import Any, Iterable, Mapping, Sequence

PROFILES = {
    "python": ["python.yml"],
    "typescript": ["typescript.yml"],
    "all": ["python.yml", "typescript.yml"],
}
REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
MAX_BASELINE_FINDINGS = 2_000
MAX_REPORT_FINDINGS = 10_000
MAX_REPORT_BYTES = 50 * 1024 * 1024
SCAN_TIMEOUT_SECONDS = 900


class SastError(ValueError):
    """Raised when a SAST profile, baseline, executable, or report is invalid."""


def profile_configs(profile: str) -> list[str]:
    if profile not in PROFILES:
        raise SastError(f"profile must be one of: {', '.join(PROFILES)}")
    return list(PROFILES[profile])


def _read_json(path: Path, *, maximum_bytes: int = MAX_REPORT_BYTES) -> dict[str, Any]:
    try:
        if not path.is_file() or path.is_symlink():
            raise SastError(f"JSON evidence must be a regular non-symlink file: {path}")
        if path.stat().st_size > maximum_bytes:
            raise SastError(f"JSON evidence exceeds {maximum_bytes} bytes: {path}")
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SastError(f"invalid JSON file {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise SastError(f"JSON root must be an object: {path}")
    return data


def _validate_repository(repository: str, head_sha: str) -> None:
    if not REPOSITORY_RE.fullmatch(repository):
        raise SastError("repository must use the bounded owner/name form")
    if not SHA_RE.fullmatch(head_sha):
        raise SastError("head_sha must be a lowercase 40-character commit SHA")


def _normalized_relative_path(value: str) -> str:
    if not value or len(value) > 1024 or any(ord(char) < 32 for char in value):
        raise SastError("finding paths must be bounded non-empty strings")
    path = PurePosixPath(value.replace("\\", "/"))
    if path.is_absolute() or ".." in path.parts:
        raise SastError("finding paths must be repository relative")
    normalized = path.as_posix()
    if normalized in {"", "."}:
        raise SastError("finding paths must identify a repository file")
    return normalized


def load_baseline(path: Path | None, today: str | None = None) -> set[tuple[str, str, str]]:
    if path is None:
        return set()
    data = _read_json(path, maximum_bytes=2 * 1024 * 1024)
    if data.get("version") != 1 or not isinstance(data.get("findings"), list):
        raise SastError("baseline must use version 1 and contain a findings array")
    if len(data["findings"]) > MAX_BASELINE_FINDINGS:
        raise SastError(f"baseline exceeds {MAX_BASELINE_FINDINGS} findings")
    try:
        current = date.fromisoformat(today) if today else datetime.now(timezone.utc).date()
    except ValueError as exc:
        raise SastError("today must be an ISO date") from exc
    result: set[tuple[str, str, str]] = set()
    for entry in data["findings"]:
        if not isinstance(entry, dict):
            raise SastError("baseline findings must be objects")
        required = ("rule_id", "path", "fingerprint", "owner", "statement", "expires")
        if any(not isinstance(entry.get(key), str) or not entry[key].strip() for key in required):
            raise SastError("baseline findings require rule_id, path, fingerprint, owner, statement and expires")
        for key in ("rule_id", "fingerprint", "owner", "statement"):
            if len(entry[key]) > 1024 or any(ord(char) < 32 for char in entry[key]):
                raise SastError(f"baseline {key} is too long or contains control characters")
        normalized_path = _normalized_relative_path(entry["path"])
        try:
            expiry = date.fromisoformat(entry["expires"])
        except ValueError as exc:
            raise SastError("baseline expires values must be ISO dates") from exc
        if expiry < current:
            raise SastError(f"expired SAST baseline: {entry['rule_id']} {normalized_path}")
        key = (entry["rule_id"], normalized_path, entry["fingerprint"])
        if key in result:
            raise SastError(f"duplicate SAST baseline entry: {entry['rule_id']} {normalized_path}")
        result.add(key)
    return result


def _fingerprint(finding: dict[str, Any]) -> str:
    extra = finding.get("extra") if isinstance(finding.get("extra"), dict) else {}
    supplied = extra.get("fingerprint")
    if isinstance(supplied, str) and supplied and len(supplied) <= 1024:
        return supplied
    start = finding.get("start") if isinstance(finding.get("start"), dict) else {}
    raw = "|".join([str(finding.get("check_id", "")), str(finding.get("path", "")), str(start.get("line", "")), str(start.get("col", ""))])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _sanitize(finding: dict[str, Any]) -> dict[str, str]:
    extra = finding.get("extra") if isinstance(finding.get("extra"), dict) else {}
    metadata = extra.get("metadata") if isinstance(extra.get("metadata"), dict) else {}
    rule_id = str(finding.get("check_id", ""))
    if not rule_id or len(rule_id) > 512 or any(ord(char) < 32 for char in rule_id):
        raise SastError("Semgrep finding has an invalid rule ID")
    severity = str(extra.get("severity", "WARNING")).upper()
    if severity not in {"INFO", "WARNING", "ERROR", "INVENTORY", "EXPERIMENT"}:
        severity = "WARNING"
    category = str(metadata.get("category", "security"))
    if not category or len(category) > 256 or any(ord(char) < 32 for char in category):
        category = "security"
    return {"rule_id": rule_id, "path": _normalized_relative_path(str(finding.get("path", ""))), "fingerprint": _fingerprint(finding), "severity": severity, "category": category}


def filter_findings(findings: Iterable[dict[str, Any]], baseline: set[tuple[str, str, str]], *, blocking_severities: set[str]) -> dict[str, list[dict[str, str]]]:
    blocking: list[dict[str, str]] = []
    suppressed: list[dict[str, str]] = []
    informational: list[dict[str, str]] = []
    for index, raw in enumerate(findings):
        if index >= MAX_REPORT_FINDINGS:
            raise SastError(f"Semgrep report exceeds {MAX_REPORT_FINDINGS} findings")
        if not isinstance(raw, dict):
            raise SastError("Semgrep report findings must be objects")
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
    results = report.get("results", [])
    if not isinstance(results, list):
        raise SastError("Semgrep report results must be an array")
    sanitized_results: list[dict[str, Any]] = []
    for index, finding in enumerate(results):
        if index >= MAX_REPORT_FINDINGS:
            raise SastError(f"Semgrep report exceeds {MAX_REPORT_FINDINGS} findings")
        if not isinstance(finding, dict):
            raise SastError("Semgrep report findings must be objects")
        extra = finding.get("extra") if isinstance(finding.get("extra"), dict) else {}
        metadata = extra.get("metadata") if isinstance(extra.get("metadata"), dict) else {}
        sanitized_results.append({"check_id": str(finding.get("check_id", "")), "path": _normalized_relative_path(str(finding.get("path", ""))), "start": {"line": int((finding.get("start") or {}).get("line", 0)), "col": int((finding.get("start") or {}).get("col", 0))}, "end": {"line": int((finding.get("end") or {}).get("line", 0)), "col": int((finding.get("end") or {}).get("col", 0))}, "extra": {"fingerprint": _fingerprint(finding), "severity": str(extra.get("severity", "WARNING")).upper(), "metadata": {"category": str(metadata.get("category", "security"))}}})
    version = report.get("version")
    return {"version": str(version)[:128] if version is not None else "unknown", "results": sanitized_results}


def sanitize_sarif(report: dict[str, Any]) -> dict[str, Any]:
    def clean(value: Any) -> Any:
        if isinstance(value, list):
            return [clean(item) for item in value]
        if isinstance(value, dict):
            result = {}
            for key, item in value.items():
                if key in {"snippet", "contextRegion", "artifactContent", "fixes", "replacement", "insertedContent", "codeFlows", "stacks"}:
                    continue
                result[key] = clean(item)
            return result
        return value
    cleaned = clean(report)
    if not isinstance(cleaned, dict):
        raise SastError("sanitized SARIF root must remain an object")
    return cleaned


def render_human_readable(decision: Mapping[str, list[dict[str, str]]]) -> str:
    lines = ["Optimizr controlled SAST findings"]
    for key, label in (("blocking", "BLOCKING"), ("suppressed", "SUPPRESSED"), ("informational", "INFORMATIONAL")):
        findings = decision.get(key, [])
        lines.append(f"{label}: {len(findings)}")
        for item in findings:
            lines.append(f"{label} {item['rule_id']} {item['path']} {item['severity']} {item['category']}")
    return "\n".join(lines) + "\n"


def _sha256(path: Path) -> str:
    if not path.is_file() or path.is_symlink():
        raise SastError(f"evidence file must be a regular non-symlink file: {path}")
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_bootstrap(*, evidence_dir: Path, repository: str, head_sha: str, profile: str, semgrep_version: str) -> None:
    _validate_repository(repository, head_sha)
    profile_configs(profile)
    _write_json(evidence_dir / "bootstrap.json", {"schema_version": 1, "repository": repository, "head_sha": head_sha, "profile": profile, "semgrep_version": semgrep_version, "result": "started"})


def write_failure_evidence(*, evidence_dir: Path, repository: str, head_sha: str, profile: str, semgrep_version: str, failure_kind: str) -> None:
    try:
        _validate_repository(repository, head_sha)
        profile_configs(profile)
    except SastError:
        return
    safe_kind = re.sub(r"[^A-Za-z0-9_.-]", "_", failure_kind)[:128] or "unknown"
    _write_json(evidence_dir / "evidence.json", {"schema_version": 1, "repository": repository, "head_sha": head_sha, "profile": profile, "semgrep_version": semgrep_version, "result": "failed", "failure_kind": safe_kind, "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")})


def _validate_run_paths(*, root: Path, rules_dir: Path, baseline_path: Path | None, evidence_dir: Path, semgrep: Path) -> None:
    if not root.is_dir() or root.is_symlink():
        raise SastError("root must be a regular repository directory")
    if not rules_dir.is_dir() or rules_dir.is_symlink():
        raise SastError("rules_dir must be a regular non-symlink directory")
    if not evidence_dir.is_dir() or evidence_dir.is_symlink():
        raise SastError("evidence_dir must be a regular non-symlink directory")
    if not evidence_dir.is_relative_to(root):
        raise SastError("evidence_dir must remain inside the repository")
    if baseline_path is not None and (not baseline_path.is_file() or baseline_path.is_symlink() or not baseline_path.is_relative_to(root)):
        raise SastError("baseline must be a regular non-symlink repository file")
    if not semgrep.is_file() or semgrep.is_symlink() or not os.access(semgrep, os.X_OK):
        raise SastError("semgrep must be an executable regular non-symlink file")


def _run(command: list[str], *, cwd: Path) -> None:
    try:
        completed = subprocess.run(command, cwd=cwd, check=False, timeout=SCAN_TIMEOUT_SECONDS, env={**os.environ, "SEMGREP_SEND_METRICS": "off"})
    except subprocess.TimeoutExpired as exc:
        raise SastError(f"Semgrep scan exceeded {SCAN_TIMEOUT_SECONDS} seconds") from exc
    if completed.returncode != 0:
        raise SastError(f"Semgrep scan failed with exit code {completed.returncode}")


def run_semgrep(*, root: Path, rules_dir: Path, profile: str, baseline_path: Path | None, evidence_dir: Path, semgrep: Path, semgrep_version: str, repository: str, head_sha: str) -> int:
    _validate_repository(repository, head_sha)
    if not semgrep_version or len(semgrep_version) > 128 or any(ord(char) < 32 for char in semgrep_version):
        raise SastError("semgrep_version must be a bounded non-empty value")
    configs = [rules_dir / name for name in profile_configs(profile)]
    _validate_run_paths(root=root, rules_dir=rules_dir, baseline_path=baseline_path, evidence_dir=evidence_dir, semgrep=semgrep)
    for config in configs:
        resolved = config.resolve()
        if not resolved.is_file() or resolved.is_symlink() or not resolved.is_relative_to(rules_dir):
            raise SastError(f"missing local rule profile: {config.name}")
    json_report = evidence_dir / "semgrep.json"
    sarif_report = evidence_dir / "semgrep.sarif"
    human_report = evidence_dir / "findings.txt"
    common = [str(semgrep), "scan", "--metrics=off", "--disable-version-check", "--no-rewrite-rule-ids", "--timeout=30", "--quiet"]
    config_args: list[str] = []
    for config in configs:
        config_args.extend(["--config", str(config)])
    _run([*common, *config_args, "--json", "--output", str(json_report), "."], cwd=root)
    _run([*common, *config_args, "--sarif", "--output", str(sarif_report), "."], cwd=root)
    report = sanitize_semgrep_json(_read_json(json_report))
    _write_json(json_report, report)
    sarif = sanitize_sarif(_read_json(sarif_report))
    _write_json(sarif_report, sarif)
    findings = report.get("results", [])
    if not isinstance(findings, list):
        raise SastError("Semgrep report results must be an array")
    baseline = load_baseline(baseline_path)
    decision = filter_findings(findings, baseline, blocking_severities={"ERROR"})
    human_report.write_text(render_human_readable(decision), encoding="utf-8")
    result = "failed" if decision["blocking"] else "passed"
    payload = {"schema_version": 1, "repository": repository, "head_sha": head_sha, "profile": profile, "rules": {path.name: _sha256(path) for path in configs}, "baseline_sha256": _sha256(baseline_path) if baseline_path else None, "semgrep_version": semgrep_version, "reports": {"json_sha256": _sha256(json_report), "sarif_sha256": _sha256(sarif_report), "human_sha256": _sha256(human_report)}, "decision": decision, "result": result, "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")}
    _write_json(evidence_dir / "evidence.json", payload)
    return 0 if result == "passed" else 1


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    bootstrap = sub.add_parser("bootstrap")
    bootstrap.add_argument("--evidence-dir", required=True)
    bootstrap.add_argument("--repository", required=True)
    bootstrap.add_argument("--head-sha", required=True)
    bootstrap.add_argument("--profile", required=True)
    bootstrap.add_argument("--semgrep-version", required=True)
    scan = sub.add_parser("scan")
    scan.add_argument("--root", required=True)
    scan.add_argument("--rules-dir", required=True)
    scan.add_argument("--profile", required=True)
    scan.add_argument("--baseline", default="")
    scan.add_argument("--evidence-dir", required=True)
    scan.add_argument("--semgrep", required=True)
    scan.add_argument("--semgrep-version", required=True)
    scan.add_argument("--repository", required=True)
    scan.add_argument("--head-sha", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    evidence_dir = Path(args.evidence_dir).resolve()
    if args.command == "bootstrap":
        try:
            write_bootstrap(evidence_dir=evidence_dir, repository=args.repository, head_sha=args.head_sha, profile=args.profile, semgrep_version=args.semgrep_version)
            return 0
        except (SastError, OSError) as exc:
            print(f"SAST gate error: {exc}", file=sys.stderr)
            return 2
    try:
        baseline = Path(args.baseline).resolve() if args.baseline else None
        return run_semgrep(root=Path(args.root).resolve(), rules_dir=Path(args.rules_dir).resolve(), profile=args.profile, baseline_path=baseline, evidence_dir=evidence_dir, semgrep=Path(args.semgrep).resolve(), semgrep_version=args.semgrep_version, repository=args.repository, head_sha=args.head_sha)
    except (SastError, OSError, subprocess.SubprocessError) as exc:
        write_failure_evidence(evidence_dir=evidence_dir, repository=args.repository, head_sha=args.head_sha, profile=args.profile, semgrep_version=args.semgrep_version, failure_kind=type(exc).__name__)
        print(f"SAST gate error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
