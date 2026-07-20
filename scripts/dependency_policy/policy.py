#!/usr/bin/env python3
"""Dependency lockfile and Trivy vulnerability/license policy engine."""

from __future__ import annotations

import argparse
from datetime import date, datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
from typing import Any, Sequence

KNOWN_SEVERITIES = {"UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
DEPENDENCY_SECTIONS = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")


class PolicyError(ValueError):
    """Raised when dependency evidence or policy is invalid."""


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PolicyError(f"invalid JSON file {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise PolicyError(f"JSON root must be an object: {path}")
    return value


def detect_ecosystems(root: Path) -> list[dict[str, str]]:
    root = root.resolve()
    result: list[dict[str, str]] = []
    pyproject = root / "pyproject.toml"
    if pyproject.exists():
        locks = [("python-uv", "uv.lock"), ("python-poetry", "poetry.lock")]
        selected = [(kind, name) for kind, name in locks if (root / name).is_file()]
        if len(selected) != 1:
            raise PolicyError("pyproject.toml requires exactly one supported lockfile: uv.lock or poetry.lock")
        kind, name = selected[0]
        result.append({"ecosystem": kind, "lockfile": name})

    package_json = root / "package.json"
    if package_json.exists():
        manifest = _read_json(package_json)
        candidates = {
            "node-pnpm": "pnpm-lock.yaml",
            "node-npm": "package-lock.json",
            "node-yarn": "yarn.lock",
        }
        present = [(kind, name) for kind, name in candidates.items() if (root / name).is_file()]
        package_manager = str(manifest.get("packageManager", ""))
        if package_manager:
            prefix = package_manager.split("@", 1)[0]
            expected = {"pnpm": "node-pnpm", "npm": "node-npm", "yarn": "node-yarn"}.get(prefix)
            if expected is None:
                raise PolicyError(f"unsupported packageManager: {package_manager}")
            present = [item for item in present if item[0] == expected]
        if len(present) != 1:
            raise PolicyError("package.json requires exactly one supported lockfile matching packageManager")
        kind, name = present[0]
        result.append({"ecosystem": kind, "lockfile": name})

    if not result:
        raise PolicyError("no supported Python or Node dependency manifest was found")
    return result


def validate_package_lock(manifest: dict[str, Any], lock: dict[str, Any]) -> None:
    packages = lock.get("packages")
    if not isinstance(packages, dict) or not isinstance(packages.get(""), dict):
        raise PolicyError("package-lock.json must use lockfileVersion 2 or 3 with packages['']")
    root = packages[""]
    for section in DEPENDENCY_SECTIONS:
        expected = manifest.get(section, {}) or {}
        actual = root.get(section, {}) or {}
        if not isinstance(expected, dict) or not isinstance(actual, dict) or expected != actual:
            raise PolicyError(f"package-lock.json is stale for package.json section {section}")


def _today(value: str | None) -> date:
    return date.fromisoformat(value) if value else datetime.now(timezone.utc).date()


def load_policy(path: Path, today: str | None = None) -> dict[str, Any]:
    policy = _read_json(path)
    if policy.get("version") != 1:
        raise PolicyError("policy version must be 1")
    severities = policy.get("block_severities", ["HIGH", "CRITICAL"])
    if not isinstance(severities, list) or not severities or any(item not in KNOWN_SEVERITIES for item in severities):
        raise PolicyError("block_severities must be a non-empty list of known severities")
    licenses = policy.get("denied_licenses", [])
    if not isinstance(licenses, list) or any(not isinstance(item, str) or not item for item in licenses):
        raise PolicyError("denied_licenses must be a list of non-empty SPDX identifiers")
    exceptions = policy.get("exceptions", [])
    if not isinstance(exceptions, list):
        raise PolicyError("exceptions must be a list")
    current = _today(today)
    normalized: list[dict[str, str]] = []
    for entry in exceptions:
        if not isinstance(entry, dict):
            raise PolicyError("every exception must be an object")
        required = {"kind", "id", "package", "owner", "statement", "expires"}
        if set(entry) < required or entry.get("kind") not in {"vulnerability", "license"}:
            raise PolicyError("exceptions require kind, id, package, owner, statement, and expires")
        if any(not isinstance(entry.get(field), str) or not entry[field].strip() for field in required):
            raise PolicyError("exception fields must be non-empty strings")
        expiry = date.fromisoformat(entry["expires"])
        if expiry < current:
            raise PolicyError(f"expired dependency exception: {entry['id']} ({entry['expires']})")
        normalized.append({field: entry[field] for field in sorted(required)})
    return {
        "version": 1,
        "block_severities": list(dict.fromkeys(severities)),
        "denied_licenses": list(dict.fromkeys(licenses)),
        "exceptions": normalized,
    }


def _excepted(policy: dict[str, Any], kind: str, identifier: str, package: str) -> bool:
    return any(
        entry["kind"] == kind
        and entry["id"] == identifier
        and entry["package"] in {package, "*"}
        for entry in policy["exceptions"]
    )


def evaluate_report(report: dict[str, Any], policy: dict[str, Any], today: str | None = None) -> dict[str, Any]:
    del today
    blocking: list[dict[str, str]] = []
    suppressed: list[dict[str, str]] = []
    for result in report.get("Results", []) or []:
        if not isinstance(result, dict):
            continue
        target = str(result.get("Target", "unknown"))
        for vulnerability in result.get("Vulnerabilities", []) or []:
            if not isinstance(vulnerability, dict):
                continue
            identifier = str(vulnerability.get("VulnerabilityID", ""))
            package = str(vulnerability.get("PkgName", ""))
            severity = str(vulnerability.get("Severity", "UNKNOWN"))
            if severity not in policy["block_severities"]:
                continue
            finding = {"kind": "vulnerability", "id": identifier, "package": package, "severity": severity, "target": target}
            (suppressed if _excepted(policy, "vulnerability", identifier, package) else blocking).append(finding)
        for license_item in result.get("Licenses", []) or []:
            if not isinstance(license_item, dict):
                continue
            identifier = str(license_item.get("Name") or license_item.get("License") or "")
            package = str(license_item.get("PkgName") or license_item.get("Package") or "")
            if identifier not in policy["denied_licenses"]:
                continue
            finding = {"kind": "license", "id": identifier, "package": package, "severity": "POLICY", "target": target}
            (suppressed if _excepted(policy, "license", identifier, package) else blocking).append(finding)
    return {"blocking": blocking, "suppressed": suppressed, "passed": not blocking}


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_evidence(*, root: Path, report_path: Path, policy_path: Path, output: Path, repository: str, head_sha: str) -> bool:
    ecosystems = detect_ecosystems(root)
    if (root / "package.json").exists() and (root / "package-lock.json").exists():
        validate_package_lock(_read_json(root / "package.json"), _read_json(root / "package-lock.json"))
    policy = load_policy(policy_path)
    report = _read_json(report_path)
    decision = evaluate_report(report, policy)
    payload = {
        "schema_version": 1,
        "repository": repository,
        "head_sha": head_sha,
        "ecosystems": [{**item, "sha256": _hash_file(root / item["lockfile"])} for item in ecosystems],
        "policy": {"sha256": _hash_file(policy_path), "block_severities": policy["block_severities"], "denied_licenses": policy["denied_licenses"]},
        "report": {"sha256": _hash_file(report_path)},
        "decision": decision,
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return decision["passed"]


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    detect = sub.add_parser("detect")
    detect.add_argument("--root", required=True)
    validate = sub.add_parser("validate-npm-lock")
    validate.add_argument("--root", required=True)
    evaluate = sub.add_parser("evaluate")
    evaluate.add_argument("--root", required=True)
    evaluate.add_argument("--report", required=True)
    evaluate.add_argument("--policy", required=True)
    evaluate.add_argument("--output", required=True)
    evaluate.add_argument("--repository", required=True)
    evaluate.add_argument("--head-sha", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        root = Path(args.root).resolve()
        if args.command == "detect":
            for item in detect_ecosystems(root):
                print(item["ecosystem"])
            return 0
        if args.command == "validate-npm-lock":
            validate_package_lock(_read_json(root / "package.json"), _read_json(root / "package-lock.json"))
            return 0
        passed = write_evidence(root=root, report_path=Path(args.report), policy_path=Path(args.policy), output=Path(args.output), repository=args.repository, head_sha=args.head_sha)
        return 0 if passed else 1
    except (PolicyError, OSError, ValueError) as exc:
        print(f"dependency policy error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
