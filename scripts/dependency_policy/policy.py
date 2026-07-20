#!/usr/bin/env python3
"""Dependency lockfile and Trivy vulnerability/license policy engine."""

from __future__ import annotations

import argparse
from datetime import date, datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sys
import tomllib
from typing import Any, Mapping, Sequence

KNOWN_SEVERITIES = {"UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
DEPENDENCY_SECTIONS = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
REQ_NAME_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[A-Za-z0-9_,.-]+\])?==[^\s;]+$")
HASH_RE = re.compile(r"^--hash=sha256:[0-9a-f]{64}$")


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


def _normalize_package(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name.strip().lower())


def _logical_requirement_lines(path: Path) -> list[str]:
    logical: list[str] = []
    pending = ""
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        pending = f"{pending} {line}".strip()
        if pending.endswith("\\"):
            pending = pending[:-1].rstrip()
            continue
        logical.append(pending)
        pending = ""
    if pending:
        raise PolicyError(f"unterminated continuation in {path.name}")
    return logical


def _requirement_name(line: str, filename: str) -> str:
    tokens = line.split()
    hash_tokens = [token for token in tokens if token.startswith("--hash=")]
    if not hash_tokens or any(not HASH_RE.fullmatch(token) for token in hash_tokens):
        raise PolicyError(f"{filename} requirements must include only SHA-256 hashes")
    base_tokens = [token for token in tokens if not token.startswith("--hash=")]
    base = " ".join(base_tokens).split(";", 1)[0].strip()
    if base.startswith(("-", "http:", "https:", "git+", "svn+", "hg+", "bzr+")):
        raise PolicyError(f"{filename} contains an unsupported requirement source or option")
    match = REQ_NAME_RE.fullmatch(base)
    if not match:
        raise PolicyError(f"{filename} requirements must use exact == pins with SHA-256 hashes")
    return _normalize_package(match.group(1))


def validate_requirements_file(path: Path) -> list[str]:
    lines = _logical_requirement_lines(path)
    if not lines:
        raise PolicyError(f"requirements lockfile is empty: {path.name}")
    return [_requirement_name(line, path.name) for line in lines]


def _requirements_files(root: Path) -> list[Path]:
    return sorted(path for path in root.glob("requirements*.txt") if path.is_file())


def detect_ecosystems(root: Path) -> list[dict[str, str]]:
    root = root.resolve()
    result: list[dict[str, str]] = []
    pyproject = root / "pyproject.toml"
    requirement_files = _requirements_files(root)
    if pyproject.exists():
        locks = [("python-uv", "uv.lock"), ("python-poetry", "poetry.lock")]
        selected = [(kind, name) for kind, name in locks if (root / name).is_file()]
        if len(selected) > 1:
            raise PolicyError("pyproject.toml permits only one supported primary lockfile")
        if selected:
            kind, name = selected[0]
            result.append({"ecosystem": kind, "lockfile": name})
        elif requirement_files:
            for path in requirement_files:
                validate_requirements_file(path)
                result.append({"ecosystem": "python-requirements", "lockfile": path.name})
        else:
            raise PolicyError("pyproject.toml requires uv.lock, poetry.lock, or hash-locked requirements*.txt")
    elif requirement_files:
        for path in requirement_files:
            validate_requirements_file(path)
            result.append({"ecosystem": "python-requirements", "lockfile": path.name})

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
    if lock.get("lockfileVersion") not in {2, 3} or not isinstance(packages, dict) or not isinstance(packages.get(""), dict):
        raise PolicyError("package-lock.json must use lockfileVersion 2 or 3 with packages['']")
    root = packages[""]
    for section in DEPENDENCY_SECTIONS:
        expected = manifest.get(section, {}) or {}
        actual = root.get(section, {}) or {}
        if not isinstance(expected, dict) or not isinstance(actual, dict) or expected != actual:
            raise PolicyError(f"package-lock.json is stale for package.json section {section}")


def _parse_dependency_name(spec: str) -> str | None:
    match = re.match(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)", spec)
    return _normalize_package(match.group(1)) if match else None


def _set_scope(result: dict[str, str], name: str, scope: str) -> None:
    key = _normalize_package(name)
    priority = {"direct-production": 4, "direct-optional": 3, "direct-peer": 2, "direct-development": 1}
    if not key:
        return
    if key not in result or priority[scope] > priority[result[key]]:
        result[key] = scope


def collect_direct_dependencies(root: Path) -> dict[str, str]:
    root = root.resolve()
    result: dict[str, str] = {}
    package_json = root / "package.json"
    if package_json.is_file():
        manifest = _read_json(package_json)
        scopes = {
            "dependencies": "direct-production",
            "optionalDependencies": "direct-optional",
            "peerDependencies": "direct-peer",
            "devDependencies": "direct-development",
        }
        for section, scope in scopes.items():
            values = manifest.get(section, {}) or {}
            if not isinstance(values, dict):
                raise PolicyError(f"package.json section {section} must be an object")
            for name in values:
                _set_scope(result, str(name), scope)

    pyproject = root / "pyproject.toml"
    if pyproject.is_file():
        try:
            data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError) as exc:
            raise PolicyError(f"invalid pyproject.toml: {exc}") from exc
        project = data.get("project", {}) if isinstance(data.get("project"), dict) else {}
        for spec in project.get("dependencies", []) or []:
            if isinstance(spec, str) and (name := _parse_dependency_name(spec)):
                _set_scope(result, name, "direct-production")
        optional = project.get("optional-dependencies", {}) or {}
        if isinstance(optional, dict):
            for specs in optional.values():
                if isinstance(specs, list):
                    for spec in specs:
                        if isinstance(spec, str) and (name := _parse_dependency_name(spec)):
                            _set_scope(result, name, "direct-optional")
        tool = data.get("tool", {}) if isinstance(data.get("tool"), dict) else {}
        poetry = tool.get("poetry", {}) if isinstance(tool.get("poetry"), dict) else {}
        poetry_dependencies = poetry.get("dependencies", {}) or {}
        if isinstance(poetry_dependencies, dict):
            for name in poetry_dependencies:
                if str(name).lower() != "python":
                    _set_scope(result, str(name), "direct-production")
        groups = poetry.get("group", {}) or {}
        if isinstance(groups, dict):
            for group in groups.values():
                deps = group.get("dependencies", {}) if isinstance(group, dict) else {}
                if isinstance(deps, dict):
                    for name in deps:
                        _set_scope(result, str(name), "direct-development")
        dependency_groups = data.get("dependency-groups", {}) or {}
        if isinstance(dependency_groups, dict):
            for specs in dependency_groups.values():
                if isinstance(specs, list):
                    for spec in specs:
                        if isinstance(spec, str) and (name := _parse_dependency_name(spec)):
                            _set_scope(result, name, "direct-development")

    for path in _requirements_files(root):
        scope = "direct-development" if re.search(r"(?:dev|test|lint|type|docs)", path.stem, re.I) else "direct-production"
        for name in validate_requirements_file(path):
            _set_scope(result, name, scope)
    return result


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
        if not required.issubset(entry) or entry.get("kind") not in {"vulnerability", "license"}:
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


def evaluate_report(
    report: dict[str, Any],
    policy: dict[str, Any],
    today: str | None = None,
    direct_dependencies: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    del today
    direct = {_normalize_package(key): value for key, value in (direct_dependencies or {}).items()}
    results = report.get("Results")
    if not isinstance(results, list):
        raise PolicyError("Trivy report Results must be an array")
    blocking: list[dict[str, str]] = []
    suppressed: list[dict[str, str]] = []
    for result in results:
        if not isinstance(result, dict):
            raise PolicyError("Trivy report results must be objects")
        target = str(result.get("Target", "unknown"))[:500]
        vulnerabilities = result.get("Vulnerabilities", []) or []
        licenses = result.get("Licenses", []) or []
        if not isinstance(vulnerabilities, list) or not isinstance(licenses, list):
            raise PolicyError("Trivy vulnerability and license findings must be arrays")
        for vulnerability in vulnerabilities:
            if not isinstance(vulnerability, dict):
                raise PolicyError("Trivy vulnerability findings must be objects")
            identifier = str(vulnerability.get("VulnerabilityID", ""))
            package = str(vulnerability.get("PkgName", ""))
            severity = str(vulnerability.get("Severity", "UNKNOWN"))
            if not identifier or not package or severity not in KNOWN_SEVERITIES:
                raise PolicyError("Trivy vulnerability finding is incomplete")
            if severity not in policy["block_severities"]:
                continue
            finding = {
                "kind": "vulnerability",
                "id": identifier,
                "package": package,
                "severity": severity,
                "target": target,
                "dependency_scope": direct.get(_normalize_package(package), "transitive"),
            }
            (suppressed if _excepted(policy, "vulnerability", identifier, package) else blocking).append(finding)
        for license_item in licenses:
            if not isinstance(license_item, dict):
                raise PolicyError("Trivy license findings must be objects")
            identifier = str(license_item.get("Name") or license_item.get("License") or "")
            package = str(license_item.get("PkgName") or license_item.get("Package") or "")
            if not identifier or not package:
                raise PolicyError("Trivy license finding is incomplete")
            if identifier not in policy["denied_licenses"]:
                continue
            finding = {
                "kind": "license",
                "id": identifier,
                "package": package,
                "severity": "POLICY",
                "target": target,
                "dependency_scope": direct.get(_normalize_package(package), "transitive"),
            }
            (suppressed if _excepted(policy, "license", identifier, package) else blocking).append(finding)
    return {"blocking": blocking, "suppressed": suppressed, "passed": not blocking}


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_evidence(
    *,
    root: Path,
    report_path: Path,
    policy_path: Path,
    database_path: Path,
    output: Path,
    repository: str,
    head_sha: str,
    trivy_version: str,
) -> bool:
    if not REPOSITORY_RE.fullmatch(repository) or len(repository) > 200:
        raise PolicyError("repository must use the bounded owner/name form")
    if not SHA_RE.fullmatch(head_sha):
        raise PolicyError("head_sha must be a lowercase 40-character commit SHA")
    ecosystems = detect_ecosystems(root)
    if (root / "package.json").exists() and (root / "package-lock.json").exists():
        validate_package_lock(_read_json(root / "package.json"), _read_json(root / "package-lock.json"))
    policy = load_policy(policy_path)
    report = _read_json(report_path)
    direct = collect_direct_dependencies(root)
    decision = evaluate_report(report, policy, direct_dependencies=direct)
    counts: dict[str, int] = {}
    for scope in direct.values():
        counts[scope] = counts.get(scope, 0) + 1
    payload = {
        "schema_version": 1,
        "repository": repository,
        "head_sha": head_sha,
        "ecosystems": [{**item, "sha256": _hash_file(root / item["lockfile"])} for item in ecosystems],
        "direct_dependency_counts": counts,
        "policy": {
            "sha256": _hash_file(policy_path),
            "block_severities": policy["block_severities"],
            "denied_licenses": policy["denied_licenses"],
        },
        "tool": {"trivy": trivy_version},
        "database": {"sha256": _hash_file(database_path)},
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
    requirements = sub.add_parser("validate-requirements")
    requirements.add_argument("--root", required=True)
    evaluate = sub.add_parser("evaluate")
    evaluate.add_argument("--root", required=True)
    evaluate.add_argument("--report", required=True)
    evaluate.add_argument("--policy", required=True)
    evaluate.add_argument("--database", required=True)
    evaluate.add_argument("--trivy-version", required=True)
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
        if args.command == "validate-requirements":
            entries = [item for item in detect_ecosystems(root) if item["ecosystem"] == "python-requirements"]
            if not entries:
                raise PolicyError("no hash-locked requirements files were detected")
            for item in entries:
                validate_requirements_file(root / item["lockfile"])
            return 0
        passed = write_evidence(
            root=root,
            report_path=Path(args.report),
            policy_path=Path(args.policy),
            database_path=Path(args.database),
            output=Path(args.output),
            repository=args.repository,
            head_sha=args.head_sha,
            trivy_version=args.trivy_version,
        )
        return 0 if passed else 1
    except (PolicyError, OSError, ValueError, KeyError) as exc:
        print(f"dependency policy error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
