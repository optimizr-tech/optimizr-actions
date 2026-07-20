"""Run a repository-owned local validation preset and write secret-free evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import subprocess
import sys
import tempfile
import time
from typing import Any, Mapping, Sequence

_MAX_JSON_BYTES = 2 * 1024 * 1024
_MAX_SCALAR = 512
_ID_RE = re.compile(r"^[a-z][a-z0-9-]{0,79}$")
_SERVICE_RE = re.compile(r"^[a-z][a-z0-9._-]{0,79}$")
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_ALLOWED_INTERPRETERS = {"python", "bash"}
_ALLOWED_RESULTS = {"passed", "failed", "skipped"}
_SECRET_PATTERNS = (
    re.compile(r"(?i)(password|passwd|secret|token|authorization|cookie|private[_ .-]?key)\s*[:=]"),
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/-]+=*"),
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    re.compile(r"(?i)(?:x-amz-signature|x-goog-signature|signature|signed_url|sig)=([^&\s]+)"),
)


class ValidationError(ValueError):
    """Raised when a preset, command, or metadata document violates the contract."""


def _bounded(value: Any, label: str, *, maximum: int = _MAX_SCALAR) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise ValidationError(f"{label} must be a bounded non-empty string")
    if any(ord(character) < 32 for character in value):
        raise ValidationError(f"{label} contains control characters")
    if any(pattern.search(value) for pattern in _SECRET_PATTERNS):
        raise ValidationError(f"{label} contains prohibited secret-like data")
    return value


def _relative_path(value: Any, label: str) -> str:
    value = _bounded(value, label)
    if "\\" in value:
        raise ValidationError(f"{label} must use POSIX repository separators")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or path.as_posix() in {"", "."}:
        raise ValidationError(f"{label} must remain repository relative")
    return path.as_posix()


def _workspace_file(workspace: Path, relative: str) -> Path:
    workspace = workspace.resolve(strict=True)
    candidate = workspace / _relative_path(relative, "repository path")
    resolved = candidate.resolve(strict=True)
    if not resolved.is_relative_to(workspace) or candidate.is_symlink() or not resolved.is_file():
        raise ValidationError("repository path must be a regular non-symlink file inside workspace")
    current = candidate.parent
    while current != workspace:
        if current.is_symlink():
            raise ValidationError("repository path must not contain symlink directories")
        current = current.parent
    return resolved


def _read_json(path: Path, label: str) -> Any:
    if not path.is_file() or path.is_symlink():
        raise ValidationError(f"{label} must be a regular non-symlink file")
    if path.stat().st_size > _MAX_JSON_BYTES:
        raise ValidationError(f"{label} exceeds {_MAX_JSON_BYTES} bytes")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValidationError(f"{label} is not valid UTF-8 JSON") from exc


def _normalize_requirements(raw: Any, label: str) -> list[dict[str, str]]:
    if not isinstance(raw, list) or not raw:
        raise ValidationError(f"{label} must be a non-empty array")
    normalized: list[dict[str, str]] = []
    identifiers: set[str] = set()
    for item in raw:
        if not isinstance(item, Mapping) or set(item) != {"id", "description"}:
            raise ValidationError(f"{label} entries require exactly id and description")
        identifier = item["id"]
        if not isinstance(identifier, str) or not _ID_RE.fullmatch(identifier) or identifier in identifiers:
            raise ValidationError(f"{label} ids must be unique bounded identifiers")
        identifiers.add(identifier)
        normalized.append(
            {"id": identifier, "description": _bounded(item["description"], f"{label} description")}
        )
    return normalized


def normalize_preset(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, Mapping) or raw.get("schema_version") != 2:
        raise ValidationError("preset must be an object with schema_version 2")
    name = raw.get("name")
    if not isinstance(name, str) or not _ID_RE.fullmatch(name):
        raise ValidationError("preset name must be a bounded identifier")
    python_version = _bounded(raw.get("python"), "python")
    if not re.fullmatch(r"[0-9]+\.[0-9]+", python_version):
        raise ValidationError("python must use major.minor")
    entrypoint = _relative_path(raw.get("entrypoint"), "entrypoint")
    interpreter = raw.get("entrypoint_interpreter")
    if interpreter not in _ALLOWED_INTERPRETERS:
        raise ValidationError("entrypoint_interpreter must be python or bash")
    lockfile = _relative_path(raw.get("lockfile"), "lockfile")

    required_tools = raw.get("required_tools")
    if (
        not isinstance(required_tools, list)
        or not required_tools
        or any(tool not in {"python", "git", "docker"} for tool in required_tools)
    ):
        raise ValidationError("required_tools must be a non-empty subset of python, git and docker")
    required_tools = list(dict.fromkeys(required_tools))

    required_services = raw.get("required_services")
    if (
        not isinstance(required_services, list)
        or not required_services
        or any(
            not isinstance(service, str) or not _SERVICE_RE.fullmatch(service)
            for service in required_services
        )
        or len(set(required_services)) != len(required_services)
    ):
        raise ValidationError("required_services must contain unique service identifiers")
    constraints = raw.get("service_constraints")
    if not isinstance(constraints, Mapping) or set(constraints) != set(required_services):
        raise ValidationError("service_constraints must exactly match required_services")
    normalized_constraints: dict[str, dict[str, Any]] = {}
    for service in required_services:
        constraint = constraints[service]
        if not isinstance(constraint, Mapping) or set(constraint) != {
            "version_prefix",
            "digest_required",
        }:
            raise ValidationError("service constraints require version_prefix and digest_required")
        prefix = _bounded(constraint["version_prefix"], f"{service} version_prefix", maximum=128)
        digest_required = constraint["digest_required"]
        if not isinstance(digest_required, bool):
            raise ValidationError("digest_required must be boolean")
        normalized_constraints[service] = {
            "version_prefix": prefix,
            "digest_required": digest_required,
        }

    forbidden = raw.get("forbidden_services", [])
    if (
        not isinstance(forbidden, list)
        or any(
            not isinstance(service, str) or not _SERVICE_RE.fullmatch(service)
            for service in forbidden
        )
    ):
        raise ValidationError("forbidden_services must contain service identifiers")
    forbidden = list(dict.fromkeys(forbidden))
    if set(forbidden) & set(required_services):
        raise ValidationError("a service cannot be both required and forbidden")

    return {
        "schema_version": 2,
        "name": name,
        "python": python_version,
        "entrypoint": entrypoint,
        "entrypoint_interpreter": interpreter,
        "lockfile": lockfile,
        "required_tools": required_tools,
        "required_services": required_services,
        "service_constraints": normalized_constraints,
        "forbidden_services": forbidden,
        "required_checks": _normalize_requirements(raw.get("required_checks"), "required_checks"),
        "required_conformance": _normalize_requirements(
            raw.get("required_conformance"), "required_conformance"
        ),
    }


def _normalize_result_map(raw: Any, label: str) -> dict[str, str]:
    if not isinstance(raw, Mapping):
        raise ValidationError(f"{label} must be an object")
    normalized: dict[str, str] = {}
    for key, value in raw.items():
        if not isinstance(key, str) or not _ID_RE.fullmatch(key):
            raise ValidationError(f"{label} keys must be bounded identifiers")
        if value not in _ALLOWED_RESULTS:
            raise ValidationError(f"{label} values must be passed, failed or skipped")
        normalized[key] = value
    return normalized


def normalize_metadata(raw: Any) -> dict[str, Any]:
    expected_keys = {"schema_version", "services", "checks", "conformance"}
    if not isinstance(raw, Mapping) or set(raw) != expected_keys or raw.get("schema_version") != 1:
        raise ValidationError("metadata must use the exact schema_version 1 contract")
    services_raw = raw.get("services")
    if not isinstance(services_raw, Mapping) or len(services_raw) > 50:
        raise ValidationError("metadata services must be an object with at most 50 entries")
    services: dict[str, dict[str, str]] = {}
    for name, details in services_raw.items():
        if not isinstance(name, str) or not _SERVICE_RE.fullmatch(name):
            raise ValidationError("metadata service names must be bounded identifiers")
        if not isinstance(details, Mapping) or set(details) != {"version", "digest", "kind"}:
            raise ValidationError("service metadata requires version, digest and kind")
        version = _bounded(details["version"], f"{name} version", maximum=128)
        digest = _bounded(details["digest"], f"{name} digest", maximum=128)
        kind = details["kind"]
        if kind != "real":
            raise ValidationError("service metadata kind must be real")
        if digest != "unknown" and not _DIGEST_RE.fullmatch(digest):
            raise ValidationError("service digest must be unknown or a lowercase sha256 digest")
        services[name] = {"version": version, "digest": digest, "kind": "real"}
    return {
        "schema_version": 1,
        "services": services,
        "checks": _normalize_result_map(raw.get("checks"), "checks"),
        "conformance": _normalize_result_map(raw.get("conformance"), "conformance"),
    }


def evaluate_metadata(preset: Mapping[str, Any], metadata: Mapping[str, Any]) -> list[str]:
    unresolved: list[str] = []
    services = metadata["services"]
    for forbidden in preset["forbidden_services"]:
        if forbidden in services:
            unresolved.append(f"forbidden service present: {forbidden}")
    for service in preset["required_services"]:
        details = services.get(service)
        if details is None:
            unresolved.append(f"missing required service: {service}")
            continue
        constraint = preset["service_constraints"][service]
        if not details["version"].startswith(constraint["version_prefix"]):
            unresolved.append(f"{service} version does not match {constraint['version_prefix']}")
        if constraint["digest_required"] and not _DIGEST_RE.fullmatch(details["digest"]):
            unresolved.append(f"{service} digest is not immutable")
    for requirement in preset["required_checks"]:
        if metadata["checks"].get(requirement["id"]) != "passed":
            unresolved.append(f"required check not passed: {requirement['id']}")
    for requirement in preset["required_conformance"]:
        if metadata["conformance"].get(requirement["id"]) != "passed":
            unresolved.append(f"required conformance not passed: {requirement['id']}")
    return unresolved


def _tool_version(executable: str) -> str:
    if executable == "python":
        return platform.python_version()
    try:
        result = subprocess.run(
            [executable, "--version"],
            capture_output=True,
            text=True,
            check=False,
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired):
        return "unknown"
    output = (result.stdout or result.stderr).strip()
    return output.splitlines()[0] if result.returncode == 0 and output else "unknown"


def _git(workspace: Path, *args: str) -> str:
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=workspace,
            capture_output=True,
            text=True,
            check=False,
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired):
        return "unknown"
    return result.stdout.strip() if result.returncode == 0 else "unknown"


def _atomic_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise ValidationError("evidence path must not be a symlink")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
        os.chmod(path, 0o600)
    finally:
        if os.path.exists(temporary_name):
            os.unlink(temporary_name)


def _parse_args_json(raw: str) -> list[str]:
    try:
        values = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValidationError("command_args_json must be valid JSON") from exc
    if not isinstance(values, list) or len(values) > 50:
        raise ValidationError("command_args_json must contain at most 50 strings")
    return [_bounded(value, "command argument", maximum=1024) for value in values]


def run_validation(
    *,
    workspace: Path,
    preset_path: Path,
    evidence_path: Path,
    command_args: Sequence[str],
    allow_dirty: bool,
) -> dict[str, Any]:
    workspace = workspace.resolve(strict=True)
    preset = normalize_preset(_read_json(preset_path, "preset"))
    entrypoint = _workspace_file(workspace, preset["entrypoint"])
    lockfile = _workspace_file(workspace, preset["lockfile"])
    dirty = _git(workspace, "status", "--porcelain") != ""
    tools = {tool: _tool_version(tool) for tool in preset["required_tools"]}
    unresolved: list[str] = []
    if dirty and not allow_dirty:
        unresolved.append("clean worktree")
    if tools.get("python", "unknown").split(".")[:2] != preset["python"].split("."):
        unresolved.append(f"python {preset['python']}")
    for tool in preset["required_tools"]:
        if tools.get(tool) == "unknown":
            unresolved.append(f"required tool unavailable: {tool}")

    argv = (
        [sys.executable, str(entrypoint), *command_args]
        if preset["entrypoint_interpreter"] == "python"
        else ["bash", str(entrypoint), *command_args]
    )
    command_hash = hashlib.sha256(
        json.dumps(argv, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    evidence_path.parent.mkdir(parents=True, exist_ok=True)
    metadata_path = evidence_path.parent / f".{evidence_path.name}.metadata.json"
    if metadata_path.is_symlink():
        raise ValidationError("metadata path must not be a symlink")
    metadata_path.unlink(missing_ok=True)
    command_result: dict[str, Any] = {
        "entrypoint": preset["entrypoint"],
        "entrypoint_sha256": hashlib.sha256(entrypoint.read_bytes()).hexdigest(),
        "argv_sha256": command_hash,
        "exit_code": None,
        "duration_seconds": 0.0,
    }
    metadata = {"schema_version": 1, "services": {}, "checks": {}, "conformance": {}}

    if not unresolved:
        environment = os.environ.copy()
        environment["OPTIMIZR_VALIDATION_METADATA_PATH"] = str(metadata_path)
        started = time.monotonic()
        try:
            completed = subprocess.run(argv, cwd=workspace, check=False, env=environment)
            command_result["exit_code"] = completed.returncode
        except OSError:
            command_result["exit_code"] = 127
        command_result["duration_seconds"] = round(time.monotonic() - started, 3)
        if command_result["exit_code"] != 0:
            unresolved.append("repository validation entrypoint failed")
        if metadata_path.is_file() and not metadata_path.is_symlink():
            metadata = normalize_metadata(_read_json(metadata_path, "validation metadata"))
            unresolved.extend(evaluate_metadata(preset, metadata))
        else:
            unresolved.append("validation metadata was not produced")

    metadata_path.unlink(missing_ok=True)
    payload: dict[str, Any] = {
        "schema_version": 2,
        "preset": {
            "name": preset["name"],
            "sha256": hashlib.sha256(preset_path.read_bytes()).hexdigest(),
        },
        "repository": {
            "head_sha": _git(workspace, "rev-parse", "HEAD"),
            "base_sha": _git(workspace, "merge-base", "HEAD", "origin/main"),
            "clean": not dirty,
        },
        "tools": tools,
        "lockfile": {
            "path": preset["lockfile"],
            "sha256": hashlib.sha256(lockfile.read_bytes()).hexdigest(),
        },
        "command": command_result,
        "services": metadata["services"],
        "checks": metadata["checks"],
        "conformance": metadata["conformance"],
        "unresolved_gaps": sorted(set(unresolved)),
        "result": "passed" if not unresolved else "failed",
    }
    _atomic_json(evidence_path, payload)
    return payload


def _workspace_path(workspace: Path, relative: str, *, must_exist: bool) -> Path:
    workspace = workspace.resolve(strict=True)
    normalized = _relative_path(relative, "workspace path")
    candidate = workspace / normalized
    resolved = candidate.resolve(strict=must_exist)
    if not resolved.is_relative_to(workspace):
        raise ValidationError("workspace path resolves outside workspace")
    current = candidate
    while current != workspace:
        if current.is_symlink():
            raise ValidationError("workspace path must not contain symlinks")
        current = current.parent
    return resolved


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--preset", required=True)
    parser.add_argument("--evidence", required=True)
    parser.add_argument("--command-args-json", default="[]")
    parser.add_argument("--allow-dirty", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        workspace = args.workspace.resolve(strict=True)
        preset_path = _workspace_path(workspace, args.preset, must_exist=True)
        evidence_path = _workspace_path(workspace, args.evidence, must_exist=False)
        payload = run_validation(
            workspace=workspace,
            preset_path=preset_path,
            evidence_path=evidence_path,
            command_args=_parse_args_json(args.command_args_json),
            allow_dirty=args.allow_dirty,
        )
        return 0 if payload["result"] == "passed" else 1
    except (ValidationError, OSError) as exc:
        print(f"local validation error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
