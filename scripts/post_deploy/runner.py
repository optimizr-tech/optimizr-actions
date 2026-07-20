#!/usr/bin/env python3
"""Run bounded container and HTTP checks for an exact deployed commit."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import ssl
import subprocess
import sys
import time
from typing import Any, Mapping, Sequence
from urllib import error, parse, request

REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$")
CONTAINER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
TARGET_RE = re.compile(r"^target[1-5]$")
HEADER_RE = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,100}$")
ALLOWED_METHODS = {"GET", "HEAD"}
MAX_CHECKS = 20
MAX_MANIFEST_BYTES = 1024 * 1024
MAX_BODY = 64 * 1024
DOCKER_TIMEOUT = 30
DOCKER_FORMAT = "{{.State.Running}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}|{{.State.Status}}|{{.Image}}"


class VerificationError(ValueError):
    """Raised when verification input violates the reusable contract."""


class NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _identity(repository: str, deployed_sha: str) -> None:
    if not REPOSITORY_RE.fullmatch(repository):
        raise VerificationError("repository must use owner/name")
    if not SHA_RE.fullmatch(deployed_sha):
        raise VerificationError("deployed_sha must be a lowercase 40-character SHA")


def _bounded(value: Any, label: str, maximum: int) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum or any(ord(char) < 32 for char in value):
        raise VerificationError(f"{label} must be a bounded non-empty string")
    return value


def normalize_manifest(data: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(data, Mapping) or data.get("version") != 1:
        raise VerificationError("manifest must be an object with version 1")
    raw_containers = data.get("containers", []) or []
    raw_http = data.get("http", []) or []
    if not isinstance(raw_containers, list) or not isinstance(raw_http, list):
        raise VerificationError("containers and http must be arrays")
    if len(raw_containers) > MAX_CHECKS or len(raw_http) > MAX_CHECKS or not 1 <= len(raw_containers) + len(raw_http) <= MAX_CHECKS:
        raise VerificationError(f"manifest must contain 1-{MAX_CHECKS} total checks")
    names: set[str] = set()
    containers: list[dict[str, Any]] = []
    http: list[dict[str, Any]] = []
    for raw in raw_containers:
        if not isinstance(raw, Mapping):
            raise VerificationError("container checks must be objects")
        name = raw.get("name")
        container = raw.get("container")
        if not isinstance(name, str) or not NAME_RE.fullmatch(name) or name in names:
            raise VerificationError("check names must be unique bounded identifiers")
        if not isinstance(container, str) or not CONTAINER_RE.fullmatch(container):
            raise VerificationError("container must be a bounded Docker name")
        health = raw.get("health", "running")
        if health not in {"running", "healthy"}:
            raise VerificationError("container health must be running or healthy")
        names.add(name)
        containers.append({"name": name, "container": container, "health": health})
    for raw in raw_http:
        if not isinstance(raw, Mapping):
            raise VerificationError("HTTP checks must be objects")
        name = raw.get("name")
        if not isinstance(name, str) or not NAME_RE.fullmatch(name) or name in names:
            raise VerificationError("check names must be unique bounded identifiers")
        target = raw.get("target")
        if not isinstance(target, str) or not TARGET_RE.fullmatch(target):
            raise VerificationError("HTTP target must be target1 through target5")
        path_value = _bounded(raw.get("path"), "HTTP path", 2048)
        parsed = parse.urlsplit(path_value)
        if not path_value.startswith("/") or "\\" in path_value or parsed.scheme or parsed.netloc or parsed.query or parsed.fragment:
            raise VerificationError("HTTP path must be an absolute path without authority, query, or fragment")
        method = str(raw.get("method", "GET")).upper()
        if method not in ALLOWED_METHODS:
            raise VerificationError("HTTP method must be GET or HEAD")
        statuses = raw.get("expected_status")
        if not isinstance(statuses, list) or not 1 <= len(statuses) <= 10 or any(not isinstance(code, int) or isinstance(code, bool) or code < 100 or code > 599 for code in statuses):
            raise VerificationError("expected_status must contain 1-10 valid HTTP codes")
        timeout = raw.get("timeout_seconds", 5)
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 1 <= timeout <= 10:
            raise VerificationError("timeout_seconds must be between 1 and 10")
        required_headers = raw.get("required_headers", {}) or {}
        if not isinstance(required_headers, Mapping) or len(required_headers) > 20:
            raise VerificationError("required_headers must contain at most 20 entries")
        normalized_headers: dict[str, str] = {}
        for key, value in required_headers.items():
            if not isinstance(key, str) or not HEADER_RE.fullmatch(key):
                raise VerificationError("required header names must be HTTP tokens")
            normalized_headers[key.lower()] = _bounded(value, "required header value", 500)
        names.add(name)
        http.append({
            "name": name,
            "target": target,
            "path": path_value,
            "method": method,
            "expected_status": sorted(set(statuses)),
            "timeout_seconds": float(timeout),
            "required_headers": normalized_headers,
        })
    return {"version": 1, "containers": containers, "http": http}


def load_manifest(path: Path) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink():
        raise VerificationError("manifest must be a regular non-symlink file")
    if path.stat().st_size > MAX_MANIFEST_BYTES:
        raise VerificationError(f"manifest exceeds {MAX_MANIFEST_BYTES} bytes")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise VerificationError("manifest is not valid UTF-8 JSON") from exc
    return normalize_manifest(data)


def _target_origin(alias: str, value: str) -> str:
    if not TARGET_RE.fullmatch(alias):
        raise VerificationError("unsupported target alias")
    value = _bounded(value, alias, 2048)
    parsed = parse.urlsplit(value)
    try:
        port = parsed.port
    except ValueError as exc:
        raise VerificationError("target has an invalid port") from exc
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in {"", "/"}:
        raise VerificationError("target must be an HTTP(S) origin without credentials or path")
    if port is not None and not 1 <= port <= 65535:
        raise VerificationError("target port is invalid")
    return value.rstrip("/")


def _write_evidence(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise VerificationError("evidence path must not be a symlink")
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def _container_check(check: Mapping[str, Any]) -> dict[str, Any]:
    started = time.monotonic()
    result: dict[str, Any] = {"kind": "container", "name": check["name"], "required_state": check["health"]}
    try:
        completed = subprocess.run(
            ["docker", "inspect", "--format", DOCKER_FORMAT, check["container"]],
            check=False,
            capture_output=True,
            text=True,
            timeout=DOCKER_TIMEOUT,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        result.update({"outcome": "unavailable", "failure_kind": type(exc).__name__})
    else:
        if completed.returncode != 0:
            result.update({"outcome": "unavailable", "failure_kind": "docker_inspect_failed"})
        else:
            parts = completed.stdout.strip().split("|")
            if len(parts) != 4 or parts[0] not in {"true", "false"}:
                result.update({"outcome": "unavailable", "failure_kind": "invalid_docker_output"})
            else:
                running = parts[0] == "true"
                health = parts[1]
                status = parts[2]
                image_id = parts[3]
                passed = running and (check["health"] == "running" or health == "healthy")
                result.update({
                    "outcome": "passed" if passed else "failed",
                    "running": running,
                    "health": health,
                    "status": status,
                    "image_id": image_id,
                })
                if not passed:
                    result["failure_kind"] = "state_mismatch"
    result["duration_ms"] = int((time.monotonic() - started) * 1000)
    return result


def _http_check(check: Mapping[str, Any], targets: Mapping[str, str], opener: request.OpenerDirector) -> dict[str, Any]:
    started = time.monotonic()
    alias = check["target"]
    result: dict[str, Any] = {
        "kind": "http",
        "name": check["name"],
        "target": alias,
        "method": check["method"],
        "expected_status": check["expected_status"],
    }
    raw_target = targets.get(alias, "")
    if not raw_target:
        result.update({"outcome": "unavailable", "failure_kind": "missing_target"})
    else:
        try:
            origin = _target_origin(alias, raw_target)
            req = request.Request(origin + check["path"], method=check["method"], headers={"User-Agent": "optimizr-post-deploy/1"})
            response = None
            try:
                try:
                    response = opener.open(req, timeout=check["timeout_seconds"])
                except error.HTTPError as exc:
                    response = exc
                body = response.read(MAX_BODY + 1)
                headers = {key.lower(): value for key, value in response.headers.items()}
                status_ok = response.status in check["expected_status"]
                headers_ok = all(headers.get(key) == value for key, value in check["required_headers"].items())
                body_ok = len(body) <= MAX_BODY
                passed = status_ok and headers_ok and body_ok
                result.update({
                    "outcome": "passed" if passed else "failed",
                    "actual_status": response.status,
                    "status_ok": status_ok,
                    "required_headers_ok": headers_ok,
                    "body_size_ok": body_ok,
                })
                if not passed:
                    result["failure_kind"] = "response_too_large" if not body_ok else "assertion_mismatch"
            finally:
                if response is not None:
                    response.close()
        except VerificationError:
            result.update({"outcome": "unavailable", "failure_kind": "invalid_target"})
        except (error.URLError, TimeoutError, OSError, ssl.SSLError) as exc:
            result.update({"outcome": "unavailable", "failure_kind": type(exc).__name__})
    result["duration_ms"] = int((time.monotonic() - started) * 1000)
    return result


def run_verification(*, manifest: Mapping[str, Any], targets: Mapping[str, str], repository: str, deployed_sha: str, evidence_path: Path) -> dict[str, Any]:
    _identity(repository, deployed_sha)
    normalized = normalize_manifest(manifest)
    opener = request.build_opener(request.ProxyHandler({}), NoRedirect, request.HTTPSHandler(context=ssl.create_default_context()))
    checks: list[dict[str, Any]] = []
    for check in normalized["containers"]:
        checks.append(_container_check(check))
    for check in normalized["http"]:
        checks.append(_http_check(check, targets, opener))
    passed = all(check["outcome"] == "passed" for check in checks)
    payload = {
        "schema_version": 1,
        "repository": repository,
        "deployed_sha": deployed_sha,
        "generated_at": _now(),
        "passed": passed,
        "result": "passed" if passed else "failed",
        "checks": checks,
    }
    _write_evidence(evidence_path, payload)
    return payload


def _repo_path(workspace: Path, relative: str, *, must_exist: bool) -> Path:
    if not relative or relative.startswith("/") or "\\" in relative or ".." in Path(relative).parts:
        raise VerificationError("repository paths must be relative and confined")
    candidate = workspace / relative
    resolved = candidate.resolve(strict=must_exist)
    if not resolved.is_relative_to(workspace):
        raise VerificationError("repository path resolves outside workspace")
    current = candidate
    while current != workspace:
        if current.is_symlink():
            raise VerificationError("repository path must not contain symlinks")
        current = current.parent
    return resolved


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest-path", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--deployed-sha", required=True)
    parser.add_argument("--evidence-path", required=True)
    parser.add_argument("--workspace", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        workspace = Path(args.workspace).resolve(strict=True)
        manifest_path = _repo_path(workspace, args.manifest_path, must_exist=True)
        evidence_path = _repo_path(workspace, args.evidence_path, must_exist=False)
        targets = {f"target{i}": os.environ.get(f"VERIFY_TARGET_{i}", "") for i in range(1, 6)}
        payload = run_verification(
            manifest=load_manifest(manifest_path),
            targets=targets,
            repository=args.repository,
            deployed_sha=args.deployed_sha,
            evidence_path=evidence_path,
        )
        return 0 if payload["passed"] else 1
    except (VerificationError, OSError, json.JSONDecodeError) as exc:
        print(f"post-deploy verification error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
