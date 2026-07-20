#!/usr/bin/env python3
"""Execute bounded declarative post-deploy negative security probes."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import ssl
import sys
import time
from typing import Any, Mapping, Sequence
from urllib import error, parse, request

TARGET_RE = re.compile(r"^target[1-5]$")
ALLOWED_METHODS = {"GET", "HEAD", "OPTIONS"}
MAX_PROBES = 20
MAX_BODY = 64 * 1024


class ProbeError(ValueError):
    """Raised when a probe manifest or target violates the safety contract."""


class NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ProbeError(f"invalid probe manifest {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ProbeError("probe manifest root must be an object")
    return data


def load_manifest(path: Path) -> dict[str, Any]:
    data = _json(path)
    probes = data.get("probes")
    if data.get("version") != 1 or not isinstance(probes, list) or not 1 <= len(probes) <= MAX_PROBES:
        raise ProbeError(f"manifest must use version 1 and contain 1-{MAX_PROBES} probes")
    names: set[str] = set()
    normalized: list[dict[str, Any]] = []
    for raw in probes:
        if not isinstance(raw, dict):
            raise ProbeError("every probe must be an object")
        name = raw.get("name")
        target = raw.get("target")
        path_value = raw.get("path")
        method = str(raw.get("method", "GET")).upper()
        statuses = raw.get("expected_status")
        timeout = raw.get("timeout_seconds", 5)
        if not isinstance(name, str) or not name or len(name) > 80 or name in names:
            raise ProbeError("probe names must be unique non-empty strings up to 80 characters")
        names.add(name)
        if not isinstance(target, str) or not TARGET_RE.fullmatch(target):
            raise ProbeError("probe target must be target1 through target5")
        if not isinstance(path_value, str) or not path_value.startswith("/") or len(path_value) > 2048 or "\0" in path_value:
            raise ProbeError("probe path must be an absolute URL path")
        parsed_path = parse.urlsplit(path_value)
        if parsed_path.scheme or parsed_path.netloc or parsed_path.fragment:
            raise ProbeError("probe path must not contain a scheme, authority, or fragment")
        if method not in ALLOWED_METHODS:
            raise ProbeError(f"probe method must be one of {sorted(ALLOWED_METHODS)}")
        if not isinstance(statuses, list) or not statuses or len(statuses) > 10 or any(not isinstance(code, int) or code < 100 or code > 599 for code in statuses):
            raise ProbeError("expected_status must contain 1-10 valid HTTP status codes")
        if not isinstance(timeout, (int, float)) or timeout < 1 or timeout > 10:
            raise ProbeError("timeout_seconds must be between 1 and 10")
        required_headers = raw.get("required_headers", {}) or {}
        forbidden_headers = raw.get("forbidden_headers", []) or []
        forbidden_body = raw.get("body_must_not_contain", []) or []
        if not isinstance(required_headers, dict) or len(required_headers) > 20 or any(not isinstance(k, str) or not isinstance(v, str) or not k or len(k) > 100 or len(v) > 500 for k, v in required_headers.items()):
            raise ProbeError("required_headers must be a mapping of at most 20 string pairs")
        if not isinstance(forbidden_headers, list) or len(forbidden_headers) > 20 or any(not isinstance(item, str) or not item or len(item) > 100 for item in forbidden_headers):
            raise ProbeError("forbidden_headers must be a list of at most 20 names")
        if not isinstance(forbidden_body, list) or len(forbidden_body) > 10 or any(not isinstance(item, str) or not item or len(item) > 100 for item in forbidden_body):
            raise ProbeError("body_must_not_contain must be a list of at most 10 bounded strings")
        normalized.append({
            "name": name,
            "target": target,
            "path": path_value,
            "method": method,
            "expected_status": statuses,
            "timeout_seconds": float(timeout),
            "required_headers": required_headers,
            "forbidden_headers": forbidden_headers,
            "body_must_not_contain": forbidden_body,
        })
    return {"version": 1, "probes": normalized}


def _validate_target(alias: str, value: str) -> str:
    if not TARGET_RE.fullmatch(alias):
        raise ProbeError(f"unsupported target alias: {alias}")
    if len(value) > 2048 or "\0" in value:
        raise ProbeError(f"{alias} must be a bounded HTTP(S) origin")
    parsed = parse.urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ProbeError(f"{alias} must be an HTTP(S) origin without credentials, query, or fragment")
    if parsed.path not in {"", "/"}:
        raise ProbeError(f"{alias} must not include an application path")
    return value.rstrip("/")


def _response(opener: request.OpenerDirector, req: request.Request, timeout: float):
    try:
        return opener.open(req, timeout=timeout)
    except error.HTTPError as exc:
        return exc


def run_probes(*, manifest: dict[str, Any], targets: Mapping[str, str], evidence_path: Path, repository: str, head_sha: str) -> dict[str, Any]:
    if not repository or len(repository) > 200 or "\n" in repository:
        raise ProbeError("repository must be a bounded non-empty identifier")
    if not re.fullmatch(r"[0-9a-f]{40}", head_sha):
        raise ProbeError("head_sha must be a lowercase 40-character commit SHA")
    validated_targets = {alias: _validate_target(alias, value) for alias, value in targets.items() if value}
    context = ssl.create_default_context()
    opener = request.build_opener(NoRedirect, request.HTTPSHandler(context=context))
    results: list[dict[str, Any]] = []
    all_passed = True
    for probe in manifest["probes"]:
        alias = probe["target"]
        if alias not in validated_targets:
            raise ProbeError(f"missing configured secret for {alias}")
        url = validated_targets[alias] + probe["path"]
        req = request.Request(url, method=probe["method"], headers={"User-Agent": "optimizr-negative-probe/1"})
        started = time.monotonic()
        result: dict[str, Any] = {
            "name": probe["name"],
            "target": alias,
            "method": probe["method"],
            "path_sha256": __import__("hashlib").sha256(probe["path"].encode()).hexdigest(),
            "expected_status": probe["expected_status"],
        }
        try:
            response = _response(opener, req, probe["timeout_seconds"])
            body = response.read(MAX_BODY + 1)
            if len(body) > MAX_BODY:
                raise ProbeError(f"probe {probe['name']} exceeded the {MAX_BODY}-byte response limit")
            headers = {key.lower(): value for key, value in response.headers.items()}
            status_ok = response.status in probe["expected_status"]
            required_ok = all(headers.get(key.lower()) == value for key, value in probe["required_headers"].items())
            forbidden_headers_ok = all(key.lower() not in headers for key in probe["forbidden_headers"])
            text = body.decode("utf-8", errors="replace")
            body_ok = all(value not in text for value in probe["body_must_not_contain"])
            passed = status_ok and required_ok and forbidden_headers_ok and body_ok
            result.update({
                "actual_status": response.status,
                "status_ok": status_ok,
                "required_headers_ok": required_ok,
                "forbidden_headers_ok": forbidden_headers_ok,
                "body_policy_ok": body_ok,
                "outcome": "passed" if passed else "failed",
            })
        except (error.URLError, TimeoutError, OSError) as exc:
            passed = False
            result.update({"outcome": "unavailable", "error_type": type(exc).__name__})
        result["duration_ms"] = int((time.monotonic() - started) * 1000)
        all_passed = all_passed and passed
        results.append(result)
    payload = {
        "schema_version": 1,
        "repository": repository,
        "head_sha": head_sha,
        "passed": all_passed,
        "results": results,
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }
    evidence_path.parent.mkdir(parents=True, exist_ok=True)
    evidence_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return payload


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--evidence", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--head-sha", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    targets = {f"target{number}": __import__("os").environ.get(f"PROBE_TARGET_{number}", "") for number in range(1, 6)}
    try:
        payload = run_probes(
            manifest=load_manifest(Path(args.manifest)),
            targets=targets,
            evidence_path=Path(args.evidence),
            repository=args.repository,
            head_sha=args.head_sha,
        )
        return 0 if payload["passed"] else 1
    except (ProbeError, OSError, ValueError) as exc:
        print(f"negative probe error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
