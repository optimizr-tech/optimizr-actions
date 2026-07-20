#!/usr/bin/env python3
"""Write a Docker Compose compatible environment file without exposing values."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
from typing import Any, Mapping, Sequence

KEY_RE = re.compile(r"^[A-Z_][A-Z0-9_]{0,127}$")
MAX_SCHEMA_BYTES = 1024 * 1024
MAX_ENTRIES = 200
MAX_VALUE_BYTES = 1024 * 1024
ALLOWED_MODES = {0o400, 0o440, 0o600, 0o640, 0o660}


class EnvFileError(ValueError):
    """Raised when schema, paths, or environment values violate the contract."""


def _bounded_value(value: str, label: str) -> str:
    if not isinstance(value, str):
        raise EnvFileError(f"{label} must be a string")
    if len(value.encode("utf-8")) > MAX_VALUE_BYTES:
        raise EnvFileError(f"{label} exceeds {MAX_VALUE_BYTES} bytes")
    if "\x00" in value:
        raise EnvFileError(f"{label} contains a NUL byte")
    return value


def normalize_schema(data: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(data, Mapping) or data.get("version") != 1:
        raise EnvFileError("schema must be an object with version 1")
    entries = data.get("entries")
    if not isinstance(entries, list) or not 1 <= len(entries) <= MAX_ENTRIES:
        raise EnvFileError(f"schema entries must contain 1-{MAX_ENTRIES} items")
    normalized: list[dict[str, Any]] = []
    keys: set[str] = set()
    for raw in entries:
        if not isinstance(raw, Mapping):
            raise EnvFileError("every schema entry must be an object")
        key = raw.get("key")
        if not isinstance(key, str) or not KEY_RE.fullmatch(key):
            raise EnvFileError("entry key must be an uppercase environment variable name")
        if key in keys:
            raise EnvFileError(f"duplicate entry key: {key}")
        keys.add(key)
        has_env = "env" in raw
        has_literal = "literal" in raw
        if has_env == has_literal:
            raise EnvFileError(f"{key} must define exactly one of env or literal")
        secret = raw.get("secret", has_env)
        required = raw.get("required", False)
        if not isinstance(secret, bool) or not isinstance(required, bool):
            raise EnvFileError(f"{key} secret and required fields must be boolean")
        if has_env:
            source = raw.get("env")
            if not isinstance(source, str) or not KEY_RE.fullmatch(source):
                raise EnvFileError(f"{key} env source must be an uppercase variable name")
            if secret and "default" in raw:
                raise EnvFileError(f"{key} secret entries must not embed defaults")
            default = raw.get("default")
            if default is not None:
                default = _bounded_value(default, f"{key} default")
            normalized.append({
                "key": key,
                "source_kind": "env",
                "source": source,
                "required": required,
                "secret": secret,
                "default": default,
            })
        else:
            if secret:
                raise EnvFileError(f"{key} literal entries cannot be secret")
            literal = _bounded_value(raw.get("literal"), f"{key} literal")
            normalized.append({
                "key": key,
                "source_kind": "literal",
                "literal": literal,
                "required": True,
                "secret": False,
                "default": None,
            })
    return {"version": 1, "entries": normalized}


def load_schema(path: Path) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink():
        raise EnvFileError("schema must be a regular non-symlink file")
    if path.stat().st_size > MAX_SCHEMA_BYTES:
        raise EnvFileError(f"schema exceeds {MAX_SCHEMA_BYTES} bytes")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise EnvFileError("schema is not valid UTF-8 JSON") from exc
    return normalize_schema(data)


def _compose_quote(value: str) -> str:
    value = _bounded_value(value, "environment value")
    escaped = (
        value.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\r", "\\r")
        .replace("\n", "\\n")
        .replace("\t", "\\t")
        .replace("$", "$$")
    )
    return f'"{escaped}"'


def render_env(schema: Mapping[str, Any], environment: Mapping[str, str]) -> tuple[str, list[dict[str, Any]]]:
    normalized = normalize_schema(schema)
    lines: list[str] = []
    metadata: list[dict[str, Any]] = []
    for entry in normalized["entries"]:
        if entry["source_kind"] == "literal":
            value = entry["literal"]
            present = True
        else:
            source = entry["source"]
            raw = environment.get(source)
            if raw is None or raw == "":
                if entry["default"] is not None:
                    value = entry["default"]
                    present = True
                elif entry["required"]:
                    raise EnvFileError(f"required environment source is missing for {entry['key']}")
                else:
                    value = ""
                    present = False
            else:
                value = _bounded_value(raw, f"environment source for {entry['key']}")
                present = True
        lines.append(f"{entry['key']}={_compose_quote(value)}")
        metadata.append({
            "key": entry["key"],
            "key_sha256": hashlib.sha256(entry["key"].encode("utf-8")).hexdigest(),
            "source_kind": entry["source_kind"],
            "required": entry["required"],
            "secret": entry["secret"],
            "present": present,
        })
    return "\n".join(lines) + "\n", metadata


def _ensure_no_symlink_components(path: Path, stop: Path) -> None:
    current = path
    while True:
        if current.is_symlink():
            raise EnvFileError("path must not contain symbolic links")
        if current == stop:
            return
        if current.parent == current:
            raise EnvFileError("path is not contained by allowed root")
        current = current.parent


def _resolve_destination(destination: Path, allowed_root: Path) -> tuple[Path, Path]:
    if not allowed_root.is_dir() or allowed_root.is_symlink():
        raise EnvFileError("allowed_root must be an existing non-symlink directory")
    allowed = allowed_root.resolve(strict=True)
    parent = destination.parent.resolve(strict=True)
    if not parent.is_relative_to(allowed):
        raise EnvFileError("destination parent must remain inside allowed_root")
    _ensure_no_symlink_components(destination.parent, allowed_root)
    candidate = parent / destination.name
    if candidate.exists() and (candidate.is_symlink() or not candidate.is_file()):
        raise EnvFileError("destination must be a regular file or absent")
    return candidate, allowed


def _write_json_atomic(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise EnvFileError("evidence path must not be a symbolic link")
    temporary = path.with_name(path.name + ".tmp")
    if temporary.is_symlink():
        raise EnvFileError("temporary evidence path must not be a symbolic link")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def write_env_file(*, schema: Mapping[str, Any], environment: Mapping[str, str], destination: Path, allowed_root: Path, mode: int, evidence_path: Path) -> dict[str, Any]:
    if mode not in ALLOWED_MODES:
        raise EnvFileError("mode must be one of 0400, 0440, 0600, 0640, or 0660")
    destination, _ = _resolve_destination(destination, allowed_root)
    rendered, entries = render_env(schema, environment)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{destination.name}.", dir=destination.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(rendered)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, destination)
        actual_mode = stat.S_IMODE(destination.stat().st_mode)
        if actual_mode != mode:
            raise EnvFileError("destination mode verification failed")
    finally:
        if temporary.exists():
            temporary.unlink()
    payload = {
        "schema_version": 1,
        "result": "passed",
        "destination_name": destination.name,
        "mode": format(mode, "04o"),
        "entry_count": len(entries),
        "entries": entries,
    }
    _write_json_atomic(evidence_path, payload)
    return payload


def _repository_path(workspace: Path, relative: str, *, must_exist: bool) -> Path:
    if not isinstance(relative, str) or not relative or relative.startswith("/") or "\\" in relative:
        raise EnvFileError("repository paths must be relative")
    parts = Path(relative).parts
    if ".." in parts:
        raise EnvFileError("repository paths must not traverse")
    candidate = workspace / relative
    resolved = candidate.resolve(strict=must_exist)
    if not resolved.is_relative_to(workspace):
        raise EnvFileError("repository path resolves outside workspace")
    _ensure_no_symlink_components(candidate, workspace)
    return resolved


def _parse_mode(value: str) -> int:
    if not re.fullmatch(r"0[0-7]{3}", value):
        raise EnvFileError("mode must be a four-digit octal string")
    return int(value, 8)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--schema-path", required=True)
    parser.add_argument("--destination", required=True)
    parser.add_argument("--allowed-root", required=True)
    parser.add_argument("--mode", default="0600")
    parser.add_argument("--evidence-path", required=True)
    parser.add_argument("--workspace", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        workspace = Path(args.workspace).resolve(strict=True)
        schema_path = _repository_path(workspace, args.schema_path, must_exist=True)
        evidence_path = _repository_path(workspace, args.evidence_path, must_exist=False)
        write_env_file(
            schema=load_schema(schema_path),
            environment=os.environ,
            destination=Path(args.destination),
            allowed_root=Path(args.allowed_root),
            mode=_parse_mode(args.mode),
            evidence_path=evidence_path,
        )
        return 0
    except (EnvFileError, OSError) as exc:
        print(f"environment-file writer error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
