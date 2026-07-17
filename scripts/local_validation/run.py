"""Run a preset locally and write secret-free validation evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time
from typing import Any


def _git(*args: str) -> str:
    result = subprocess.run(["git", *args], capture_output=True, text=True, check=False)
    return result.stdout.strip() if result.returncode == 0 else "unknown"


def _tool_version(executable: str) -> str:
    result = subprocess.run([executable, "--version"], capture_output=True, text=True, check=False)
    return result.stdout.strip().splitlines()[0] if result.returncode == 0 and result.stdout else "unknown"


def _parse_services(values: list[str]) -> dict[str, str]:
    services: dict[str, str] = {}
    for value in values:
        name, separator, version = value.partition("=")
        if not separator or not name or not version:
            raise ValueError("service values must use name=version")
        services[name] = version
    return services


def _write_evidence(path: Path, evidence: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--preset", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--service", action="append", default=[])
    parser.add_argument("--allow-dirty", action="store_true")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    if args.command[:1] == ["--"]:
        args.command = args.command[1:]

    preset = json.loads(args.preset.read_text(encoding="utf-8"))
    provided_services = _parse_services(args.service)
    dirty = _git("status", "--porcelain") != ""
    unresolved = [name for name in preset["required_services"] if name not in provided_services]
    if dirty and not args.allow_dirty:
        unresolved.append("clean worktree")

    lockfile = Path(preset.get("lockfile", "uv.lock"))
    evidence: dict[str, Any] = {
        "preset": preset["name"],
        "repository": {"head_sha": _git("rev-parse", "HEAD"), "base_sha": _git("merge-base", "HEAD", "origin/main"), "clean": not dirty},
        "tools": {tool: _tool_version(tool) for tool in ("python", "git", "docker")},
        "lockfile": {"path": str(lockfile), "sha256": hashlib.sha256(lockfile.read_bytes()).hexdigest() if lockfile.is_file() else "missing"},
        "services": {name: {"version": version, "kind": "real"} for name, version in provided_services.items()},
        "commands": [],
        "unresolved_gaps": unresolved,
        "result": "failed",
    }

    if args.command and not unresolved:
        started = time.monotonic()
        result = subprocess.run(args.command, check=False)
        evidence["commands"].append({"argv": args.command, "exit_code": result.returncode, "duration_seconds": round(time.monotonic() - started, 3)})
        if result.returncode:
            unresolved.append("required command failed")
    elif not args.command and not unresolved:
        unresolved.append("no required command supplied")

    evidence["result"] = "passed" if not unresolved else "failed"
    _write_evidence(args.evidence, evidence)
    return 0 if evidence["result"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
