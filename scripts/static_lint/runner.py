#!/usr/bin/env python3
"""Deterministic ShellCheck, actionlint, and composite-action metadata runner."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import fnmatch
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any, Iterable, Sequence


class LintError(ValueError):
    """Raised when lint inputs violate the portable contract."""


SPECS: dict[str, dict[str, dict[str, str]]] = {
    "x86_64": {
        "shellcheck": {
            "version": "0.11.0",
            "url": "https://github.com/koalaman/shellcheck/releases/download/v0.11.0/shellcheck-v0.11.0.linux.x86_64.tar.xz",
            "sha256": "8c3be12b05d5c177a04c29e3c78ce89ac86f1595681cab149b65b97c4e227198",
            "member": "shellcheck-v0.11.0/shellcheck",
        },
        "actionlint": {
            "version": "1.7.12",
            "url": "https://github.com/rhysd/actionlint/releases/download/v1.7.12/actionlint_1.7.12_linux_amd64.tar.gz",
            "sha256": "8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8",
            "member": "actionlint",
        },
    },
    "aarch64": {
        "shellcheck": {
            "version": "0.11.0",
            "url": "https://github.com/koalaman/shellcheck/releases/download/v0.11.0/shellcheck-v0.11.0.linux.aarch64.tar.xz",
            "sha256": "12b331c1d2db6b9eb13cfca64306b1b157a86eb69db83023e261eaa7e7c14588",
            "member": "shellcheck-v0.11.0/shellcheck",
        },
        "actionlint": {
            "version": "1.7.12",
            "url": "https://github.com/rhysd/actionlint/releases/download/v1.7.12/actionlint_1.7.12_linux_arm64.tar.gz",
            "sha256": "325e971b6ba9bfa504672e29be93c24981eeb1c07576d730e9f7c8805afff0c6",
            "member": "actionlint",
        },
    },
}


def install_spec(machine: str) -> dict[str, dict[str, str]]:
    aliases = {"amd64": "x86_64", "arm64": "aarch64"}
    key = aliases.get(machine, machine)
    if key not in SPECS:
        raise LintError(f"unsupported runner architecture: {machine}")
    return SPECS[key]


def validate_exclusions(value: str) -> list[str]:
    patterns = [line.strip() for line in value.splitlines() if line.strip()]
    if len(patterns) > 64:
        raise LintError("at most 64 exclusion patterns are allowed")
    for pattern in patterns:
        path = Path(pattern)
        if path.is_absolute() or ".." in path.parts or "\0" in pattern:
            raise LintError(f"unsafe exclusion pattern: {pattern}")
    return patterns


def _excluded(path: str, patterns: Iterable[str]) -> bool:
    return any(fnmatch.fnmatchcase(path, pattern) for pattern in patterns)


def discover_files(tracked: Iterable[str], exclusions: Iterable[str]) -> dict[str, list[str]]:
    clean = sorted({path for path in tracked if path and not _excluded(path, exclusions)})
    shell = [path for path in clean if Path(path).suffix in {".sh", ".bash"}]
    actions = [
        path
        for path in clean
        if (
            path.startswith(".github/workflows/")
            and Path(path).suffix in {".yml", ".yaml"}
        )
        or (
            path.startswith(".github/actions/")
            and Path(path).name in {"action.yml", "action.yaml"}
        )
    ]
    return {"shell": shell, "actions": actions}


def _run(argv: Sequence[str], cwd: Path) -> dict[str, Any]:
    try:
        proc = subprocess.run(
            list(argv), cwd=cwd, capture_output=True, text=True, check=False, timeout=900
        )
        output = ((proc.stdout or "") + (proc.stderr or ""))[-1_000_000:]
        exit_code = proc.returncode
    except subprocess.TimeoutExpired:
        output = "lint command exceeded the 900-second timeout\n"
        exit_code = 124
    if output:
        print(output, end="" if output.endswith("\n") else "\n")
    return {"exit_code": exit_code, "output": output}


def safe_actionlint_argv(actionlint: Path, workflows: Sequence[str]) -> list[str]:
    return [
        str(actionlint),
        "-format",
        "{{.Filepath}}:{{.Line}}:{{.Column}}: [{{.Kind}}] {{.Message}}",
        *workflows,
    ]


def _validate_composite_actions(root: Path, paths: Iterable[str]) -> list[dict[str, str]]:
    try:
        import yaml  # type: ignore
    except ImportError as exc:
        raise LintError("PyYAML is required for composite action metadata validation") from exc
    failures: list[dict[str, str]] = []
    for relative in paths:
        if not relative.startswith(".github/actions/"):
            continue
        try:
            data = yaml.safe_load((root / relative).read_text(encoding="utf-8"))
        except Exception as exc:
            failures.append({"path": relative, "error": f"invalid YAML: {exc}"})
            continue
        if not isinstance(data, dict):
            failures.append({"path": relative, "error": "metadata must be a mapping"})
            continue
        for field in ("name", "description", "runs"):
            if field not in data:
                failures.append({"path": relative, "error": f"missing required key: {field}"})
        runs = data.get("runs")
        if not isinstance(runs, dict) or runs.get("using") not in {"composite", "node20", "node24", "docker"}:
            failures.append({"path": relative, "error": "runs.using is missing or unsupported"})
        if isinstance(runs, dict) and runs.get("using") == "composite" and not isinstance(runs.get("steps"), list):
            failures.append({"path": relative, "error": "composite actions require runs.steps"})
    return failures


def run_lints(
    *,
    root: Path,
    shellcheck: Path,
    actionlint: Path,
    severity: str,
    exclusions: list[str],
    evidence_dir: Path,
) -> int:
    if severity not in {"error", "warning", "info", "style"}:
        raise LintError("shellcheck severity must be error, warning, info, or style")
    for tool in (shellcheck, actionlint):
        if not tool.is_file() or not os.access(tool, os.X_OK):
            raise LintError(f"lint tool is missing or non-executable: {tool}")
    tracked = subprocess.run(
        ["git", "ls-files", "-z"], cwd=root, capture_output=True, check=True
    ).stdout.decode().split("\0")
    files = discover_files(tracked, exclusions)
    evidence_dir.mkdir(parents=True, exist_ok=True)
    results: dict[str, Any] = {"files": files, "tools": {}, "commands": {}}
    status = 0
    results["tools"]["shellcheck"] = _run([str(shellcheck), "--version"], root)["output"].splitlines()[0:2]
    results["tools"]["actionlint"] = _run([str(actionlint), "-version"], root)["output"].strip()
    if files["shell"]:
        result = _run([str(shellcheck), "--severity", severity, "--format", "gcc", *files["shell"]], root)
        results["commands"]["shellcheck"] = {"exit_code": result["exit_code"]}
        (evidence_dir / "shellcheck.txt").write_text(result["output"], encoding="utf-8")
        status = max(status, int(result["exit_code"] != 0))
    workflows = [path for path in files["actions"] if path.startswith(".github/workflows/")]
    if workflows:
        result = _run(safe_actionlint_argv(actionlint, workflows), root)
        results["commands"]["actionlint"] = {"exit_code": result["exit_code"]}
        (evidence_dir / "actionlint.txt").write_text(result["output"], encoding="utf-8")
        status = max(status, int(result["exit_code"] != 0))
    metadata_failures = _validate_composite_actions(root, files["actions"])
    results["composite_action_failures"] = metadata_failures
    if metadata_failures:
        status = 1
    results["result"] = "passed" if status == 0 else "failed"
    results["generated_at"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    (evidence_dir / "evidence.json").write_text(
        json.dumps(results, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return status


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True)
    parser.add_argument("--shellcheck", required=True)
    parser.add_argument("--actionlint", required=True)
    parser.add_argument("--severity", default="warning")
    parser.add_argument("--exclusions", default="")
    parser.add_argument("--evidence-dir", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        return run_lints(
            root=Path(args.root).resolve(),
            shellcheck=Path(args.shellcheck).resolve(),
            actionlint=Path(args.actionlint).resolve(),
            severity=args.severity,
            exclusions=validate_exclusions(args.exclusions),
            evidence_dir=Path(args.evidence_dir),
        )
    except (LintError, OSError, subprocess.CalledProcessError) as exc:
        print(f"static lint error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
