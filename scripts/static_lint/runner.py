#!/usr/bin/env python3
"""Deterministic ShellCheck, actionlint, and composite-action metadata runner."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import fnmatch
import json
from pathlib import Path
import re
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


def _run(argv: Sequence[str], cwd: Path, *, print_output: bool = True) -> dict[str, Any]:
    proc = subprocess.run(list(argv), cwd=cwd, capture_output=True, text=True, check=False)
    output = ((proc.stdout or "") + (proc.stderr or ""))[-1_000_000:]
    if output and print_output:
        print(output, end="" if output.endswith("\n") else "\n")
    return {"argv": list(argv), "exit_code": proc.returncode, "output": output}


def _has_queue_key_candidate(content: str) -> bool:
    pattern = r"(?m)(?:^\s*|[,{]\s*)(?:['\"]queue['\"]|queue)\s*:"
    return re.search(pattern, content) is not None


def _location_for_concurrency(path: tuple[str | None, ...]) -> bool:
    return path == ("concurrency",) or (
        len(path) == 3
        and path[0] == "jobs"
        and path[1] is not None
        and path[2] == "concurrency"
    )


def validate_concurrency_queue_contract(
    root: Path,
    workflows: Sequence[str],
) -> tuple[dict[str, set[tuple[int, int]]], list[dict[str, str]]]:
    """Validate GitHub's concurrency.queue contract and return safe lint exceptions.

    actionlint 1.7.12 predates this GitHub Actions property. Only queue keys that
    pass this companion contract can be exempted from its exact unsupported-key
    diagnostic; all other diagnostics remain blocking.
    """
    try:
        import yaml  # type: ignore
        from yaml.nodes import MappingNode, ScalarNode, SequenceNode
    except ImportError as exc:
        raise LintError("PyYAML is required for concurrency queue validation") from exc

    allowed: dict[str, set[tuple[int, int]]] = {}
    failures: list[dict[str, str]] = []

    for relative in workflows:
        source = (root / relative).read_text(encoding="utf-8")
        if not _has_queue_key_candidate(source):
            continue
        try:
            document = yaml.compose(source, Loader=yaml.SafeLoader)
        except yaml.YAMLError as exc:
            mark = getattr(exc, "problem_mark", None)
            location = (
                f" near line {mark.line + 1}, column {mark.column + 1}"
                if mark is not None
                else ""
            )
            failures.append({
                "path": relative,
                "error": f"queue workflow YAML is invalid{location}",
            })
            continue
        if document is None:
            failures.append({"path": relative, "error": "queue workflow is empty"})
            continue

        file_locations: set[tuple[int, int]] = set()

        def visit(node: Any, mapping_path: tuple[str | None, ...] = ()) -> None:
            if isinstance(node, MappingNode):
                queue_entries = [
                    (key_node, value_node)
                    for key_node, value_node in node.value
                    if isinstance(key_node, ScalarNode) and key_node.value == "queue"
                ]
                if queue_entries:
                    if not _location_for_concurrency(mapping_path):
                        for key_node, _ in queue_entries:
                            failures.append({
                                "path": relative,
                                "error": (
                                    "queue is only supported directly under workflow-level or "
                                    f"job-level concurrency (line {key_node.start_mark.line + 1}, "
                                    f"column {key_node.start_mark.column + 1})"
                                ),
                            })
                    elif len(queue_entries) > 1:
                        for key_node, _ in queue_entries[1:]:
                            failures.append({
                                "path": relative,
                                "error": (
                                    "duplicate concurrency.queue keys are not supported "
                                    f"(line {key_node.start_mark.line + 1}, "
                                    f"column {key_node.start_mark.column + 1})"
                                ),
                            })
                    else:
                        key_node, queue_node = queue_entries[0]
                        cancel_entries = [
                            (cancel_key, value_node)
                            for cancel_key, value_node in node.value
                            if isinstance(cancel_key, ScalarNode)
                            and cancel_key.value == "cancel-in-progress"
                        ]
                        merge_entries = [
                            key_node
                            for key_node, _ in node.value
                            if isinstance(key_node, ScalarNode)
                            and key_node.value == "<<"
                        ]
                        problem: str | None = None
                        problem_node = key_node
                        valid_queue_value = (
                            isinstance(queue_node, ScalarNode)
                            and queue_node.tag == "tag:yaml.org,2002:str"
                            and queue_node.value in {"single", "max"}
                        )
                        if not valid_queue_value:
                            problem = "concurrency.queue must be the string 'single' or 'max'"
                        elif len(cancel_entries) > 1:
                            problem = "duplicate concurrency.cancel-in-progress keys are not supported"
                            problem_node = cancel_entries[1][0]
                        elif merge_entries:
                            problem = "YAML merge keys are not supported in concurrency mappings with queue"
                            problem_node = merge_entries[0]
                        elif queue_node.value == "max" and cancel_entries:
                            cancel_key, cancel_node = cancel_entries[0]
                            if not (
                                isinstance(cancel_node, ScalarNode)
                                and cancel_node.tag == "tag:yaml.org,2002:bool"
                                and cancel_node.value.lower() == "false"
                            ):
                                problem = (
                                    "concurrency.queue: max requires cancel-in-progress "
                                    "to be omitted or false"
                                )
                                problem_node = cancel_key
                        if problem:
                            failures.append({
                                "path": relative,
                                "error": (
                                    f"{problem} (line {problem_node.start_mark.line + 1}, "
                                    f"column {problem_node.start_mark.column + 1})"
                                ),
                            })
                        else:
                            file_locations.add(
                                (key_node.start_mark.line + 1, key_node.start_mark.column + 1)
                            )

                for key_node, value_node in node.value:
                    key = key_node.value if isinstance(key_node, ScalarNode) else None
                    visit(value_node, (*mapping_path, key))
            elif isinstance(node, SequenceNode):
                for item in node.value:
                    visit(item, (*mapping_path, None))

        visit(document)
        if file_locations:
            allowed[Path(relative).as_posix()] = file_locations

    return allowed, failures


def filter_actionlint_queue_errors(
    output: str,
    valid_locations: dict[str, set[tuple[int, int]]],
) -> tuple[str, int, bool]:
    """Suppress only the known actionlint error at a contract-validated key."""
    kept: list[str] = []
    suppressed = 0
    parseable = True
    expected_message = 'unexpected key "queue" for "concurrency" section'

    for line in output.splitlines(keepends=True):
        if not line.strip():
            kept.append(line)
            continue
        try:
            diagnostic = json.loads(line)
        except json.JSONDecodeError:
            parseable = False
            kept.append(line)
            continue
        if not isinstance(diagnostic, dict):
            parseable = False
            kept.append(line)
            continue

        filepath = diagnostic.get("Filepath")
        line_number = diagnostic.get("Line")
        column = diagnostic.get("Column")
        if not (
            isinstance(filepath, str)
            and type(line_number) is int
            and type(column) is int
            and isinstance(diagnostic.get("Message"), str)
            and isinstance(diagnostic.get("Kind"), str)
        ):
            parseable = False
            kept.append(line)
            continue

        normalized_path = filepath.replace("\\", "/")
        while normalized_path.startswith("./"):
            normalized_path = normalized_path[2:]
        if (
            diagnostic["Message"] == expected_message
            and diagnostic["Kind"] == "syntax-check"
            and (line_number, column) in valid_locations.get(normalized_path, set())
        ):
            suppressed += 1
        else:
            kept.append(line)

    return "".join(kept), suppressed, parseable


def effective_actionlint_exit_code(
    exit_code: int,
    filtered_output: str,
    suppressed_count: int,
    parseable: bool,
) -> int:
    if exit_code == 0 and filtered_output.strip() and not parseable:
        return 2
    if (
        exit_code == 1
        and suppressed_count > 0
        and parseable
        and not filtered_output.strip()
    ):
        return 0
    return exit_code


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


def run_lints(*, root: Path, shellcheck: Path, actionlint: Path, severity: str, exclusions: list[str], evidence_dir: Path) -> int:
    if severity not in {"error", "warning", "info", "style"}:
        raise LintError("shellcheck severity must be error, warning, info, or style")
    tracked = subprocess.run(["git", "ls-files", "-z"], cwd=root, capture_output=True, check=True).stdout.decode().split("\0")
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
        valid_queue_locations, queue_failures = validate_concurrency_queue_contract(root, workflows)
        results["concurrency_queue_failures"] = queue_failures
        for failure in queue_failures:
            print(f"concurrency queue contract: {failure['path']}: {failure['error']}")
        result = _run(
            [str(actionlint), "-format", "{{json .}}", *workflows],
            root,
            print_output=False,
        )
        filtered_output, suppressed_count, parseable = filter_actionlint_queue_errors(
            result["output"],
            valid_queue_locations,
        )
        if filtered_output:
            print(filtered_output, end="" if filtered_output.endswith("\n") else "\n")
        if suppressed_count:
            print(
                "actionlint compatibility: accepted "
                f"{suppressed_count} validated concurrency.queue diagnostic(s)"
            )
        effective_exit_code = effective_actionlint_exit_code(
            result["exit_code"],
            filtered_output,
            suppressed_count,
            parseable,
        )
        results["commands"]["actionlint"] = {
            "exit_code": result["exit_code"],
            "effective_exit_code": effective_exit_code,
            "suppressed_queue_diagnostics": suppressed_count,
        }
        (evidence_dir / "actionlint.jsonl").write_text(result["output"], encoding="utf-8")
        (evidence_dir / "actionlint.filtered.jsonl").write_text(filtered_output, encoding="utf-8")
        status = max(status, int(effective_exit_code != 0), int(bool(queue_failures)))
    metadata_failures = _validate_composite_actions(root, files["actions"])
    results["composite_action_failures"] = metadata_failures
    if metadata_failures:
        status = 1
    results["result"] = "passed" if status == 0 else "failed"
    results["generated_at"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    (evidence_dir / "evidence.json").write_text(json.dumps(results, indent=2, sort_keys=True) + "\n", encoding="utf-8")
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
        return run_lints(root=Path(args.root).resolve(), shellcheck=Path(args.shellcheck).resolve(), actionlint=Path(args.actionlint).resolve(), severity=args.severity, exclusions=validate_exclusions(args.exclusions), evidence_dir=Path(args.evidence_dir))
    except (LintError, OSError, subprocess.CalledProcessError) as exc:
        print(f"static lint error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
