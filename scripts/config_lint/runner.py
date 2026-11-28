from __future__ import annotations

import argparse
import datetime as dt
import fnmatch
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys


HADOLINT_IMAGE = (
    "hadolint/hadolint@sha256:"
    "32dac94127fd60b7b7e3fbfc65e1383b9b5e25c9bfd7b8536de7a539fe68a12d"
)
RULES = {
    "privileged": "service sets privileged: true",
    "host-network": "service uses network_mode: host",
    "published-port": "service publishes a port outside the allowlist",
    "image-digest": "service image is not pinned by digest",
    "read-only": "required service does not set read_only: true",
    "cap-drop": "required service does not drop ALL capabilities",
}
SEVERITIES = {"error", "warning", "info", "style"}


def _fail(message: str) -> None:
    raise ValueError(message)


def load_policy(path: Path) -> dict:
    try:
        policy = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        _fail(f"cannot read policy JSON: {exc}")
    if not isinstance(policy, dict) or policy.get("version") != 1:
        _fail("policy must be an object with version 1")
    fail_on = policy.get("fail_on")
    if not isinstance(fail_on, list) or any(
        not isinstance(value, str) or value not in SEVERITIES for value in fail_on
    ):
        _fail("fail_on must be a list of hadolint severities")
    compose = policy.get("compose")
    if not isinstance(compose, dict):
        _fail("compose policy must be an object")
    allow_ports = compose.get("allowed_published_ports", [])
    if not isinstance(allow_ports, list) or any(
        not isinstance(port, (str, int)) for port in allow_ports
    ):
        _fail("compose.allowed_published_ports must contain strings or integers")
    for key in ("require_read_only", "require_cap_drop"):
        if not isinstance(compose.get(key, []), list) or any(
            not isinstance(item, str) or not item for item in compose.get(key, [])
        ):
            _fail(f"compose.{key} must be a list of service names")
    severities = compose.get("severities", {})
    if not isinstance(severities, dict) or any(
        rule not in RULES or severity not in SEVERITIES
        for rule, severity in severities.items()
    ):
        _fail("compose.severities contains an unknown rule or severity")
    exceptions = policy.get("exceptions", [])
    if not isinstance(exceptions, list):
        _fail("exceptions must be a list")
    today = dt.date.today()
    for exception in exceptions:
        if not isinstance(exception, dict) or not all(
            isinstance(exception.get(key), str) and exception[key].strip()
            for key in ("rule", "reason", "expires")
        ):
            _fail("each exception needs rule, reason, and expires")
        if exception["rule"] not in RULES and not re.fullmatch(
            r"hadolint:[A-Z]{2}[0-9]{4}", exception["rule"]
        ):
            _fail(f"unknown exception rule: {exception['rule']}")
        try:
            expiry = dt.date.fromisoformat(exception["expires"])
        except ValueError:
            _fail("exception expires must use ISO date YYYY-MM-DD")
        if expiry < today:
            _fail(f"exception for {exception['rule']} expired on {expiry.isoformat()}")
        for scope in ("path", "service"):
            if scope in exception and (
                not isinstance(exception[scope], str) or not exception[scope].strip()
            ):
                _fail(f"exception {scope} must be a non-empty string")
    return policy


def tracked_files(root: Path) -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files", "-z"], cwd=root, check=True, capture_output=True
    )
    paths = result.stdout.decode("utf-8").split("\0")
    return [root / path for path in paths if path and (root / path).is_file()]


def discover_dockerfiles(root: Path) -> list[Path]:
    return sorted(
        path
        for path in tracked_files(root)
        if PurePosixPath(path.relative_to(root).as_posix()).name.startswith("Dockerfile")
    )


def discover_compose_files(root: Path, requested: str) -> list[Path]:
    tracked = tracked_files(root)
    if requested.strip():
        patterns = requested.split()
        selected = [
            path for path in tracked
            if any(fnmatch.fnmatch(path.relative_to(root).as_posix(), pattern) for pattern in patterns)
        ]
        missing = [pattern for pattern in patterns if not any(
            fnmatch.fnmatch(path.relative_to(root).as_posix(), pattern) for path in selected
        )]
        if missing:
            _fail("compose_files patterns matched no tracked files: " + ", ".join(missing))
        return sorted(set(selected))
    return sorted(
        path for path in tracked
        if re.match(r"^(?:docker-)?compose(?:[-.].*)?\.ya?ml$", path.name)
    )


def exception_matches(policy: dict, rule: str, path: str, service: str = "") -> bool:
    for item in policy.get("exceptions", []):
        if item["rule"] != rule:
            continue
        if item.get("path", path) != path or item.get("service", service) != service:
            continue
        return True
    return False


def emit_finding(policy: dict, finding: dict, failures: list[dict]) -> None:
    severity = finding["severity"]
    label = finding.get("path") or finding.get("service") or "configuration"
    message = finding["message"].replace("\n", " ")
    annotation = "error" if severity == "error" else "warning" if severity == "warning" else "notice"
    print(f"::{annotation} file={label}::{message}")
    failures.append(finding)


def run_hadolint(root: Path, files: list[Path], policy: dict, failures: list[dict]) -> None:
    for path in files:
        relative = path.relative_to(root).as_posix()
        result = subprocess.run(
            # The hadolint image has no ENTRYPOINT: the binary must be the command.
            ["docker", "run", "--rm", "-v", f"{root}:/workspace:ro", HADOLINT_IMAGE,
             "hadolint", "--format", "json", f"/workspace/{relative}"],
            cwd=root, capture_output=True, text=True,
        )
        if result.returncode not in (0, 1):
            _fail(f"hadolint could not scan {relative}: {result.stderr.strip()}")
        try:
            findings = json.loads(result.stdout or "[]")
        except json.JSONDecodeError as exc:
            _fail(f"hadolint returned invalid JSON for {relative}: {exc}")
        for item in findings:
            rule = item.get("code", "unknown")
            severity = str(item.get("level", "warning")).lower()
            if severity not in SEVERITIES:
                severity = "warning"
            finding = {
                "rule": f"hadolint:{rule}", "severity": severity, "path": relative,
                "message": f"{rule}: {item.get('message', 'lint finding')}",
            }
            if exception_matches(policy, finding["rule"], relative):
                continue
            emit_finding(policy, finding, failures)


def compose_config(root: Path, files: list[Path]) -> dict:
    command = ["docker", "compose"]
    for path in files:
        command.extend(["-f", str(path.relative_to(root))])
    result = subprocess.run(
        command + ["config", "--format", "json"], cwd=root, capture_output=True, text=True
    )
    if result.returncode:
        _fail(f"docker compose config failed with exit code {result.returncode}")
    try:
        config = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        _fail(f"docker compose returned invalid JSON: {exc}")
    if not isinstance(config, dict) or not isinstance(config.get("services"), dict):
        _fail("docker compose config must contain a services object")
    return config


def run_compose(root: Path, files: list[Path], policy: dict, failures: list[dict]) -> None:
    if not files:
        print("::notice::No tracked Compose files found; Compose policy checks skipped")
        return
    compose_policy = policy["compose"]
    allowed_ports = {str(port) for port in compose_policy.get("allowed_published_ports", [])}
    required_read = set(compose_policy.get("require_read_only", []))
    required_caps = set(compose_policy.get("require_cap_drop", []))
    severities = compose_policy.get("severities", {})
    seen_services: set[str] = set()
    for path in files:
        config = compose_config(root, [path])
        for name, service in config["services"].items():
            seen_services.add(name)
            rules = []
            if service.get("privileged") is True:
                rules.append("privileged")
            if service.get("network_mode") == "host":
                rules.append("host-network")
            for port in service.get("ports", []):
                published = str(port.get("published", ""))
                if published and published not in allowed_ports:
                    rules.append("published-port")
            image = service.get("image", "")
            if image and not re.search(r"@sha256:[0-9a-f]{64}$", image):
                rules.append("image-digest")
            if name in required_read and service.get("read_only") is not True:
                rules.append("read-only")
            cap_drop = service.get("cap_drop", [])
            if name in required_caps and not any(str(value).upper() == "ALL" for value in cap_drop):
                rules.append("cap-drop")
            for rule in sorted(set(rules)):
                finding = {
                    "rule": rule, "severity": severities.get(rule, "error"),
                    "path": path.relative_to(root).as_posix(), "service": name,
                    "message": f"{name}: {RULES[rule]}",
                }
                if exception_matches(policy, rule, finding["path"], name):
                    continue
                emit_finding(policy, finding, failures)
    for service in sorted((required_read | required_caps) - seen_services):
        _fail(f"required service is absent from Compose configuration: {service}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--compose-files", default="")
    args = parser.parse_args()
    root = args.root.resolve()
    summary = Path(os.environ.get("GITHUB_STEP_SUMMARY", root / "config-lint-summary.md"))
    findings: list[dict] = []
    try:
        policy_path = args.policy if args.policy.is_absolute() else root / args.policy
        policy_path = policy_path.resolve()
        if not policy_path.is_relative_to(root):
            _fail("policy_file must resolve inside the caller repository")
        policy = load_policy(policy_path)
        dockerfiles = discover_dockerfiles(root)
        compose_files = discover_compose_files(root, args.compose_files)
        if dockerfiles:
            run_hadolint(root, dockerfiles, policy, findings)
        else:
            print("::notice::No tracked Dockerfile* files found; hadolint skipped")
        run_compose(root, compose_files, policy, findings)
    except (ValueError, OSError, subprocess.CalledProcessError) as exc:
        print(f"::error::{exc}", file=sys.stderr)
        summary.parent.mkdir(parents=True, exist_ok=True)
        with summary.open("a", encoding="utf-8") as handle:
            handle.write(f"\n# Configuration lint\n\nFailed: {exc}\n")
        return 2
    blocking = [item for item in findings if item["severity"] in policy["fail_on"]]
    lines = ["# Configuration lint", "", f"- Dockerfiles scanned: {len(dockerfiles)}",
             f"- Compose files scanned: {len(compose_files)}", f"- Findings: {len(findings)}",
             f"- Blocking findings: {len(blocking)}", ""]
    if findings:
        lines.extend(["| Severity | Rule | Target | Finding |", "|---|---|---|---|"])
        lines.extend(
            f"| {item['severity']} | {item['rule']} | {item.get('service') or item.get('path', '')} | {item['message']} |"
            for item in findings
        )
    else:
        lines.append("No policy-blocking findings.")
    summary.parent.mkdir(parents=True, exist_ok=True)
    with summary.open("a", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")
    return 1 if blocking else 0


if __name__ == "__main__":
    raise SystemExit(main())
