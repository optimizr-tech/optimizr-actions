#!/usr/bin/env python3
"""Audit selected organization workflows through GitHub's contents API."""

from __future__ import annotations

import argparse
import base64
from collections import Counter
from dataclasses import asdict, dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import sys
from typing import Any, Iterable, Mapping, Sequence
from urllib import error, parse, request

API_ROOT = "https://api.github.com"
TEMPORARY_ACTIONS_SHA = "7925034d32f769326a45f6af155c95dac6aefc55"
REPO_RE = re.compile(r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$")
USES_RE = re.compile(r"(?m)^\s*-?\s*uses:\s*([^\s#]+)")
INTERNAL_REF_RE = re.compile(r"optimizr-tech/optimizr-actions/(?:\.github/(?:workflows|actions)/[^@\s]+)@([^\s#]+)")
THIRD_PARTY_RE = re.compile(r"^(?!\./)([^/\s]+)/([^@\s]+)@([^\s]+)$")
PR_BILLING_SKIP_GUARD_RE = re.compile(
    r"!\s*contains\(\s*github\.event\.pull_request\.title\s*,\s*"
    r"['\"]\[skip-tests\]['\"]\s*\)",
    re.MULTILINE,
)
WRITE_PERMISSIONS = {"contents", "actions", "issues", "pull-requests", "security-events", "packages", "id-token"}
START_MARKER = "<!-- optimizr-actions-audit:start -->"
END_MARKER = "<!-- optimizr-actions-audit:end -->"
MAX_WORKFLOW_BYTES = 2 * 1024 * 1024
MAX_REPOSITORIES = 100


class AuditError(ValueError):
    """Raised when audit configuration or API responses violate the contract."""


@dataclass(frozen=True)
class Finding:
    repository: str
    visibility: str
    workflow_path: str
    rule_id: str
    message: str


def public_alias(repository: str, visibility: str) -> str:
    if visibility == "public":
        return repository
    return "private-" + hashlib.sha256(repository.encode("utf-8")).hexdigest()[:12]


def _on_block(content: str) -> str:
    lines = content.splitlines()
    start = None
    for index, line in enumerate(lines):
        if line.strip() == "on:" and not line.startswith((" ", "\t")):
            start = index + 1
            break
    if start is None:
        return ""
    selected: list[str] = []
    for line in lines[start:]:
        if line and not line.startswith((" ", "\t", "#")):
            break
        selected.append(line)
    return "\n".join(selected)


def _has_event(on_block: str, event: str) -> bool:
    if re.search(rf"(?m)^\s{{2,}}{re.escape(event)}\s*:", on_block):
        return True
    return bool(re.search(rf"\b{re.escape(event)}\b", on_block))


def _event_has_path_filter(on_block: str, event: str) -> bool:
    lines = on_block.splitlines()
    event_indent = None
    event_index = None
    for index, line in enumerate(lines):
        match = re.match(rf"^(\s+){re.escape(event)}\s*:", line)
        if match:
            event_indent = len(match.group(1))
            event_index = index
            break
    if event_index is None or event_indent is None:
        return False
    for line in lines[event_index + 1:]:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip())
        if indent <= event_indent:
            break
        if re.match(r"^\s+(paths|paths-ignore)\s*:", line):
            return True
    return False


def _write_permissions(content: str) -> set[str]:
    result: set[str] = set()
    lines = content.splitlines()
    for index, line in enumerate(lines):
        match = re.match(r"^(\s*)permissions\s*:\s*$", line)
        if not match:
            continue
        base_indent = len(match.group(1))
        for child in lines[index + 1:]:
            if not child.strip() or child.lstrip().startswith("#"):
                continue
            indent = len(child) - len(child.lstrip())
            if indent <= base_indent:
                break
            permission = re.match(r"^\s*([A-Za-z-]+)\s*:\s*write\s*(?:#.*)?$", child)
            if permission and permission.group(1) in WRITE_PERMISSIONS:
                result.add(permission.group(1))
    return result


def audit_workflows(repository: str, visibility: str, workflows: Mapping[str, str]) -> list[Finding]:
    findings: list[Finding] = []
    for path, content in sorted(workflows.items()):
        def add(rule_id: str, message: str) -> None:
            findings.append(Finding(repository, visibility, path, rule_id, message))

        if "optimizr-tech/optimizr-infra-ops/.github/" in content:
            add("LEGACY_INFRA_OPS_REUSABLE", "Portable automation still references the legacy infra-ops host.")
        if TEMPORARY_ACTIONS_SHA in content:
            add("TEMPORARY_ACTIONS_SHA", "Workflow still references the temporary semantic-release compatibility SHA.")
        for ref in INTERNAL_REF_RE.findall(content):
            if ref != "v1":
                add("INTERNAL_REF_NOT_V1", "First-party portable automation does not use the governed floating v1 contract.")
                break
        for use in USES_RE.findall(content):
            match = THIRD_PARTY_RE.fullmatch(use)
            if not match:
                continue
            owner, _name, ref = match.groups()
            if owner == "optimizr-tech":
                continue
            if not re.fullmatch(r"[0-9a-f]{40}", ref):
                add("UNPINNED_THIRD_PARTY_ACTION", "A third-party action is not pinned to an immutable 40-character commit SHA.")
                break
        permissions = _write_permissions(content)
        if permissions:
            add("BROAD_WORKFLOW_PERMISSION", "Workflow grants write permissions that require job-level least-privilege review: " + ", ".join(sorted(permissions)) + ".")
        on_block = _on_block(content)
        if Path(path).name in {"ci.yml", "deploy.yml", "test.yml"}:
            for event in ("push", "pull_request"):
                if _has_event(on_block, event) and not _event_has_path_filter(on_block, event):
                    add("MISSING_PATH_FILTER", f"{event} trigger has no paths or paths-ignore filter.")
                    break
        if _has_event(on_block, "pull_request") and ("self-hosted" in content or re.search(r"runner_json\s*:\s*.*self-hosted", content)):
            add("SELF_HOSTED_PULL_REQUEST", "Pull-request workflow may route untrusted candidate code to a persistent self-hosted runner.")
        basename = Path(path).name
        if basename == "update-badges.yml" and "_release-badge-recovery.yml@v1" not in content:
            add("DUPLICATED_BADGE_WORKFLOW", "Release badge recovery is implemented inline instead of calling the canonical reusable.")
        if basename == "commitlint.yml" and "optimizr-actions/.github/workflows/_commitlint.yml@v1" not in content:
            add("DUPLICATED_COMMITLINT_WORKFLOW", "Commitlint does not call the canonical optimizr-actions reusable.")
        if basename == "validate-pr.yml" and "optimizr-actions/.github/workflows/_validate-pr.yml@v1" not in content:
            add("DUPLICATED_PR_VALIDATION", "Pull-request validation does not call the canonical optimizr-actions reusable.")
        if (
            _has_event(on_block, "pull_request")
            and "optimizr-actions/.github/workflows/" in content
            and not PR_BILLING_SKIP_GUARD_RE.search(content)
        ):
            add(
                "MISSING_PR_BILLING_SKIP_GUARD",
                "Pull-request workflow has no caller-level [skip-tests] guard before its reusable dependency chain, so a billing outage can fail before the reusable starts.",
            )
    return findings


def render_json(findings: Iterable[Finding], *, public: bool) -> dict[str, Any]:
    items = list(findings)
    records = []
    for finding in items:
        record = asdict(finding)
        record["repository"] = public_alias(finding.repository, finding.visibility) if public else finding.repository
        record.pop("visibility", None)
        records.append(record)
    counts = Counter(record["rule_id"] for record in records)
    return {
        "schema_version": 1,
        "public_redaction": public,
        "finding_count": len(records),
        "rule_counts": dict(sorted(counts.items())),
        "findings": records,
    }


def render_markdown(findings: Iterable[Finding], *, public: bool) -> str:
    items = list(findings)
    title = "# Optimizr Actions adoption audit"
    lines = [title, "", f"Findings: **{len(items)}**", ""]
    if not items:
        lines.append("No findings.")
        return "\n".join(lines) + "\n"
    lines.extend(["| Repository | Workflow | Rule | Finding |", "|---|---|---|---|"])
    for finding in items:
        repository = public_alias(finding.repository, finding.visibility) if public else finding.repository
        path = finding.workflow_path.replace("|", "\\|")
        message = finding.message.replace("|", "\\|")
        lines.append(f"| `{repository}` | `{path}` | `{finding.rule_id}` | {message} |")
    return "\n".join(lines) + "\n"


def update_marked_section(body: str, report: str) -> str:
    section = f"{START_MARKER}\n{report.rstrip()}\n{END_MARKER}"
    pattern = re.compile(re.escape(START_MARKER) + r".*?" + re.escape(END_MARKER), re.DOTALL)
    if pattern.search(body):
        return pattern.sub(section, body)
    separator = "\n" if body.endswith("\n") or not body else "\n\n"
    return body + separator + section + "\n"


def _api_json(url: str, token: str, *, method: str = "GET", payload: Mapping[str, Any] | None = None) -> Any:
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = request.Request(url, data=data, method=method, headers={
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "optimizr-actions-adoption-audit/1",
    })
    try:
        with request.urlopen(req, timeout=30) as response:
            return json.load(response)
    except error.HTTPError as exc:
        if exc.code == 404:
            return None
        raise AuditError(f"GitHub API request failed with HTTP {exc.code}") from exc
    except (error.URLError, OSError, json.JSONDecodeError) as exc:
        raise AuditError("GitHub API request failed") from exc


def _fetch_workflows(repository: str, token: str) -> tuple[str, dict[str, str]]:
    metadata = _api_json(f"{API_ROOT}/repos/{repository}", token)
    if not isinstance(metadata, Mapping):
        raise AuditError("repository metadata is unavailable")
    visibility = str(metadata.get("visibility", "private"))
    listing = _api_json(f"{API_ROOT}/repos/{repository}/contents/.github/workflows", token)
    if listing is None:
        return visibility, {}
    if not isinstance(listing, list):
        raise AuditError("workflow directory response is invalid")
    workflows: dict[str, str] = {}
    for item in listing:
        if not isinstance(item, Mapping) or item.get("type") != "file":
            continue
        path = str(item.get("path", ""))
        if not path.endswith((".yml", ".yaml")):
            continue
        file_data = _api_json(f"{API_ROOT}/repos/{repository}/contents/{parse.quote(path)}", token)
        if not isinstance(file_data, Mapping) or file_data.get("encoding") != "base64":
            raise AuditError("workflow content response is invalid")
        encoded = str(file_data.get("content", "")).replace("\n", "")
        raw = base64.b64decode(encoded, validate=True)
        if len(raw) > MAX_WORKFLOW_BYTES:
            raise AuditError("workflow exceeds the audit size limit")
        workflows[path] = raw.decode("utf-8")
    return visibility, workflows


def _repositories_from_env(name: str) -> list[str]:
    raw = os.environ.get(name, "")
    repositories = [line.strip() for line in raw.replace(",", "\n").splitlines() if line.strip()]
    if not 1 <= len(repositories) <= MAX_REPOSITORIES or len(set(repositories)) != len(repositories):
        raise AuditError(f"{name} must contain 1-{MAX_REPOSITORIES} unique repositories")
    if any(not REPO_RE.fullmatch(repository) for repository in repositories):
        raise AuditError(f"{name} contains an invalid owner/name repository")
    return repositories


def _audit_selected(repositories: Sequence[str], token: str) -> list[Finding]:
    findings: list[Finding] = []
    for repository in repositories:
        visibility, workflows = _fetch_workflows(repository, token)
        findings.extend(audit_workflows(repository, visibility, workflows))
    return findings


def _update_issue(issue_ref: str, token: str, report: str) -> None:
    match = re.fullmatch(r"([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)#([1-9][0-9]*)", issue_ref)
    if not match:
        raise AuditError("issue reference must use owner/name#number")
    repository, number = match.groups()
    issue_url = f"{API_ROOT}/repos/{repository}/issues/{number}"
    issue = _api_json(issue_url, token)
    if not isinstance(issue, Mapping):
        raise AuditError("central audit issue is unavailable")
    body = str(issue.get("body") or "")
    updated = update_marked_section(body, report)
    if updated != body:
        _api_json(issue_url, token, method="PATCH", payload={"body": updated})


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repositories-env", required=True)
    parser.add_argument("--token-env", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--public", action="store_true")
    parser.add_argument("--issue-ref-env", default="")
    parser.add_argument("--issue-token-env", default="")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        repositories = _repositories_from_env(args.repositories_env)
        token = os.environ.get(args.token_env, "")
        if not token:
            raise AuditError("audit token is missing")
        findings = _audit_selected(repositories, token)
        output = Path(args.output_dir)
        output.mkdir(parents=True, exist_ok=True)
        (output / "report.json").write_text(json.dumps(render_json(findings, public=args.public), indent=2, sort_keys=True) + "\n", encoding="utf-8")
        markdown = render_markdown(findings, public=args.public)
        (output / "report.md").write_text(markdown, encoding="utf-8")
        if args.issue_ref_env:
            issue_ref = os.environ.get(args.issue_ref_env, "")
            issue_token = os.environ.get(args.issue_token_env, "") if args.issue_token_env else ""
            if issue_ref:
                if args.public:
                    raise AuditError("public report must not update the private central issue")
                if not issue_token:
                    raise AuditError("issue update token is missing")
                _update_issue(issue_ref, issue_token, markdown)
        print(f"Audit completed: repositories={len(repositories)} findings={len(findings)} public={args.public}")
        return 0
    except (AuditError, OSError, UnicodeDecodeError, ValueError) as exc:
        print(f"organization audit error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
