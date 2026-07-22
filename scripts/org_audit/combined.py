#!/usr/bin/env python3
"""Run the existing organization audit with additive security-adoption signals."""

from __future__ import annotations

import argparse
import base64
import json
import os
from pathlib import Path
import sys
from typing import Mapping, Sequence
from urllib import parse

from scripts.org_audit.audit import (
    API_ROOT,
    MAX_WORKFLOW_BYTES,
    AuditError,
    Finding,
    _api_json,
    _fetch_workflows,
    _repositories_from_env,
    _update_issue,
    audit_workflows,
    render_json,
    render_markdown,
)


def audit_security_adoption(
    repository: str,
    visibility: str,
    workflows: Mapping[str, str],
    dependabot_config: str | None,
) -> list[Finding]:
    """Return source-backed adoption drift without mutating a repository."""
    findings: list[Finding] = []
    contents = list(workflows.values())

    if dependabot_config is None:
        findings.append(
            Finding(
                repository,
                visibility,
                ".github/dependabot.yml",
                "MISSING_DEPENDABOT_CONFIG",
                "The organization Dependabot configuration is not present in the default branch.",
            )
        )

    if not any(
        "optimizr-actions/.github/workflows/_dependabot-security-automerge.yml@v1"
        in content
        for content in contents
    ):
        findings.append(
            Finding(
                repository,
                visibility,
                ".github/workflows/dependabot-security-automerge.yml",
                "MISSING_DEPENDABOT_AUTOMERGE",
                "The approved Dependabot native auto-merge caller is not present.",
            )
        )

    deploy_like = any(
        "deploy" in Path(path).stem.lower() or "docker compose up" in content
        for path, content in workflows.items()
    )
    canonical_deploy = any(
        "optimizr-actions/.github/workflows/_vps-self-hosted-deploy.yml@v1"
        in content
        or "optimizr-actions/.github/workflows/_vps-monorepo-deploy.yml@v1"
        in content
        for content in contents
    )
    if deploy_like and not canonical_deploy:
        findings.append(
            Finding(
                repository,
                visibility,
                ".github/workflows",
                "MISSING_CANONICAL_DEPLOY",
                "Deployment automation does not call an approved governed VPS reusable.",
            )
        )

    return findings


def _decode_optional_file(repository: str, token: str, path: str) -> str | None:
    payload = _api_json(
        f"{API_ROOT}/repos/{repository}/contents/{parse.quote(path)}", token
    )
    if payload is None:
        return None
    if not isinstance(payload, Mapping) or payload.get("encoding") != "base64":
        raise AuditError("Dependabot configuration response is invalid")
    encoded = str(payload.get("content", "")).replace("\n", "")
    raw = base64.b64decode(encoded, validate=True)
    if len(raw) > MAX_WORKFLOW_BYTES:
        raise AuditError("Dependabot configuration exceeds the audit size limit")
    return raw.decode("utf-8")


def _fetch_dependabot_config(repository: str, token: str) -> str | None:
    for path in (".github/dependabot.yml", ".github/dependabot.yaml"):
        content = _decode_optional_file(repository, token, path)
        if content is not None:
            return content
    return None


def _audit_selected(repositories: Sequence[str], token: str) -> list[Finding]:
    findings: list[Finding] = []
    for repository in repositories:
        visibility, workflows = _fetch_workflows(repository, token)
        findings.extend(audit_workflows(repository, visibility, workflows))
        findings.extend(
            audit_security_adoption(
                repository,
                visibility,
                workflows,
                _fetch_dependabot_config(repository, token),
            )
        )
    return findings


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
        (output / "report.json").write_text(
            json.dumps(render_json(findings, public=args.public), indent=2, sort_keys=True)
            + "\n",
            encoding="utf-8",
        )
        markdown = render_markdown(findings, public=args.public)
        (output / "report.md").write_text(markdown, encoding="utf-8")
        if args.issue_ref_env:
            issue_ref = os.environ.get(args.issue_ref_env, "")
            issue_token = (
                os.environ.get(args.issue_token_env, "")
                if args.issue_token_env
                else ""
            )
            if issue_ref:
                if args.public:
                    raise AuditError(
                        "public report must not update the private central issue"
                    )
                if not issue_token:
                    raise AuditError("issue update token is missing")
                _update_issue(issue_ref, issue_token, markdown)
        print(
            f"Audit completed: repositories={len(repositories)} "
            f"findings={len(findings)} public={args.public}"
        )
        return 0
    except (AuditError, OSError, UnicodeDecodeError, ValueError) as exc:
        print(f"organization audit error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
