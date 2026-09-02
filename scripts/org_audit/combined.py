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

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.org_audit.audit import (
    API_ROOT,
    MAX_WORKFLOW_BYTES,
    AuditError,
    Finding,
    _api_json,
    _fetch_workflows,
    _job_blocks,
    _repositories_from_env,
    _update_issue,
    audit_workflows,
    render_json,
    render_markdown,
)

import re

ROOT = Path(__file__).resolve().parents[2]

LOCAL_COMPOSE_PATTERN = re.compile(
    r"^\s+docker(?:-compose)? compose config\b|run:.*\bdocker(?:-compose)? compose config\b"
)
LOCAL_SECURITY_TOOL_PATTERNS = {
    "Trivy scan": re.compile(r"^\s+trivy\s+(?:fs|image|rootfs|filesystem|repo|config|filesystem)\b|run:.*\btrivy\b"),
    "gitleaks": re.compile(r"^\s+gitleaks\b|run:.*\bgitleaks\b"),
    "SBOM": re.compile(r"^\s+syft\b|run:.*\bsyft\b"),
    "dependency audit": re.compile(r"^\s+(?:pip-audit|poetry audit|npm audit|pnpm audit|yarn audit)\b|run:.*\b(?:pip-audit|poetry audit|npm audit|pnpm audit|yarn audit)\b"),
}
LOCAL_PYTHON_TEST_PATTERN = re.compile(
    r"^\s+(?:uv run pytest|uv run coverage|pytest|coverage run|coverage report)\b|run:.*\b(?:uv run pytest|pytest --cov|coverage run)\b"
)
LOCAL_STATIC_LINT_PATTERNS = {
    "ShellCheck": re.compile(r"^\s+shellcheck\b|run:.*\bshellcheck\b"),
    "actionlint": re.compile(r"^\s+actionlint\b|run:.*\bactionlint\b"),
    "Ruff": re.compile(r"^\s+ruff check\b|run:.*\bruff check\b"),
    "mypy": re.compile(r"^\s+mypy\b|run:.*\bmypy\b"),
}
LOCAL_QUALITY_GATE_PATTERN = re.compile(
    r"\.github/scripts/quality[-_]gate|scripts/quality[-_]gate|run:.*\bquality-gate\b"
)
CANONICAL_REUSABLE_SUFFIX = {
    "compose": "optimizr-actions/.github/workflows/_docker-compose-validate.yml@v1",
    "security": ("optimizr-actions/.github/workflows/_security-gate.yml@v1", "optimizr-actions/.github/workflows/_trivy-scan.yml@v1", "optimizr-actions/.github/workflows/_sast-gate.yml@v1", "optimizr-actions/.github/workflows/_dependency-policy.yml@v1", "optimizr-actions/.github/workflows/_supply-chain-evidence.yml@v1"),
    "python": ("optimizr-actions/.github/workflows/_python-uv-test.yml@v1", "optimizr-actions/.github/actions/python-uv-test-steps/action.yml@v1"),
    "lint": "optimizr-actions/.github/workflows/_static-lint.yml@v1",
    "quality_gate": ("optimizr-actions/.github/workflows/_quality-gate.yml@v1", "optimizr-actions/.github/workflows/_quality-gate-pr.yml@v1", "optimizr-actions/.github/actions/quality-gate-scripts/action.yml@v1"),
    "repository_validation": "optimizr-actions/.github/workflows/_repository-validation.yml@v1",
    "validation_gate": "optimizr-actions/.github/workflows/_validation-gate.yml@v1",
    "validate_pr": "optimizr-actions/.github/workflows/_validate-pr.yml@v1",
}
SELF_HOSTED_RUNS_ON_RE = re.compile(r"(?m)^\s+runs-on\s*:\s*.*self-hosted")
HOSTED_RUNS_ON_RE = re.compile(r"(?m)^\s+runs-on\s*:\s*.*(?:ubuntu|windows|macos)-")
USES_REUSABLE_RE = re.compile(r"optimizr-actions/(?:\.github/(?:workflows|actions)/[^@\s]+\.ya?ml|\.github/actions/[^@\s]+/action\.yml)@([^\s#]+)")


def _canonical_present(joined: str) -> dict[str, bool]:
    present: dict[str, bool] = {}
    for capability, suffix in CANONICAL_REUSABLE_SUFFIX.items():
        targets = (suffix,) if isinstance(suffix, str) else suffix
        present[capability] = any(
            re.search(
                re.escape(f"optimizr-tech/{target.rsplit('@', 1)[0]}")
                + r"@v1(?=$|[\s\"'#,)\]])",
                joined,
            )
            for target in targets
        )
    return present


def _has_governed_internal_ref(content: str, artifact_path: str) -> bool:
    return re.search(
        rf"optimizr-tech/optimizr-actions/{re.escape(artifact_path)}@"
        r"v1(?=$|[\s\"'#,)\]])",
        content,
    ) is not None


def audit_functional_duplication(
    repository: str,
    visibility: str,
    workflows: Mapping[str, str],
    catalog: Mapping[str, object] | None = None,
) -> list[Finding]:
    """Detect avoidable local reimplementation of canonical capabilities.

    A local implementation is reported only when the canonical reusable is
    not called anywhere in the repository. Product-specific extensions are
    allowed: register the exception in the consumer ``docs/adoption.md`` with
    a reason.
    """
    findings: list[Finding] = []
    joined = "\n".join(workflows.values())
    canonical = _canonical_present(joined)

    for path, content in workflows.items():
        def add(rule_id: str, message: str) -> None:
            findings.append(Finding(repository, visibility, path, rule_id, message))

        if not canonical["compose"] and LOCAL_COMPOSE_PATTERN.search(content):
            add(
                "LOCAL_COMPOSE_VALIDATION",
                "Compose model validation is implemented locally. Canonical: `optimizr-actions/.github/workflows/_docker-compose-validate.yml@v1`. Risk: divergence from the central contract. Migrate to the reusable; declare a product-specific exception in docs/adoption.md when the local check adds behavior the reusable does not provide.",
            )
        if not canonical["security"]:
            found_tools = [
                tool
                for tool, pattern in LOCAL_SECURITY_TOOL_PATTERNS.items()
                if pattern.search(content)
            ]
            if found_tools:
                add(
                    "DUPLICATED_SECURITY_SCAN",
                    f"Security scanning is recreated locally ({', '.join(found_tools)}). Canonical: `_security-gate.yml`, `_trivy-scan.yml`, `_sast-gate.yml`, `_dependency-policy.yml` or `_supply-chain-evidence.yml` at @v1. Risk: findings and evidence are not governed. Migrate to the canonical reusable; declare product-specific exceptions in docs/adoption.md.",
                )
        if not canonical["python"] and LOCAL_PYTHON_TEST_PATTERN.search(content):
            add(
                "DUPLICATED_PYTHON_TEST_RUNNER",
                "Python uv/pytest/coverage is recreated locally. Canonical: `_python-uv-test.yml@v1` with `python-uv-test-steps/action.yml`. Risk: matrix and evidence drift from the canonical runner. Migrate to the reusable; declare product-specific exceptions in docs/adoption.md.",
            )
        if not canonical["lint"]:
            found_linters = [
                linter
                for linter, pattern in LOCAL_STATIC_LINT_PATTERNS.items()
                if pattern.search(content)
            ]
            if found_linters:
                add(
                    "DUPLICATED_STATIC_LINT",
                    f"Static linting is recreated locally ({', '.join(found_linters)}). Canonical: `_static-lint.yml@v1`. Risk: versions and gates diverge from the canonical policy. Migrate to the reusable; declare product-specific exceptions in docs/adoption.md.",
                )
        if not canonical["quality_gate"] and LOCAL_QUALITY_GATE_PATTERN.search(content):
            add(
                "DUPLICATED_QUALITY_GATE",
                "A quality gate is implemented locally instead of the canonical one. Canonical: `_quality-gate.yml@v1`, `_quality-gate-pr.yml@v1` or `quality-gate-scripts/action.yml`. Risk: baseline and duplicate-collection evidence are lost. Migrate to the canonical gate; declare product-specific exceptions in docs/adoption.md.",
            )
        for job_name, job_block in _job_blocks(content):
            mandatory = (
                _has_governed_internal_ref(job_block, ".github/workflows/_repository-validation.yml")
                or _has_governed_internal_ref(job_block, ".github/workflows/_validate-pr.yml")
            )
            if mandatory and re.search(r"skip\s*:\s*[\"']?true[\"']?", job_block):
                add(
                    "PERMANENT_SKIP_IN_MANDATORY_VALIDATION",
                    f"Job `{job_name}` permanently sets `skip: true` on mandatory canonical validation. Risk: the reusable is nominally adopted but functionally disabled, with no evidence produced. Remove the permanent skip or document the exception in docs/adoption.md.",
                )
        if re.search(r"actions/checkout@[^\s]+", content) and re.search(
            r"optimizr-actions/scripts/", content
        ):
            add(
                "ACTIONS_CLONE_SCRIPT_EXECUTION",
                "The workflow checks out optimizr-actions and executes its internal scripts directly, running part of a central contract and losing reusable outputs and evidence. Canonical: call the reusable with @v1 instead. Risk: silent drift and no governed evidence.",
            )
        if "optimizr-actions/.github/workflows/" in content and SELF_HOSTED_RUNS_ON_RE.search(content):
            reported: set[str] = set()
            for job_name, job_block in _job_blocks(content):
                if HOSTED_RUNS_ON_RE.search(job_block):
                    for reusable in sorted(
                        {match.group(0) for match in USES_REUSABLE_RE.finditer(job_block)}
                    ):
                        reusable_path = ".github/" + reusable.split("/.github/", 1)[1].split("@", 1)[0]
                        runner_kinds = _runner_kinds_for(catalog, reusable_path)
                        if any(kind.startswith("self-hosted") for kind in runner_kinds) and reusable not in reported:
                            reported.add(reusable)
                            add(
                                "HOSTED_ONLY_REUSABLE",
                                f"Reusable `{reusable}` supports self-hosted runners but is called only from hosted job `{job_name}` in a repository that already runs self-hosted jobs. Risk: persistent/efêmero capacity with evidence is never exercised. Call it from a self-hosted job or document the hosted-only choice in docs/adoption.md.",
                            )
    return findings


def _runner_kinds_for(
    catalog: Mapping[str, object] | None, artifact_path: str
) -> list[str]:
    """Return runner kinds declared in the catalog for ``artifact_path``."""
    if not catalog:
        return []
    artifacts = catalog.get("artifacts")
    if not isinstance(artifacts, list):
        return []
    for artifact in artifacts:
        if not isinstance(artifact, Mapping) or artifact.get("path") != artifact_path:
            continue
        runner = artifact.get("runner")
        if isinstance(runner, list):
            return [str(kind) for kind in runner]
    return []



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
        _has_governed_internal_ref(content, ".github/workflows/_dependabot-security-automerge.yml")
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
        _has_governed_internal_ref(content, ".github/workflows/_vps-self-hosted-deploy.yml")
        or _has_governed_internal_ref(content, ".github/workflows/_vps-monorepo-deploy.yml")
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


def _load_catalog() -> dict[str, object] | None:
    """Load the canonical capability catalog shipped with the audit."""
    catalog_file = ROOT / "catalog" / "capabilities.json"
    try:
        payload = json.loads(catalog_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, Mapping) else None


def _audit_selected(repositories: Sequence[str], token: str) -> list[Finding]:
    catalog = _load_catalog()
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
        findings.extend(
            audit_functional_duplication(repository, visibility, workflows, catalog)
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
