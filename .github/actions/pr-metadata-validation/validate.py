#!/usr/bin/env python3
"""Validate pull-request metadata without executing candidate repository code."""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

ALLOWED_TYPES = {
    "feat", "fix", "security", "config", "docs", "style", "refactor",
    "perf", "test", "build", "ci", "chore", "revert", "hotfix", "raw",
    "cleanup", "remove", "init",
}
ALLOWED_EMOJI_CODES = {
    ":sparkles:", ":bug:", ":ambulance:", ":lock:", ":memo:",
    ":recycle:", ":zap:", ":white_check_mark:", ":arrow_up:",
    ":wrench:", ":rocket:", ":gear:", ":globe_with_meridians:",
    ":broom:", ":bookmark_tabs:", ":fire:", ":books:", ":ok_hand:",
    ":package:", ":bricks:", ":card_file_box:", ":wastebasket:",
    ":lipstick:", ":closed_lock_with_key:", ":test_tube:",
    ":heavy_plus_sign:", ":heavy_minus_sign:", ":hammer:", ":truck:",
    ":tada:", ":shield:", ":construction_worker:",
}
PT_WORDS = {
    "corrigir", "corrig", "adicionar", "bloquear", "permitir", "restaurar",
    "evitar", "remover", "atualizar", "implementar", "ajuste", "ajustes",
    "quando", "durante", "entre", "após", "antes", "também", "apenas",
    "ainda", "não", "está", "foram", "pelo", "pela", "pelos", "pelas",
    "sem", "com", "para", "nos", "nas", "aos", "das", "dos", "que",
    "uma", "num", "numa", "sobre", "deve", "ser", "erro", "erros",
    "suíte", "usuário", "usuarios", "entregadores", "pedidos",
    "configuração", "configuracao", "limitar", "reprecificar", "catálogo",
    "catalogo", "público", "publico", "fora", "horario", "horário", "zona",
}
SUBJECT_RE = re.compile(r"^(?P<type>[a-z]+)(?:\([^)]+\))?:\s+(?P<description>.+)$")
SHORTCODE_RE = re.compile(r"^:([a-z0-9_+\-]+):\s+(.+)$")
PORTUGUESE_DIACRITICS_RE = re.compile(r"[àáâãäåèéêëìíîïòóôõöùúûüçñÀÁÂÃÉÍÓÔÕÚÇ]")
MOJIBAKE_RE = re.compile(r"ðŸ|Ã.|â€")
CORRUPT_PATH_RE = re.compile(r"\\(origin/|assets/|release\.yml|\.releaserc|main\\|dev\\)")
REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
SKIPPED_COMMIT_PREFIXES = ("Merge ", "Revert ", "fixup!", "squash!")


@dataclass(frozen=True)
class ValidationFailure:
    stage: str
    message: str


def validate_subject(subject: str, label: str) -> list[ValidationFailure]:
    failures: list[ValidationFailure] = []
    try:
        subject.encode("ascii")
    except UnicodeEncodeError:
        return [ValidationFailure(label, "must be ASCII-only; use :shortcode: gitmoji")]

    rest = subject
    emoji_token = ""
    shortcode = SHORTCODE_RE.match(rest)
    if shortcode:
        emoji_token = f":{shortcode.group(1)}:"
        rest = shortcode.group(2)
    else:
        first, separator, remainder = rest.partition(" ")
        if separator and not first.startswith(":"):
            emoji_token = first
            rest = remainder

    match = SUBJECT_RE.match(rest)
    if not match or match.group("type") not in ALLOWED_TYPES:
        return [ValidationFailure(label, "expected '<emoji> type[(scope)]: description'")]

    if emoji_token.startswith(":") and emoji_token not in ALLOWED_EMOJI_CODES:
        failures.append(ValidationFailure(label, f"gitmoji '{emoji_token}' is not allowed"))

    description = match.group("description")
    if len(description) < 4:
        failures.append(ValidationFailure(label, "description is shorter than 4 characters"))
    if description.endswith("."):
        failures.append(ValidationFailure(label, "remove the trailing period"))
    if len(subject) > 72:
        failures.append(ValidationFailure(label, f"must be at most 72 characters; got {len(subject)}"))
    if PORTUGUESE_DIACRITICS_RE.search(description):
        failures.append(ValidationFailure(label, "description must be English; Portuguese diacritics detected"))

    words = {word.lower() for word in re.findall(r"[A-Za-zÀ-ÿ]+", description)}
    if words & PT_WORDS:
        failures.append(ValidationFailure(label, "description must be English; Portuguese wording detected"))
    return failures


def validate_body(body: str) -> list[ValidationFailure]:
    failures: list[ValidationFailure] = []
    if not body.strip():
        failures.append(ValidationFailure("PR body", "body is empty"))
        return failures
    for char in body:
        code = ord(char)
        if code < 32 and char not in "\t\n\r":
            failures.append(ValidationFailure("PR body", "contains C0 control characters"))
            break
    if MOJIBAKE_RE.search(body):
        failures.append(ValidationFailure("PR body", "contains mojibake sequences"))
    if CORRUPT_PATH_RE.search(body):
        failures.append(ValidationFailure("PR body", "looks like corrupted PowerShell markdown"))
    return failures


def _request_json(url: str, token: str) -> object:
    request = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "optimizr-pr-metadata-validation",
        },
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def _repository_api_root(api_url: str, repository: str) -> str:
    encoded_repo = "/".join(urllib.parse.quote(part, safe="") for part in repository.split("/"))
    return f"{api_url.rstrip('/')}/repos/{encoded_repo}"


def fetch_pr_metadata(api_url: str, repository: str, pr_number: int, token: str) -> tuple[dict, list[dict]]:
    root = f"{_repository_api_root(api_url, repository)}/pulls/{pr_number}"
    pr = _request_json(root, token)
    if not isinstance(pr, dict):
        raise RuntimeError("GitHub PR response is not an object")

    commits: list[dict] = []
    for page in range(1, 11):
        payload = _request_json(f"{root}/commits?per_page=100&page={page}", token)
        if not isinstance(payload, list):
            raise RuntimeError("GitHub PR commits response is not a list")
        commits.extend(item for item in payload if isinstance(item, dict))
        if len(payload) < 100:
            return pr, commits
    raise RuntimeError("PR has more than 1000 commits; metadata validation is bounded")


def fetch_branch_history(
    api_url: str,
    repository: str,
    head_owner: str,
    head_ref: str,
    token: str,
) -> list[dict]:
    root = f"{_repository_api_root(api_url, repository)}/pulls"
    history: list[dict] = []
    for page in range(1, 11):
        query = urllib.parse.urlencode(
            {
                "state": "closed",
                "head": f"{head_owner}:{head_ref}",
                "per_page": 100,
                "page": page,
            }
        )
        payload = _request_json(f"{root}?{query}", token)
        if not isinstance(payload, list):
            raise RuntimeError("GitHub branch history response is not a list")
        history.extend(item for item in payload if isinstance(item, dict))
        if len(payload) < 100:
            return history
    raise RuntimeError("branch history exceeds 1000 pull requests; validation is bounded")


def resolve_head_identity(pr: dict) -> tuple[str, str] | None:
    head = pr.get("head") or {}
    if not isinstance(head, dict):
        return None
    head_ref = str(head.get("ref") or "")
    head_repo = head.get("repo") or {}
    head_repo_full_name = str(head_repo.get("full_name") or "") if isinstance(head_repo, dict) else ""
    head_label = str(head.get("label") or "")

    head_owner = ""
    if "/" in head_repo_full_name:
        head_owner = head_repo_full_name.split("/", 1)[0]
    elif ":" in head_label:
        head_owner = head_label.split(":", 1)[0]

    if not head_owner or not head_ref:
        return None
    return head_owner, head_ref


def validate_pr_lifecycle(
    pr: dict,
    pr_number: int,
    branch_history: list[dict],
) -> list[ValidationFailure]:
    failures: list[ValidationFailure] = []
    if str(pr.get("state") or "") != "open":
        failures.append(ValidationFailure("branch lifecycle", "current pull request is not open"))
    if bool(pr.get("merged")) or pr.get("merged_at"):
        failures.append(ValidationFailure("branch lifecycle", "current pull request is already merged"))

    for prior in branch_history:
        try:
            prior_number = int(prior.get("number") or 0)
        except (TypeError, ValueError):
            continue
        if prior_number == pr_number:
            continue
        if prior.get("merged_at"):
            failures.append(
                ValidationFailure(
                    "branch lifecycle",
                    f"head branch was already used by merged PR #{prior_number}; create a fresh branch",
                )
            )
            break
    return failures


def emit_failure(failure: ValidationFailure) -> None:
    title = failure.stage.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    message = failure.message.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    print(f"::error title={title}::{message}")
    print(f"FAILED: {failure.stage}: {failure.message}", file=sys.stderr)


def write_output(name: str, value: str) -> None:
    output = os.environ.get("GITHUB_OUTPUT")
    if not output:
        return
    with open(output, "a", encoding="utf-8") as handle:
        handle.write(f"{name}={value}\n")


def main() -> int:
    repository = os.environ.get("INPUT_REPOSITORY", "")
    token = os.environ.get("INPUT_TOKEN", "")
    title = os.environ.get("INPUT_PR_TITLE", "")
    body = os.environ.get("INPUT_PR_BODY", "")
    expected_base = os.environ.get("INPUT_BASE_SHA", "")
    expected_head = os.environ.get("INPUT_HEAD_SHA", "")
    api_url = os.environ.get("GITHUB_API_URL", "https://api.github.com")

    failures: list[ValidationFailure] = []
    if not REPOSITORY_RE.fullmatch(repository):
        failures.append(ValidationFailure("metadata input", "repository must be owner/name"))
    try:
        pr_number = int(os.environ.get("INPUT_PR_NUMBER", "0"))
        if pr_number <= 0:
            raise ValueError
    except ValueError:
        failures.append(ValidationFailure("metadata input", "PR number must be a positive integer"))
        pr_number = 0
    if not token:
        failures.append(ValidationFailure("metadata input", "read-only GitHub token is required"))
    if not re.fullmatch(r"[0-9a-fA-F]{40}", expected_base):
        failures.append(ValidationFailure("metadata input", "base SHA must contain 40 hexadecimal characters"))
    if not re.fullmatch(r"[0-9a-fA-F]{40}", expected_head):
        failures.append(ValidationFailure("metadata input", "head SHA must contain 40 hexadecimal characters"))

    failures.extend(validate_subject(title, "PR title"))
    failures.extend(validate_body(body))
    if failures:
        for failure in failures:
            emit_failure(failure)
        return 1

    try:
        pr, commits = fetch_pr_metadata(api_url, repository, pr_number, token)
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, RuntimeError, json.JSONDecodeError) as exc:
        emit_failure(ValidationFailure("metadata API", f"unable to fetch PR metadata: {type(exc).__name__}"))
        return 1

    actual_base = str(((pr.get("base") or {}).get("sha") or ""))
    actual_head = str(((pr.get("head") or {}).get("sha") or ""))
    if actual_base != expected_base:
        failures.append(ValidationFailure("exact SHA", "PR base SHA does not match the event input"))
    if actual_head != expected_head:
        failures.append(ValidationFailure("exact SHA", "PR head SHA does not match the event input"))
    if not commits:
        failures.append(ValidationFailure("PR commits", "no commits were returned by GitHub"))

    state_failures = validate_pr_lifecycle(pr, pr_number, [])
    failures.extend(state_failures)
    if not state_failures:
        head_identity = resolve_head_identity(pr)
        if head_identity is None:
            failures.append(ValidationFailure("branch lifecycle", "unable to resolve the exact head branch identity"))
        else:
            try:
                branch_history = fetch_branch_history(
                    api_url,
                    repository,
                    head_identity[0],
                    head_identity[1],
                    token,
                )
            except (
                urllib.error.URLError,
                urllib.error.HTTPError,
                TimeoutError,
                RuntimeError,
                json.JSONDecodeError,
            ) as exc:
                failures.append(
                    ValidationFailure(
                        "branch lifecycle",
                        f"unable to fetch branch history: {type(exc).__name__}",
                    )
                )
            else:
                failures.extend(validate_pr_lifecycle(pr, pr_number, branch_history))

    for index, item in enumerate(commits, start=1):
        commit = item.get("commit") or {}
        message = str(commit.get("message") or "")
        subject = message.splitlines()[0] if message else ""
        if not subject or subject.startswith(SKIPPED_COMMIT_PREFIXES):
            continue
        failures.extend(validate_subject(subject, f"commit {index}"))

    if failures:
        for failure in failures:
            emit_failure(failure)
        return 1

    write_output("result", "passed")
    write_output("commit_count", str(len(commits)))
    print(f"PASS: PR metadata validated for {repository}#{pr_number}; commits={len(commits)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
