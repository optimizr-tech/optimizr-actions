#!/usr/bin/env python3
"""Validate pull-request metadata without executing candidate repository code."""

from __future__ import annotations

import errno
import json
import os
import re
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
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
MOJIBAKE_RE = re.compile(r"ðŸ|Ã[\x80-\xBF]|â€|Â[\x80-\xBF]")
CORRUPT_PATH_RE = re.compile(r"\\(origin/|assets/|release\.yml|\.releaserc|main\\|dev\\)")
# Source extensions scanned in added PR lines (docs/markdown excluded on
# purpose: repair guides intentionally quote corrupted sequences).
SCAN_FILE_EXTENSIONS = frozenset({
    ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".py", ".rb", ".go", ".rs",
    ".sh", ".bash", ".ps1", ".css", ".scss", ".html", ".vue", ".svelte",
    ".yml", ".yaml", ".json", ".toml", ".sql", ".graphql",
})
# Lockfiles ship generated third-party text; never scan them.
SCAN_EXCLUDED_SUFFIXES = ("lock.yaml", "lock.json", "lock.yml")
REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
SKIPPED_COMMIT_PREFIXES = ("Merge ", "Revert ", "fixup!", "squash!")
SUBJECT_MAX_LENGTH = 72
VERIFIED_DEPENDABOT_GROUP_SUBJECT_MAX_LENGTH = 200
DEPENDABOT_LOGIN = "dependabot[bot]"
GITHUB_WEB_FLOW_LOGIN = "web-flow"
DEPENDABOT_COMMIT_AUTHOR_EMAIL_RE = re.compile(
    r"^(?P<id>\d+)\+dependabot\[bot\]@users\.noreply\.github\.com$"
)
DEPENDABOT_GROUP_SUMMARY_RE = re.compile(
    r"(?im)^Bumps the .+ group with \d+ updates?(?: in the .+ directory)?:"
)
DEPENDABOT_GROUP_FIELD_RE = re.compile(r"(?im)^\s*dependency-group:\s*\S.*$")
# Dependabot appends this generated tail to the grouped-update PR title; the
# signed commit subject carries the same text without it.
DEPENDABOT_GROUP_TITLE_SUFFIX_RE = re.compile(
    r"^ (?:from \S+ to \S+ )?in the [A-Za-z0-9_.-]+ group$"
)
AI_COAUTHOR_RE = re.compile(
    r"(?im)^Co-authored-by:\s*(?:Cursor|Composer|Copilot|Claude|Codex|ChatGPT|OpenAI|GitHub Copilot)\b"
    r"|^Co-authored-by:.*<(?:cursoragent@cursor\.com|codex@openai\.com|chatgpt@openai\.com)>"
)


@dataclass(frozen=True)
class ValidationFailure:
    stage: str
    message: str


def validate_subject(
    subject: str,
    label: str,
    *,
    max_length: int = SUBJECT_MAX_LENGTH,
) -> list[ValidationFailure]:
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
    if len(subject) > max_length:
        failures.append(
            ValidationFailure(label, f"must be at most {max_length} characters; got {len(subject)}")
        )
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


def validate_commit_message(message: str, label: str) -> list[ValidationFailure]:
    if AI_COAUTHOR_RE.search(message):
        return [
            ValidationFailure(
                label,
                "AI co-authorship trailer is not allowed; recreate the commit without Co-authored-by",
            )
        ]
    return []


def is_verified_dependabot_group_commit(pr: dict, item: dict) -> bool:
    """Return true only for a GitHub-verified Dependabot grouped commit.

    GitHub's pull-request commits endpoint attributes the observed signed
    Dependabot commits to the bot as author and `web-flow` as committer. The
    signed payload also uses the bot's no-reply author address. Require all of
    those signals plus the bot-authored PR, Dependabot branch, valid signature,
    and both generated group markers; missing or inconsistent API fields fail
    closed.
    """
    if not isinstance(pr, dict) or not isinstance(item, dict):
        return False

    pr_user = pr.get("user")
    head = pr.get("head")
    author = item.get("author")
    committer = item.get("committer")
    commit = item.get("commit")
    if not all(
        isinstance(value, dict)
        for value in (pr_user, head, author, committer, commit)
    ):
        return False

    commit_author = commit.get("author")
    commit_committer = commit.get("committer")
    verification = commit.get("verification")
    if not all(
        isinstance(value, dict)
        for value in (commit_author, commit_committer, verification)
    ):
        return False

    bot_id = pr_user.get("id")
    author_email = str(commit_author.get("email") or "")
    author_email_match = DEPENDABOT_COMMIT_AUTHOR_EMAIL_RE.fullmatch(author_email)
    commit_message = str(commit.get("message") or "")
    _, separator, body = commit_message.partition("\n")
    if not separator:
        return False

    return (
        pr_user.get("login") == DEPENDABOT_LOGIN
        and pr_user.get("type") == "Bot"
        and type(bot_id) is int
        and bot_id > 0
        and author.get("login") == DEPENDABOT_LOGIN
        and author.get("type") == "Bot"
        and author.get("id") == bot_id
        and str(head.get("ref") or "").startswith("dependabot/")
        and committer.get("login") == GITHUB_WEB_FLOW_LOGIN
        and committer.get("type") == "User"
        and author_email_match is not None
        and int(author_email_match.group("id")) == bot_id
        and commit_committer.get("email") == "noreply@github.com"
        and verification.get("verified") is True
        and verification.get("reason") == "valid"
        and DEPENDABOT_GROUP_SUMMARY_RE.search(body) is not None
        and DEPENDABOT_GROUP_FIELD_RE.search(body) is not None
    )


def resolve_effective_pr_title(title: str, pr: dict, commits: list[dict]) -> str:
    """Compact a generated Dependabot group PR title to its verified commit subject.

    Only titles over the limit are touched. The title must be the subject of a
    GitHub-verified Dependabot group commit (see
    ``is_verified_dependabot_group_commit``) followed by nothing but the
    generated ``[from X to Y ]in the <group> group`` tail. The compacted value
    is still validated with the normal 72-character limit; anything else is
    returned unchanged so the strict check applies.
    """
    if len(title) <= SUBJECT_MAX_LENGTH:
        return title
    for item in commits:
        if not is_verified_dependabot_group_commit(pr, item):
            continue
        message = str(item["commit"].get("message") or "")
        subject = message.splitlines()[0]
        if (
            subject
            and title.startswith(subject)
            and DEPENDABOT_GROUP_TITLE_SUFFIX_RE.fullmatch(title[len(subject):])
        ):
            return subject
    return title


def validate_commit_metadata(pr: dict, item: dict, label: str) -> list[ValidationFailure]:
    commit = item.get("commit") if isinstance(item, dict) else None
    if not isinstance(commit, dict):
        commit = {}
    message = str(commit.get("message") or "")
    failures = validate_commit_message(message, label)
    subject = message.splitlines()[0] if message else ""
    if not subject or subject.startswith(SKIPPED_COMMIT_PREFIXES):
        return failures

    max_length = (
        VERIFIED_DEPENDABOT_GROUP_SUBJECT_MAX_LENGTH
        if is_verified_dependabot_group_commit(pr, item)
        else SUBJECT_MAX_LENGTH
    )
    failures.extend(validate_subject(subject, label, max_length=max_length))
    return failures


def _is_scanned_source_path(path: str) -> bool:
    name = path.rsplit("/", 1)[-1]
    if name.endswith(SCAN_EXCLUDED_SUFFIXES):
        return False
    return os.path.splitext(name)[1].lower() in SCAN_FILE_EXTENSIONS


def validate_changed_files(files: list) -> list[ValidationFailure]:
    """Reject double-encoded UTF-8 on added source lines (no checkout needed).

    Only ``+`` lines are checked so encoding-repair PRs that *remove*
    corrupted sequences still pass.
    """
    failures: list[ValidationFailure] = []
    for item in files:
        if not isinstance(item, dict):
            continue
        path = str(item.get("filename") or "")
        if not path or not _is_scanned_source_path(path):
            continue
        patch = item.get("patch")
        if not isinstance(patch, str) or not patch:
            continue
        added = "\n".join(
            line[1:]
            for line in patch.splitlines()
            if line.startswith("+") and not line.startswith("+++")
        )
        if not added:
            continue
        if MOJIBAKE_RE.search(added):
            failures.append(
                ValidationFailure(
                    "changed files",
                    f"{path}: added lines contain mojibake sequences",
                )
            )
        elif CORRUPT_PATH_RE.search(added):
            failures.append(
                ValidationFailure(
                    "changed files",
                    f"{path}: added lines contain corrupted PowerShell paths",
                )
            )
    return failures


class MetadataRequestError(RuntimeError):
    """Sanitized metadata transport failure safe to include in CI logs."""

    def __init__(
        self,
        category: str,
        attempts: int,
        *,
        status_code: int | None = None,
        budget_exhausted: bool = False,
    ) -> None:
        self.category = category
        self.attempts = attempts
        self.status_code = status_code
        self.budget_exhausted = budget_exhausted
        parts = [f"category={category}", f"attempts={attempts}"]
        if status_code is not None:
            parts.append(f"http_status={status_code}")
        if budget_exhausted:
            parts.append("retry_budget_exhausted=true")
        super().__init__("metadata GET failed: " + "; ".join(parts))


def _classify_transport_error(error: BaseException) -> tuple[str, bool]:
    reason = error.reason if isinstance(error, urllib.error.URLError) else error

    # TLS failures inherit OSError, so exclude them before checking errno.
    if isinstance(reason, ssl.SSLError):
        return "tls_error", False
    if isinstance(reason, TimeoutError):
        return "timeout", True
    if isinstance(reason, socket.gaierror):
        if reason.errno == socket.EAI_AGAIN:
            return "temporary_dns", True
        return "dns_resolution", False
    if isinstance(reason, ConnectionResetError):
        return "connection_reset", True
    if isinstance(reason, ConnectionAbortedError):
        return "connection_aborted", True
    if isinstance(reason, ConnectionRefusedError):
        return "connection_refused", True
    if isinstance(reason, OSError):
        if reason.errno in {errno.ECONNRESET, errno.ECONNABORTED}:
            category = (
                "connection_reset"
                if reason.errno == errno.ECONNRESET
                else "connection_aborted"
            )
            return category, True
        if reason.errno == errno.ECONNREFUSED:
            return "connection_refused", True
        if reason.errno in {errno.EHOSTUNREACH, errno.ENETUNREACH}:
            return "network_unreachable", True
        host_down = getattr(errno, "EHOSTDOWN", None)
        if host_down is not None and reason.errno == host_down:
            return "network_unreachable", True
    return "transport_error", False


class MetadataApiClient:
    """GET GitHub metadata with a shared, bounded retry-only time budget.

    The initial request keeps the existing 30-second urllib timeout. Retries
    and their 2/4-second waits share at most 30 seconds across this client.
    urllib's timeout bounds blocking socket operations, not a strict
    end-to-end wall-clock deadline.
    """

    REQUEST_TIMEOUT_SECONDS = 30
    MAX_ATTEMPTS = 3
    RETRY_DELAYS_SECONDS = (2, 4)

    def __init__(
        self,
        *,
        retry_budget_seconds: float = 30,
        clock: Callable[[], float] | None = None,
        sleep: Callable[[float], None] | None = None,
    ) -> None:
        if retry_budget_seconds < 0:
            raise ValueError("retry budget cannot be negative")
        self._retry_budget_seconds = float(retry_budget_seconds)
        self._clock = clock or time.monotonic
        self._sleep = sleep or time.sleep
        self._retry_started_at: float | None = None

    @property
    def retry_budget_remaining(self) -> float:
        if self._retry_started_at is None:
            return self._retry_budget_seconds
        elapsed = max(0.0, self._clock() - self._retry_started_at)
        return max(0.0, self._retry_budget_seconds - elapsed)

    def request_json(self, url: str, token: str) -> object:
        request = urllib.request.Request(
            url,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "optimizr-pr-metadata-validation",
            },
        )
        attempts = 0
        last_category = "transport_error"
        while True:
            if attempts == 0:
                timeout = self.REQUEST_TIMEOUT_SECONDS
            else:
                remaining = self.retry_budget_remaining
                if remaining <= 0:
                    raise MetadataRequestError(
                        last_category,
                        attempts,
                        budget_exhausted=True,
                    ) from None
                timeout = min(self.REQUEST_TIMEOUT_SECONDS, remaining)
            attempts += 1
            try:
                with urllib.request.urlopen(request, timeout=timeout) as response:
                    return json.load(response)
            except urllib.error.HTTPError as exc:
                status_code = exc.code
                exc.close()
                # HTTP statuses, including 403, 429, and 5xx, are not retried.
                raise MetadataRequestError(
                    "http_status",
                    attempts,
                    status_code=status_code,
                ) from None
            except (urllib.error.URLError, OSError) as exc:
                category, retryable = _classify_transport_error(exc)
                if not retryable or attempts >= self.MAX_ATTEMPTS:
                    raise MetadataRequestError(category, attempts) from None

                if self._retry_started_at is None:
                    self._retry_started_at = self._clock()
                last_category = category
                delay = self.RETRY_DELAYS_SECONDS[attempts - 1]
                if self.retry_budget_remaining <= delay:
                    raise MetadataRequestError(
                        category,
                        attempts,
                        budget_exhausted=True,
                    ) from None
                self._sleep(delay)
                if self.retry_budget_remaining <= 0:
                    raise MetadataRequestError(
                        category,
                        attempts,
                        budget_exhausted=True,
                    ) from None


def _request_json(url: str, token: str) -> object:
    # Kept as the default fetch hook for existing callers and tests. main()
    # injects one shared client so its retry budget spans every metadata GET.
    return MetadataApiClient().request_json(url, token)


def _repository_api_root(api_url: str, repository: str) -> str:
    encoded_repo = "/".join(urllib.parse.quote(part, safe="") for part in repository.split("/"))
    return f"{api_url.rstrip('/')}/repos/{encoded_repo}"


def fetch_pr_metadata(
    api_url: str,
    repository: str,
    pr_number: int,
    token: str,
    *,
    request_json: Callable[[str, str], object] | None = None,
) -> tuple[dict, list[dict]]:
    root = f"{_repository_api_root(api_url, repository)}/pulls/{pr_number}"
    get_json = request_json if request_json is not None else _request_json
    pr = get_json(root, token)
    if not isinstance(pr, dict):
        raise RuntimeError("GitHub PR response is not an object")

    commits: list[dict] = []
    for page in range(1, 11):
        payload = get_json(f"{root}/commits?per_page=100&page={page}", token)
        if not isinstance(payload, list):
            raise RuntimeError("GitHub PR commits response is not a list")
        commits.extend(item for item in payload if isinstance(item, dict))
        if len(payload) < 100:
            return pr, commits
    raise RuntimeError("PR has more than 1000 commits; metadata validation is bounded")


def fetch_pr_files(
    api_url: str,
    repository: str,
    pr_number: int,
    token: str,
    *,
    request_json: Callable[[str, str], object] | None = None,
) -> list[dict]:
    root = f"{_repository_api_root(api_url, repository)}/pulls/{pr_number}/files"
    get_json = request_json if request_json is not None else _request_json
    files: list[dict] = []
    for page in range(1, 11):
        payload = get_json(f"{root}?per_page=100&page={page}", token)
        if not isinstance(payload, list):
            raise RuntimeError("GitHub PR files response is not a list")
        files.extend(item for item in payload if isinstance(item, dict))
        if len(payload) < 100:
            return files
    raise RuntimeError("PR changes more than 1000 files; metadata validation is bounded")


def fetch_branch_history(
    api_url: str,
    repository: str,
    head_owner: str,
    head_ref: str,
    token: str,
    *,
    request_json: Callable[[str, str], object] | None = None,
) -> list[dict]:
    root = f"{_repository_api_root(api_url, repository)}/pulls"
    get_json = request_json if request_json is not None else _request_json
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
        payload = get_json(f"{root}?{query}", token)
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


def _metadata_api_error_detail(error: BaseException) -> str:
    if isinstance(error, MetadataRequestError):
        return str(error)
    if isinstance(error, (json.JSONDecodeError, UnicodeDecodeError)):
        return "invalid_json"
    return type(error).__name__


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

    # An over-length title may be a generated Dependabot group title; defer
    # only that case until the verified commits are fetched. Every other
    # title failure is reported immediately, and the deferred title is
    # re-validated at the strict limit after compaction.
    title_failures = validate_subject(title, "PR title")
    title_deferred = bool(title_failures) and all(
        "at most" in failure.message for failure in title_failures
    )
    if not title_deferred:
        failures.extend(title_failures)
    failures.extend(validate_body(body))
    if failures:
        for failure in failures:
            emit_failure(failure)
        return 1

    metadata_client = MetadataApiClient()
    try:
        pr, commits = fetch_pr_metadata(
            api_url,
            repository,
            pr_number,
            token,
            request_json=metadata_client.request_json,
        )
    except (
        urllib.error.URLError,
        urllib.error.HTTPError,
        TimeoutError,
        RuntimeError,
        json.JSONDecodeError,
        UnicodeDecodeError,
    ) as exc:
        emit_failure(
            ValidationFailure(
                "metadata API",
                f"unable to fetch PR metadata: {_metadata_api_error_detail(exc)}",
            )
        )
        return 1

    if title_deferred:
        failures.extend(
            validate_subject(resolve_effective_pr_title(title, pr, commits), "PR title")
        )

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
                    request_json=metadata_client.request_json,
                )
            except (
                urllib.error.URLError,
                urllib.error.HTTPError,
                TimeoutError,
                RuntimeError,
                json.JSONDecodeError,
                UnicodeDecodeError,
            ) as exc:
                failures.append(
                    ValidationFailure(
                        "branch lifecycle",
                        f"unable to fetch branch history: {_metadata_api_error_detail(exc)}",
                    )
                )
            else:
                failures.extend(validate_pr_lifecycle(pr, pr_number, branch_history))

    for index, item in enumerate(commits, start=1):
        failures.extend(validate_commit_metadata(pr, item, f"commit {index}"))

    scan_changed = os.environ.get("INPUT_SCAN_CHANGED_FILES", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    if scan_changed:
        try:
            changed_files = fetch_pr_files(
                api_url,
                repository,
                pr_number,
                token,
                request_json=metadata_client.request_json,
            )
        except (
            urllib.error.URLError,
            urllib.error.HTTPError,
            TimeoutError,
            RuntimeError,
            json.JSONDecodeError,
            UnicodeDecodeError,
        ) as exc:
            failures.append(
                ValidationFailure(
                    "changed files",
                    f"unable to fetch PR files: {_metadata_api_error_detail(exc)}",
                )
            )
        else:
            failures.extend(validate_changed_files(changed_files))

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
