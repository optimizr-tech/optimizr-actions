"""Provider-neutral, secret-free request contract for protected delivery."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
from pathlib import Path
import re
import sys
from typing import Mapping


class RequestError(ValueError):
    """Raised when a delivery adapter submits an unsafe request."""


ADAPTERS = frozenset({"github-actions", "gitlab-ci", "ansible", "manual"})
REQUEST_KEYS = frozenset(
    {
        "adapter",
        "candidate_sha",
        "compose_file",
        "container_name",
        "reason",
        "repository",
        "service",
        "trusted_ref",
    }
)
IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)(?:password|secret|token|api[_-]?key|private[_-]?key|authorization)\s*[:=]"
)


@dataclass(frozen=True)
class DeployRequest:
    """The identity and source inputs shared by protected delivery adapters."""

    repository: str
    service: str
    candidate_sha: str
    trusted_ref: str
    compose_file: str
    container_name: str
    adapter: str
    reason: str | None = None


def _text(payload: Mapping[str, object], key: str, *, maximum: int = 256) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value or value != value.strip():
        raise RequestError(f"{key} must be a non-empty trimmed string")
    if len(value) > maximum or any(character.isspace() for character in value):
        raise RequestError(f"{key} must be bounded and must not contain whitespace")
    return value


def _identifier(value: str, field: str) -> str:
    if not IDENTIFIER_RE.fullmatch(value):
        raise RequestError(f"{field} must be a bounded identifier")
    return value


def _trusted_ref(value: str) -> str:
    if not (
        value.startswith(("refs/heads/", "refs/tags/"))
        and value.count("/") >= 2
        and ".." not in value
        and "//" not in value
        and "\\" not in value
        and not any(character.isspace() for character in value)
    ):
        raise RequestError("trusted_ref must be a trusted heads or tags ref")
    return value


def _compose_file(value: str) -> str:
    parts = value.split("/")
    if (
        value.startswith(("/", "\\"))
        or "\\" in value
        or any(part in {"", ".", ".."} for part in parts)
        or not value.lower().endswith((".yml", ".yaml"))
    ):
        raise RequestError("compose_file must be a relative POSIX YAML path")
    return value


def parse_request(payload: Mapping[str, object]) -> DeployRequest:
    """Parse and validate a request without performing any host operation."""

    if not isinstance(payload, Mapping):
        raise RequestError("request must be a JSON object")
    unknown = set(payload) - REQUEST_KEYS
    if unknown:
        raise RequestError(
            "request contains unknown fields: " + ", ".join(sorted(unknown))
        )

    repository = _text(payload, "repository", maximum=129)
    owner, separator, name = repository.partition("/")
    if not separator or "/" in name:
        raise RequestError("repository must be an owner/name identifier")
    _identifier(owner, "repository owner")
    _identifier(name, "repository name")

    service = _identifier(_text(payload, "service"), "service")
    candidate_sha = _text(payload, "candidate_sha")
    if not SHA_RE.fullmatch(candidate_sha):
        raise RequestError("candidate_sha must be a lowercase 40-character commit SHA")
    trusted_ref = _trusted_ref(_text(payload, "trusted_ref"))
    compose_file = _compose_file(_text(payload, "compose_file"))
    container_name = _identifier(_text(payload, "container_name"), "container_name")
    adapter = _text(payload, "adapter")
    if adapter not in ADAPTERS:
        raise RequestError("adapter must identify a protected delivery adapter")

    reason = payload.get("reason")
    if reason is not None:
        if not isinstance(reason, str) or not reason or len(reason) > 256:
            raise RequestError("reason must be a bounded string")
        if reason != reason.strip() or any(character in reason for character in "\r\n"):
            raise RequestError(
                "reason must not contain leading, trailing, or newline characters"
            )
        if SECRET_ASSIGNMENT_RE.search(reason):
            raise RequestError("reason must not contain secret-like assignments")

    return DeployRequest(
        repository=repository,
        service=service,
        candidate_sha=candidate_sha,
        trusted_ref=trusted_ref,
        compose_file=compose_file,
        container_name=container_name,
        adapter=adapter,
        reason=reason,
    )


def canonicalize_request(request: DeployRequest) -> dict[str, str]:
    """Return the stable, secret-free representation used by adapters/evidence."""

    result = {
        "adapter": request.adapter,
        "candidate_sha": request.candidate_sha,
        "compose_file": request.compose_file,
        "container_name": request.container_name,
        "repository": request.repository,
        "service": request.service,
        "trusted_ref": request.trusted_ref,
    }
    if request.reason is not None:
        result["reason"] = request.reason
    return result


def load_request(path: Path, allowed_root: Path) -> DeployRequest:
    """Load a request only from a regular file below an explicit root."""

    try:
        root = allowed_root.resolve(strict=True)
        raw_request_path = Path(path)
        if not raw_request_path.is_absolute():
            raw_request_path = Path.cwd() / raw_request_path
        current = Path(raw_request_path.anchor)
        for component in raw_request_path.parts[1:]:
            current /= component
            if current.is_symlink():
                raise RequestError("request path must not contain symlink components")
        request_path = raw_request_path.resolve(strict=True)
    except OSError as exc:
        raise RequestError("request path could not be resolved") from exc
    if not root.is_dir() or root == request_path or root not in request_path.parents:
        raise RequestError("request path must remain below the allowed root")
    if not request_path.is_file() or request_path.is_symlink():
        raise RequestError("request path must be a regular file")
    try:
        payload = json.loads(request_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RequestError("request file must contain valid UTF-8 JSON") from exc
    return parse_request(payload)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        request = load_request(args.request, args.root)
    except RequestError as exc:
        print(f"delivery request rejected: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(canonicalize_request(request), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
