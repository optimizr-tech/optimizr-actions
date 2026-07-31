"""Create or update the single marker-delimited quality-gate PR comment."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any
from urllib import error, request

from scripts.quality_gate.render_comment import MARKER_PREFIX

API = "https://api.github.com"


def _request(method: str, url: str, token: str, payload: dict[str, Any] | None = None) -> Any:
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    req = request.Request(
        url,
        method=method,
        data=data,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "Content-Type": "application/json",
            "User-Agent": "optimizr-quality-gate",
        },
    )
    try:
        with request.urlopen(req, timeout=30) as response:
            raw = response.read()
    except error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:500]
        raise RuntimeError(f"GitHub API {exc.code}: {detail}") from exc
    return json.loads(raw) if raw else None


def _existing_comment(repository: str, pull_number: int, token: str) -> dict[str, Any] | None:
    page = 1
    while True:
        comments = _request(
            "GET",
            f"{API}/repos/{repository}/issues/{pull_number}/comments?per_page=100&page={page}",
            token,
        )
        if not isinstance(comments, list):
            raise RuntimeError("GitHub comments response was not a list")
        for comment in comments:
            if isinstance(comment, dict) and str(comment.get("body", "")).startswith(MARKER_PREFIX):
                return comment
        if len(comments) < 100:
            return None
        page += 1


def upsert(repository: str, pull_number: int, token: str, body: str) -> None:
    if not body.startswith(MARKER_PREFIX):
        raise ValueError("quality-gate comment is missing its idempotency marker")
    existing = _existing_comment(repository, pull_number, token)
    if existing is None:
        _request(
            "POST",
            f"{API}/repos/{repository}/issues/{pull_number}/comments",
            token,
            {"body": body},
        )
        return
    comment_id = existing.get("id")
    if not isinstance(comment_id, int):
        raise RuntimeError("existing quality-gate comment has no numeric id")
    _request(
        "PATCH",
        f"{API}/repos/{repository}/issues/comments/{comment_id}",
        token,
        {"body": body},
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", required=True)
    parser.add_argument("--pull-number", type=int, required=True)
    parser.add_argument("--token-file", type=Path, required=True)
    parser.add_argument("--body-file", type=Path, required=True)
    args = parser.parse_args(argv)
    token = args.token_file.read_text(encoding="utf-8").strip()
    if not token:
        raise ValueError("GitHub token is empty")
    upsert(
        args.repository,
        args.pull_number,
        token,
        args.body_file.read_text(encoding="utf-8"),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
