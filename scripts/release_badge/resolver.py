#!/usr/bin/env python3
"""Resolve and validate the release tag used by badge recovery."""

from __future__ import annotations

import argparse
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
from typing import Sequence

SEMVER_RE = re.compile(
    r"^v(0|[1-9][0-9]*)\."
    r"(0|[1-9][0-9]*)\."
    r"(0|[1-9][0-9]*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)
BRANCH_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$")


class BadgeError(ValueError):
    """Raised when badge recovery inputs are invalid."""


def validate_inputs(branch: str, badge_path: str) -> tuple[str, str]:
    if not isinstance(branch, str) or not BRANCH_RE.fullmatch(branch) or ".." in branch.split("/") or "//" in branch or branch.endswith("/"):
        raise BadgeError("branch must be a bounded Git ref name")
    if not isinstance(badge_path, str) or not badge_path or len(badge_path) > 512 or "\\" in badge_path:
        raise BadgeError("badge_path must be repository relative")
    path = PurePosixPath(badge_path)
    if path.is_absolute() or ".." in path.parts or path.as_posix() in {"", "."}:
        raise BadgeError("badge_path must remain repository relative")
    return branch, path.as_posix()


def _valid_semver(value: str) -> bool:
    return bool(SEMVER_RE.fullmatch(value))


def resolve_version(requested: str, event_tag: str, repository: Path) -> str:
    for candidate in (requested, event_tag):
        if candidate:
            if not _valid_semver(candidate):
                raise BadgeError("release tag must be a v-prefixed semantic version")
            return candidate
    try:
        completed = subprocess.run(
            ["git", "tag", "--list", "v*", "--sort=-v:refname"],
            cwd=repository,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise BadgeError("could not enumerate repository tags") from exc
    if completed.returncode != 0:
        raise BadgeError("git tag enumeration failed")
    for line in completed.stdout.splitlines():
        candidate = line.strip()
        if _valid_semver(candidate):
            return candidate
    raise BadgeError("no valid release tag was found")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--requested", default="")
    parser.add_argument("--event-tag", default="")
    parser.add_argument("--branch", required=True)
    parser.add_argument("--badge-path", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--github-output", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        validate_inputs(args.branch, args.badge_path)
        version = resolve_version(args.requested, args.event_tag, Path(args.repository))
        with Path(args.github_output).open("a", encoding="utf-8") as output:
            output.write(f"version={version}\n")
        return 0
    except (BadgeError, OSError) as exc:
        print(f"release badge recovery error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
