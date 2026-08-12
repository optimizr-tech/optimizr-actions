#!/usr/bin/env python3
"""Resolve and safely maintain the shared Trivy database cache."""

from __future__ import annotations

import argparse
import re
import shutil
import time
from hashlib import sha256
from pathlib import Path

_VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$")
_CACHE_DIR_RE = re.compile(r"^trivy-v([A-Za-z0-9][A-Za-z0-9._-]{0,31})$")


class CacheError(ValueError):
    """Raised when a cache path or retention policy is unsafe."""


def normalize_version(version: str) -> str:
    normalized = version.removeprefix("v")
    if not _VERSION_RE.fullmatch(normalized):
        raise CacheError("trivy_version must be a simple version identifier")
    return normalized


def repository_namespace(repository: str) -> str:
    if not repository or "/" not in repository:
        raise CacheError("repository must be owner/name")
    return sha256(repository.encode("utf-8")).hexdigest()[:24]


def cache_root(*, repository: str, cache_home: Path) -> Path:
    return cache_home / "optimizr-security-gate" / repository_namespace(repository)


def cache_dir(*, repository: str, trivy_version: str, cache_home: Path) -> Path:
    return cache_root(repository=repository, cache_home=cache_home) / (
        f"trivy-v{normalize_version(trivy_version)}"
    )


def _assert_not_symlink(path: Path) -> None:
    if path.is_symlink():
        raise CacheError(f"cache path must not be a symbolic link: {path}")


def prepare(*, root: Path, current: Path, retention_days: int, now: float | None = None) -> None:
    """Create the current cache and remove only old versioned siblings.

    The caller must hold the repository-level gate lock while invoking this
    function. The previous unversioned ``trivy`` directory is migrated once,
    so existing databases are reused instead of downloaded again.
    """

    if retention_days < 1 or retention_days > 365:
        raise CacheError("retention_days must be between 1 and 365")
    _assert_not_symlink(root)
    root.mkdir(parents=True, exist_ok=True)
    _assert_not_symlink(root)

    legacy = root / "trivy"
    versioned_parent = root
    _assert_not_symlink(legacy)
    _assert_not_symlink(current)
    if legacy.is_dir() and not current.exists():
        current.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(legacy), str(current))
    current.mkdir(parents=True, exist_ok=True)
    _assert_not_symlink(current)

    current_time = time.time() if now is None else now
    cutoff = current_time - retention_days * 24 * 60 * 60
    for candidate in versioned_parent.iterdir():
        if candidate == current or not _CACHE_DIR_RE.fullmatch(candidate.name):
            continue
        _assert_not_symlink(candidate)
        if not candidate.is_dir() or candidate.stat().st_mtime >= cutoff:
            continue
        shutil.rmtree(candidate)


def _cache_home() -> Path:
    import os

    return Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache")


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    for name in ("root", "path"):
        subparser = subparsers.add_parser(name)
        subparser.add_argument("--repository", required=True)
        subparser.add_argument("--trivy-version", default="v0.70.0")

    prepare_parser = subparsers.add_parser("prepare")
    prepare_parser.add_argument("--repository", required=True)
    prepare_parser.add_argument("--trivy-version", required=True)
    prepare_parser.add_argument("--retention-days", type=int, default=14)

    args = parser.parse_args()
    root = cache_root(repository=args.repository, cache_home=_cache_home())
    if args.command == "root":
        print(root)
    elif args.command == "path":
        print(
            cache_dir(
                repository=args.repository,
                trivy_version=args.trivy_version,
                cache_home=_cache_home(),
            )
        )
    else:
        prepare(
            root=root,
            current=cache_dir(
                repository=args.repository,
                trivy_version=args.trivy_version,
                cache_home=_cache_home(),
            ),
            retention_days=args.retention_days,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
