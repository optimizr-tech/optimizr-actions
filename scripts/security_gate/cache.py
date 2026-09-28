#!/usr/bin/env python3
"""Resolve and safely maintain the shared Trivy database cache."""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import shutil
import time
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path

_VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$")
_CACHE_DIR_RE = re.compile(r"^trivy-v([A-Za-z0-9][A-Za-z0-9._-]{0,31})$")
_CACHE_SCOPES = {"repository", "shared"}


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


def shared_cache_root(*, cache_home: Path) -> Path:
    return cache_home / "optimizr-security-gate" / "shared"


def lock_root(*, repository: str, cache_home: Path, cache_scope: str) -> Path:
    repository_namespace(repository)
    if cache_scope not in _CACHE_SCOPES:
        raise CacheError("cache_scope must be repository or shared")
    # Scan-result caches remain per repository in both modes. Shared mode has
    # a second version-scoped lock for vulnerability DB refresh/read access.
    return cache_root(repository=repository, cache_home=cache_home)


def cache_dir(
    *, repository: str, trivy_version: str, cache_home: Path, cache_scope: str = "repository"
) -> Path:
    if cache_scope not in _CACHE_SCOPES:
        raise CacheError("cache_scope must be repository or shared")
    root = cache_root(repository=repository, cache_home=cache_home)
    if cache_scope == "shared":
        # Keep shared scans separate from existing repository-scoped jobs so
        # enabling the shared DB never replaces a cache that an older job uses.
        root = root / "shared-scan"
    return root / f"trivy-v{normalize_version(trivy_version)}"


def shared_cache_dir(*, trivy_version: str, cache_home: Path) -> Path:
    return shared_cache_root(cache_home=cache_home) / (
        f"trivy-v{normalize_version(trivy_version)}"
    )


def _assert_not_symlink(path: Path) -> None:
    if path.is_symlink():
        raise CacheError(f"cache path must not be a symbolic link: {path}")


def _prune_old_versions(
    *,
    root: Path,
    current: Path,
    retention_days: int,
    now: float | None,
    coordinate_with_version_locks: bool = False,
) -> None:
    current_time = time.time() if now is None else now
    cutoff = current_time - retention_days * 24 * 60 * 60
    for candidate in root.iterdir():
        if candidate == current or not _CACHE_DIR_RE.fullmatch(candidate.name):
            continue
        _assert_not_symlink(candidate)
        if not candidate.is_dir() or candidate.stat().st_mtime >= cutoff:
            continue

        lock_fd: int | None = None
        if coordinate_with_version_locks:
            try:
                import fcntl
            except ImportError:
                # On platforms without flock support, retain old shared DBs;
                # deleting without coordinating could break an active scan.
                continue
            setup_lock_path = candidate.with_name(f"{candidate.name}.setup.lock")
            database_lock_path = candidate.with_name(f"{candidate.name}.db.lock")
            lock_fds: list[int] = []
            lock_busy = False
            try:
                for lock_path in (setup_lock_path, database_lock_path):
                    flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
                    try:
                        lock_fd = os.open(lock_path, flags, 0o600)
                    except OSError as error:
                        raise CacheError(
                            f"cannot safely open shared cache lock: {lock_path}"
                        ) from error
                    try:
                        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    except BlockingIOError:
                        os.close(lock_fd)
                        lock_busy = True
                        break
                    except OSError:
                        os.close(lock_fd)
                        raise
                    lock_fds.append(lock_fd)
                if not lock_busy and candidate.is_dir() and candidate.stat().st_mtime < cutoff:
                    shutil.rmtree(candidate)
            finally:
                for lock_fd in reversed(lock_fds):
                    fcntl.flock(lock_fd, fcntl.LOCK_UN)
                    os.close(lock_fd)
            continue

        try:
            if candidate.is_dir() and candidate.stat().st_mtime < cutoff:
                shutil.rmtree(candidate)
        finally:
            if lock_fd is not None:
                os.close(lock_fd)


def _database_is_complete(path: Path) -> bool:
    metadata = path / "metadata.json"
    database = path / "trivy.db"
    return all(
        candidate.is_file() and not candidate.is_symlink()
        for candidate in (metadata, database)
    )


def _parse_timestamp(value: object) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("timestamp must be a non-empty string")
    normalized = value.strip()
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def database_is_fresh(
    path: Path, *, max_age_hours: float, now: datetime | None = None
) -> bool:
    """Return whether a usable Trivy DB is within the caller's age limit."""
    if not math.isfinite(max_age_hours) or max_age_hours <= 0:
        raise CacheError("max_age_hours must be greater than zero")
    if not _database_is_complete(path):
        return False
    try:
        content = json.loads((path / "metadata.json").read_text(encoding="utf-8"))
        if (
            not isinstance(content, dict)
            or type(content.get("Version")) is not int
            or content["Version"] < 1
        ):
            return False
        downloaded_at = _parse_timestamp(content.get("DownloadedAt"))
    except (OSError, ValueError, TypeError):
        return False
    reference = now or datetime.now(timezone.utc)
    if reference.tzinfo is None:
        reference = reference.replace(tzinfo=timezone.utc)
    age_hours = (reference.astimezone(timezone.utc) - downloaded_at).total_seconds() / 3600
    return 0 <= age_hours <= max_age_hours


def _prepare_shared_database(*, current: Path, shared_current: Path) -> None:
    local_database = current / "db"
    shared_database = shared_current / "db"
    _assert_not_symlink(shared_current)
    shared_current.mkdir(parents=True, exist_ok=True)
    _assert_not_symlink(shared_current)
    _assert_not_symlink(shared_database)

    if shared_database.exists() and not shared_database.is_dir():
        raise CacheError("shared vulnerability database path must be a directory")
    if local_database.is_symlink() and (
        local_database.resolve() != shared_database.resolve(strict=False)
    ):
        raise CacheError("shared-scan vulnerability database link has an unexpected target")
    shared_database.mkdir(parents=True, exist_ok=True)
    if local_database.is_symlink():
        return
    if local_database.exists():
        if not local_database.is_dir():
            raise CacheError("shared-scan vulnerability database path must be a directory")
        # This path is dedicated to shared mode and protected by the
        # per-repository lock. Never move or delete the repository-mode DB.
        shutil.rmtree(local_database)
    os.symlink(
        str(shared_database.resolve(strict=False)),
        str(local_database),
        target_is_directory=True,
    )


def invalidate_shared_database(*, shared_current: Path) -> None:
    """Empty only a versioned shared DB so Trivy can rebuild a corrupt one."""
    shared_database = shared_current / "db"
    _assert_not_symlink(shared_current)
    _assert_not_symlink(shared_database)
    if not shared_database.exists():
        shared_database.mkdir(parents=True, exist_ok=True)
        return
    if not shared_database.is_dir():
        raise CacheError("shared vulnerability database path must be a directory")
    shutil.rmtree(shared_database)
    shared_database.mkdir(parents=True)


def prepare(
    *,
    root: Path,
    current: Path,
    retention_days: int,
    now: float | None = None,
    shared_root: Path | None = None,
    shared_current: Path | None = None,
) -> None:
    """Prepare repository cache and optionally link its Trivy DB to shared storage.

    The caller holds the selected cache lock while preparing. Shared scans use
    a separate per-repository scan cache and link only the vulnerability DB.
    The previous unversioned ``trivy`` directory is migrated only in the
    backwards-compatible repository scope.
    """

    if retention_days < 1 or retention_days > 365:
        raise CacheError("retention_days must be between 1 and 365")
    if (shared_root is None) != (shared_current is None):
        raise CacheError("shared_root and shared_current must be provided together")
    _assert_not_symlink(root)
    root.mkdir(parents=True, exist_ok=True)
    _assert_not_symlink(root)

    legacy = root / "trivy"
    _assert_not_symlink(legacy)
    _assert_not_symlink(current.parent)
    current.parent.mkdir(parents=True, exist_ok=True)
    if shared_root is None and legacy.is_dir() and not current.exists():
        shutil.move(str(legacy), str(current))
    current.mkdir(parents=True, exist_ok=True)
    _assert_not_symlink(current)

    _prune_old_versions(
        root=current.parent,
        current=current,
        retention_days=retention_days,
        now=now,
    )
    if shared_root is not None and shared_current is not None:
        _assert_not_symlink(shared_root)
        shared_root.mkdir(parents=True, exist_ok=True)
        _assert_not_symlink(shared_root)
        _prepare_shared_database(current=current, shared_current=shared_current)
        _prune_old_versions(
            root=shared_root,
            current=shared_current,
            retention_days=retention_days,
            now=now,
            coordinate_with_version_locks=True,
        )


def _cache_home() -> Path:
    return Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache")


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    for name in ("root", "path"):
        subparser = subparsers.add_parser(name)
        subparser.add_argument("--repository", required=True)
        subparser.add_argument("--trivy-version", default="v0.74.0")
        subparser.add_argument(
            "--cache-scope", choices=sorted(_CACHE_SCOPES), default="repository"
        )

    subparsers.add_parser("shared-root")

    shared_path_parser = subparsers.add_parser("shared-path")
    shared_path_parser.add_argument("--trivy-version", required=True)

    prepare_parser = subparsers.add_parser("prepare")
    prepare_parser.add_argument("--repository", required=True)
    prepare_parser.add_argument("--trivy-version", required=True)
    prepare_parser.add_argument("--retention-days", type=int, default=14)
    prepare_parser.add_argument(
        "--cache-scope", choices=sorted(_CACHE_SCOPES), default="repository"
    )

    freshness_parser = subparsers.add_parser("database-fresh")
    freshness_parser.add_argument("--database", type=Path, required=True)
    freshness_parser.add_argument("--max-age-hours", type=float, required=True)

    invalidate_parser = subparsers.add_parser("invalidate-shared-db")
    invalidate_parser.add_argument("--trivy-version", required=True)

    args = parser.parse_args()
    cache_home = _cache_home()
    if args.command == "root":
        print(
            lock_root(
                repository=args.repository,
                cache_home=cache_home,
                cache_scope=args.cache_scope,
            )
        )
    elif args.command == "path":
        print(
            cache_dir(
                repository=args.repository,
                trivy_version=args.trivy_version,
                cache_home=cache_home,
                cache_scope=args.cache_scope,
            )
        )
    elif args.command == "shared-root":
        print(shared_cache_root(cache_home=cache_home))
    elif args.command == "shared-path":
        print(shared_cache_dir(trivy_version=args.trivy_version, cache_home=cache_home))
    elif args.command == "database-fresh":
        print(
            "true"
            if database_is_fresh(args.database, max_age_hours=args.max_age_hours)
            else "false"
        )
    elif args.command == "invalidate-shared-db":
        invalidate_shared_database(
            shared_current=shared_cache_dir(
                trivy_version=args.trivy_version, cache_home=cache_home
            )
        )
    else:
        root = cache_root(repository=args.repository, cache_home=cache_home)
        shared_root = (
            shared_cache_root(cache_home=cache_home)
            if args.cache_scope == "shared"
            else None
        )
        prepare(
            root=root,
            current=cache_dir(
                repository=args.repository,
                trivy_version=args.trivy_version,
                cache_home=cache_home,
                cache_scope=args.cache_scope,
            ),
            retention_days=args.retention_days,
            shared_root=shared_root,
            shared_current=(
                shared_cache_dir(trivy_version=args.trivy_version, cache_home=cache_home)
                if shared_root is not None
                else None
            ),
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
