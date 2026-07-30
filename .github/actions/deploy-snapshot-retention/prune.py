"""Prune secret-free deploy snapshots without touching other backup data."""

from __future__ import annotations

import argparse
import datetime as dt
from dataclasses import dataclass
from pathlib import Path
import sys


UTC = dt.timezone.utc


@dataclass(frozen=True)
class PruneConfig:
    root: Path
    max_count: int
    max_age_days: int
    max_total_bytes: int
    now: dt.datetime | None = None


@dataclass(frozen=True)
class SnapshotEntry:
    path: Path
    size: int
    mtime: dt.datetime


@dataclass(frozen=True)
class PruneResult:
    root: Path
    kept: tuple[Path, ...]
    deleted: tuple[Path, ...]
    kept_bytes: int
    deleted_bytes: int
    total_bytes_before: int
    total_bytes_after: int
    over_budget_bytes: int


def _validate_root(root: Path) -> Path:
    if not root.is_absolute():
        raise ValueError("root must be absolute")
    if root.parent == root:
        raise ValueError("root must not be a filesystem root")
    if not root.exists() or not root.is_dir():
        raise ValueError("root must be an existing directory")
    if root.is_symlink():
        raise ValueError("root must not be a symlink")

    current = Path(root.anchor)
    for part in root.parts[1:]:
        current /= part
        if current.exists() and current.is_symlink():
            raise ValueError("root must not contain symlink components")
    return root


def _validate_positive_int(name: str, value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"{name} must be an integer")
    if value < 1:
        raise ValueError(f"{name} must be at least 1")
    return value


def _load_snapshots(root: Path) -> list[SnapshotEntry]:
    entries: list[SnapshotEntry] = []
    for child in root.iterdir():
        if child.is_symlink():
            raise ValueError("snapshot root must not contain symlinks")
        if not child.is_file() or not child.name.endswith(".tar.gz"):
            continue
        stat_result = child.stat()
        entries.append(
            SnapshotEntry(
                path=child,
                size=stat_result.st_size,
                mtime=dt.datetime.fromtimestamp(stat_result.st_mtime, tz=UTC),
            )
        )
    return entries


def prune_snapshots(config: PruneConfig) -> PruneResult:
    root = _validate_root(Path(config.root))
    max_count = _validate_positive_int("max_count", config.max_count)
    max_age_days = _validate_positive_int("max_age_days", config.max_age_days)
    max_total_bytes = _validate_positive_int("max_total_bytes", config.max_total_bytes)

    now = config.now or dt.datetime.now(UTC)
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("now must be timezone-aware")
    now = now.astimezone(UTC)

    ordered = sorted(_load_snapshots(root), key=lambda entry: (entry.mtime, entry.path.name), reverse=True)
    if not ordered:
        return PruneResult(root, (), (), 0, 0, 0, 0, 0)

    newest = ordered[0]
    cutoff = now - dt.timedelta(days=max_age_days)
    survivors: list[SnapshotEntry] = [newest]
    deletions: list[SnapshotEntry] = []

    for entry in ordered[1:]:
        if entry.mtime < cutoff:
            deletions.append(entry)
        else:
            survivors.append(entry)

    while len(survivors) > max_count:
        deletions.append(survivors.pop())

    kept_bytes = sum(entry.size for entry in survivors)
    while len(survivors) > 1 and kept_bytes > max_total_bytes:
        removed = survivors.pop()
        deletions.append(removed)
        kept_bytes -= removed.size

    deletions = sorted(deletions, key=lambda entry: (entry.mtime, entry.path.name))
    deleted_bytes = 0
    for entry in deletions:
        entry.path.unlink()
        deleted_bytes += entry.size

    kept_paths = tuple(entry.path for entry in survivors)
    deleted_paths = tuple(entry.path for entry in deletions)
    total_bytes_before = kept_bytes + deleted_bytes
    over_budget_bytes = max(0, kept_bytes - max_total_bytes)

    return PruneResult(
        root=root,
        kept=kept_paths,
        deleted=deleted_paths,
        kept_bytes=kept_bytes,
        deleted_bytes=deleted_bytes,
        total_bytes_before=total_bytes_before,
        total_bytes_after=kept_bytes,
        over_budget_bytes=over_budget_bytes,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--max-count", type=int, required=True)
    parser.add_argument("--max-age-days", type=int, required=True)
    parser.add_argument("--max-total-bytes", type=int, required=True)
    args = parser.parse_args(argv)

    result = prune_snapshots(
        PruneConfig(
            root=args.root,
            max_count=args.max_count,
            max_age_days=args.max_age_days,
            max_total_bytes=args.max_total_bytes,
        )
    )
    print(
        "retention_summary "
        f"kept={len(result.kept)} "
        f"deleted={len(result.deleted)} "
        f"kept_bytes={result.kept_bytes} "
        f"deleted_bytes={result.deleted_bytes} "
        f"total_before={result.total_bytes_before} "
        f"total_after={result.total_bytes_after} "
        f"over_budget_bytes={result.over_budget_bytes}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
