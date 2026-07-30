"""Regression checks for deploy snapshot retention."""

from __future__ import annotations

import datetime as dt
import os
import runpy
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / ".github/actions/deploy-snapshot-retention/prune.py"
MODULE = runpy.run_path(str(SCRIPT))
prune_snapshots = MODULE["prune_snapshots"]
PruneConfig = MODULE["PruneConfig"]

UTC = dt.timezone.utc


class DeploySnapshotRetentionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "deploys"
        self.root.mkdir()

    def snapshot(
        self,
        name: str,
        *,
        size: int,
        when: dt.datetime,
    ) -> Path:
        path = self.root / name
        path.write_bytes(b"x" * size)
        timestamp = when.timestamp()
        path.touch()
        path.chmod(0o600)
        os.utime(path, (timestamp, timestamp))
        return path

    def test_prunes_old_snapshots_but_keeps_non_snapshot_files(self) -> None:
        older = self.snapshot(
            "20260730T120000Z.tar.gz",
            size=10,
            when=dt.datetime(2026, 7, 30, 12, 0, tzinfo=UTC),
        )
        middle = self.snapshot(
            "20260730T120100Z.tar.gz",
            size=20,
            when=dt.datetime(2026, 7, 30, 12, 1, tzinfo=UTC),
        )
        newer = self.snapshot(
            "20260730T120200Z.tar.gz",
            size=30,
            when=dt.datetime(2026, 7, 30, 12, 2, tzinfo=UTC),
        )
        notes = self.root / "notes.txt"
        notes.write_text("keep me", encoding="utf-8")

        result = prune_snapshots(
            PruneConfig(
                root=self.root,
                max_count=2,
                max_age_days=30,
                max_total_bytes=10_000,
                now=dt.datetime(2026, 7, 30, 12, 5, tzinfo=UTC),
            )
        )

        self.assertEqual((older,), result.deleted)
        self.assertTrue(newer.exists())
        self.assertTrue(notes.exists())
        self.assertEqual([newer.name, middle.name], [path.name for path in result.kept])

    def test_prunes_expired_snapshots_by_age(self) -> None:
        expired = self.snapshot(
            "20260601T120000Z.tar.gz",
            size=10,
            when=dt.datetime(2026, 6, 1, 12, 0, tzinfo=UTC),
        )
        fresh = self.snapshot(
            "20260730T120100Z.tar.gz",
            size=20,
            when=dt.datetime(2026, 7, 30, 12, 1, tzinfo=UTC),
        )

        result = prune_snapshots(
            PruneConfig(
                root=self.root,
                max_count=10,
                max_age_days=7,
                max_total_bytes=10_000,
                now=dt.datetime(2026, 7, 30, 12, 5, tzinfo=UTC),
            )
        )

        self.assertEqual((expired,), result.deleted)
        self.assertTrue(fresh.exists())
        self.assertEqual([fresh.name], [path.name for path in result.kept])

    def test_preserves_newest_snapshot_even_when_over_budget(self) -> None:
        older = self.snapshot(
            "20260730T120000Z.tar.gz",
            size=90,
            when=dt.datetime(2026, 7, 30, 12, 0, tzinfo=UTC),
        )
        newer = self.snapshot(
            "20260730T120100Z.tar.gz",
            size=80,
            when=dt.datetime(2026, 7, 30, 12, 1, tzinfo=UTC),
        )

        result = prune_snapshots(
            PruneConfig(
                root=self.root,
                max_count=1,
                max_age_days=1,
                max_total_bytes=1,
                now=dt.datetime(2026, 7, 30, 12, 5, tzinfo=UTC),
            )
        )

        self.assertEqual((older,), result.deleted)
        self.assertTrue(newer.exists())
        self.assertEqual([newer.name], [path.name for path in result.kept])

    def test_rejects_symlink_children_and_root_symlinks(self) -> None:
        link = self.root / "linked.tar.gz"
        link.write_bytes(b"x" * 10)

        original = Path.is_symlink

        def fake_is_symlink(path: Path) -> bool:
            return path == link or original(path)

        try:
            Path.is_symlink = fake_is_symlink  # type: ignore[assignment]
            with self.assertRaisesRegex(ValueError, "symlink"):
                prune_snapshots(
                    PruneConfig(
                        root=self.root,
                        max_count=10,
                        max_age_days=30,
                        max_total_bytes=1_000,
                        now=dt.datetime(2026, 7, 30, 12, 5, tzinfo=UTC),
                    )
                )
        finally:
            Path.is_symlink = original  # type: ignore[assignment]


if __name__ == "__main__":
    unittest.main()
