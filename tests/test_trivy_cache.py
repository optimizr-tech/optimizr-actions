from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from io import StringIO
from pathlib import Path
from unittest.mock import patch

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows test hosts do not provide flock
    fcntl = None

from scripts.security_gate import cache as cache_module
from scripts.security_gate.cache import (
    CacheError,
    cache_dir,
    cache_root,
    database_is_fresh,
    invalidate_shared_database,
    lock_root,
    prepare,
    shared_cache_dir,
    shared_cache_root,
)


class TrivyCacheTests(unittest.TestCase):
    def test_cache_is_namespaced_by_repository_and_trivy_version(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            cache_home = Path(temporary)
            serve = cache_dir(
                repository="optimizr-tech/optimizr-serve",
                trivy_version="v0.70.0",
                cache_home=cache_home,
            )
            actions = cache_dir(
                repository="optimizr-tech/optimizr-actions",
                trivy_version="v0.70.0",
                cache_home=cache_home,
            )
            next_version = cache_dir(
                repository="optimizr-tech/optimizr-serve",
                trivy_version="v0.71.0",
                cache_home=cache_home,
            )
            shared_scope = cache_dir(
                repository="optimizr-tech/optimizr-serve",
                trivy_version="v0.70.0",
                cache_home=cache_home,
                cache_scope="shared",
            )

            self.assertNotEqual(serve, actions)
            self.assertNotEqual(serve, next_version)
            self.assertNotEqual(serve, shared_scope)
            self.assertEqual(
                serve.parent,
                cache_root(
                    repository="optimizr-tech/optimizr-serve", cache_home=cache_home
                ),
            )

    def test_prepare_migrates_legacy_cache_and_prunes_old_versions(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            cache_home = Path(temporary)
            root = cache_root(
                repository="optimizr-tech/optimizr-serve", cache_home=cache_home
            )
            legacy = root / "trivy"
            legacy.mkdir(parents=True)
            (legacy / "db").mkdir()
            (legacy / "db" / "metadata.json").write_text("{}", encoding="utf-8")

            old = root / "trivy-v0.69.0"
            old.mkdir(parents=True)
            old.touch()
            old_timestamp = 1_600_000_000
            os.utime(old, (old_timestamp, old_timestamp))
            current = root / "trivy-v0.70.0"

            prepare(root=root, current=current, retention_days=14, now=1_700_000_000)

            self.assertTrue((current / "db" / "metadata.json").exists())
            self.assertFalse(legacy.exists())
            self.assertFalse(old.exists())

    def test_prepare_rejects_symlinked_cache(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            cache_home = Path(temporary)
            root = cache_root(
                repository="optimizr-tech/optimizr-serve", cache_home=cache_home
            )
            root.mkdir(parents=True)
            target = Path(temporary) / "outside"
            target.mkdir()
            try:
                (root / "trivy-v0.70.0").symlink_to(target, target_is_directory=True)
            except OSError as error:
                if getattr(error, "winerror", None) == 1314:
                    self.skipTest("creating symlinks requires elevated Windows privileges")
                raise

            with self.assertRaises(CacheError):
                prepare(
                    root=root,
                    current=root / "trivy-v0.70.0",
                    retention_days=14,
                )

    def test_shared_scope_keeps_scan_locks_per_repo_and_shares_versioned_db(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            cache_home = Path(temporary)
            serve = "optimizr-tech/optimizr-serve"
            actions = "optimizr-tech/optimizr-actions"

            self.assertNotEqual(
                lock_root(repository=serve, cache_home=cache_home, cache_scope="shared"),
                lock_root(repository=actions, cache_home=cache_home, cache_scope="shared"),
            )
            self.assertNotEqual(
                cache_dir(repository=serve, trivy_version="v0.74.0", cache_home=cache_home),
                cache_dir(repository=actions, trivy_version="v0.74.0", cache_home=cache_home),
            )
            self.assertEqual(
                lock_root(repository=serve, cache_home=cache_home, cache_scope="shared"),
                cache_root(repository=serve, cache_home=cache_home),
            )
            self.assertNotEqual(
                shared_cache_dir(trivy_version="v0.74.0", cache_home=cache_home),
                shared_cache_dir(trivy_version="v0.75.0", cache_home=cache_home),
            )

    def test_shared_prepare_preserves_repository_database_and_links_shared_db(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            cache_home = Path(temporary)
            shared_root = shared_cache_root(cache_home=cache_home)
            shared_current = shared_cache_dir(
                trivy_version="v0.74.0", cache_home=cache_home
            )
            repository = "optimizr-tech/optimizr-serve"
            root = cache_root(repository=repository, cache_home=cache_home)
            repository_current = cache_dir(
                repository=repository,
                trivy_version="v0.74.0",
                cache_home=cache_home,
            )
            original_database = repository_current / "db"
            original_database.mkdir(parents=True)
            (original_database / "trivy.db").write_bytes(b"repository-database")
            (original_database / "metadata.json").write_text("{}", encoding="utf-8")

            shared_scan_cache = cache_dir(
                repository=repository,
                trivy_version="v0.74.0",
                cache_home=cache_home,
                cache_scope="shared",
            )
            prepare(
                root=root,
                current=shared_scan_cache,
                retention_days=14,
                shared_root=shared_root,
                shared_current=shared_current,
            )

            shared_database = shared_current / "db"
            self.assertTrue((shared_scan_cache / "db").is_symlink())
            self.assertEqual((shared_scan_cache / "db").resolve(), shared_database.resolve())
            self.assertEqual((original_database / "trivy.db").read_bytes(), b"repository-database")
            self.assertFalse((shared_database / "trivy.db").exists())

    def test_database_freshness_rejects_missing_corrupt_or_stale_db(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "db"
            database.mkdir()
            (database / "trivy.db").write_bytes(b"database")
            now = datetime(2026, 9, 28, 12, tzinfo=timezone.utc)
            metadata = {
                "Version": 2,
                "UpdatedAt": "2026-09-28T11:00:00Z",
                "NextUpdate": "2026-09-29T11:00:00Z",
                "DownloadedAt": (now - timedelta(hours=2)).isoformat(),
            }
            (database / "metadata.json").write_text(
                json.dumps(metadata), encoding="utf-8"
            )

            self.assertTrue(
                database_is_fresh(database, max_age_hours=30, now=now)
            )
            self.assertFalse(
                database_is_fresh(database, max_age_hours=1, now=now)
            )
            (database / "metadata.json").write_text("[]", encoding="utf-8")
            self.assertFalse(
                database_is_fresh(database, max_age_hours=30, now=now)
            )

            (database / "trivy.db").write_bytes(b"database")
            metadata["Version"] = 0
            (database / "metadata.json").write_text(
                json.dumps(metadata), encoding="utf-8"
            )
            self.assertFalse(
                database_is_fresh(database, max_age_hours=30, now=now)
            )
            metadata["Version"] = 2
            metadata["DownloadedAt"] = (now + timedelta(hours=1)).isoformat()
            (database / "metadata.json").write_text(
                json.dumps(metadata), encoding="utf-8"
            )
            self.assertFalse(
                database_is_fresh(database, max_age_hours=30, now=now)
            )
            with self.assertRaises(CacheError):
                database_is_fresh(database, max_age_hours=float("nan"), now=now)
            (database / "metadata.json").write_text(
                json.dumps(metadata), encoding="utf-8"
            )
            (database / "trivy.db").unlink()
            self.assertFalse(
                database_is_fresh(database, max_age_hours=30, now=now)
            )

    def test_prepare_rejects_database_symlink_outside_shared_cache(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            cache_home = Path(temporary)
            root = cache_root(
                repository="optimizr-tech/optimizr-serve", cache_home=cache_home
            )
            current = cache_dir(
                repository="optimizr-tech/optimizr-serve",
                trivy_version="v0.74.0",
                cache_home=cache_home,
            )
            outside = Path(temporary) / "outside-db"
            outside.mkdir()
            (outside / "sentinel").write_text("preserve", encoding="utf-8")
            current.mkdir(parents=True)
            try:
                (current / "db").symlink_to(outside, target_is_directory=True)
            except OSError as error:
                if getattr(error, "winerror", None) == 1314:
                    self.skipTest("creating symlinks requires elevated Windows privileges")
                raise

            with self.assertRaises(CacheError):
                prepare(
                    root=root,
                    current=current,
                    retention_days=14,
                    shared_root=shared_cache_root(cache_home=cache_home),
                    shared_current=shared_cache_dir(
                        trivy_version="v0.74.0", cache_home=cache_home
                    ),
                )

            self.assertEqual((outside / "sentinel").read_text(encoding="utf-8"), "preserve")

    def test_invalidate_shared_database_removes_only_versioned_shared_db(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            cache_home = Path(temporary)
            shared_current = shared_cache_dir(
                trivy_version="v0.74.0", cache_home=cache_home
            )
            shared_db = shared_current / "db"
            shared_db.mkdir(parents=True)
            (shared_db / "trivy.db").write_bytes(b"shared")
            (shared_db / "metadata.json").write_text("{}", encoding="utf-8")
            repository_db = cache_dir(
                repository="optimizr-tech/optimizr-serve",
                trivy_version="v0.74.0",
                cache_home=cache_home,
            ) / "db"
            repository_db.mkdir(parents=True)
            (repository_db / "trivy.db").write_bytes(b"repository")

            invalidate_shared_database(shared_current=shared_current)

            self.assertTrue(shared_db.is_dir())
            self.assertEqual(list(shared_db.iterdir()), [])
            self.assertEqual((repository_db / "trivy.db").read_bytes(), b"repository")

    @unittest.skipIf(fcntl is None, "shared runner cache locking uses flock")
    def test_shared_retention_keeps_a_version_used_by_an_active_scan(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            cache_home = Path(temporary)
            shared_root = shared_cache_root(cache_home=cache_home)
            active_version = shared_cache_dir(
                trivy_version="v0.69.0", cache_home=cache_home
            )
            (active_version / "db").mkdir(parents=True)
            (active_version / "db" / "trivy.db").write_bytes(b"active")
            lock_path = active_version.with_name(f"{active_version.name}.db.lock")
            with lock_path.open("a+b") as lock_file:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_SH)
                current = shared_cache_dir(
                    trivy_version="v0.74.0", cache_home=cache_home
                )
                now = 1_700_000_000
                old_timestamp = now - 30 * 24 * 60 * 60
                os.utime(active_version, (old_timestamp, old_timestamp))
                prepare(
                    root=cache_root(
                        repository="optimizr-tech/optimizr-serve",
                        cache_home=cache_home,
                    ),
                    current=cache_dir(
                        repository="optimizr-tech/optimizr-serve",
                        trivy_version="v0.74.0",
                        cache_home=cache_home,
                        cache_scope="shared",
                    ),
                    retention_days=14,
                    now=now,
                    shared_root=shared_root,
                    shared_current=current,
                )
                self.assertTrue(active_version.exists())

    def test_shared_cache_cli_commands_do_not_require_repository_argument(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with patch.dict(os.environ, {"XDG_CACHE_HOME": temporary}):
                for arguments, expected in (
                    (["cache.py", "shared-root"], str(shared_cache_root(cache_home=Path(temporary)))),
                    (["cache.py", "shared-path", "--trivy-version", "v0.74.0"], str(shared_cache_dir(trivy_version="v0.74.0", cache_home=Path(temporary)))),
                ):
                    output = StringIO()
                    with patch.object(sys, "argv", arguments), redirect_stdout(output):
                        self.assertEqual(cache_module.main(), 0)
                    self.assertEqual(output.getvalue().strip(), expected)

    def test_shared_scope_rejects_unknown_values(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(CacheError):
                lock_root(
                    repository="optimizr-tech/optimizr-serve",
                    cache_home=Path(temporary),
                    cache_scope="global",
                )


if __name__ == "__main__":
    unittest.main()
