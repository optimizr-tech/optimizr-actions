from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from scripts.security_gate.cache import CacheError, cache_dir, cache_root, prepare


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

            self.assertNotEqual(serve, actions)
            self.assertNotEqual(serve, next_version)
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


if __name__ == "__main__":
    unittest.main()
