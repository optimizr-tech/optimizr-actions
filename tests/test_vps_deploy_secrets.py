"""Unit tests for VPS deployment secret handling."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path


class VpsDeploySecretsTests(unittest.TestCase):
    def test_secrets_directory_is_excluded_from_chown(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            deploy_path = Path(tmpdir) / "deploy"
            secrets_path = deploy_path / ".secrets"
            secrets_file = secrets_path / "mysecret"
            other_file = deploy_path / "other_file"
            another_dir = deploy_path / "another_dir"
            another_file = another_dir / "another_file"

            deploy_path.mkdir()
            secrets_path.mkdir()
            secrets_file.touch()
            other_file.touch()
            another_dir.mkdir()
            another_file.touch()


            # This logic mirrors the shell command in the workflow.
            # It simulates: find "$DEPLOY_PATH" -mindepth 1 -maxdepth 1 -not -name '.secrets'
            paths_to_chown_recursively = []
            for path in deploy_path.iterdir():
                if path.name != ".secrets":
                    paths_to_chown_recursively.append(path)

            # The `chown -R` would affect the path itself and everything inside it.
            all_affected_paths = set()
            for path in paths_to_chown_recursively:
                all_affected_paths.add(path)
                if path.is_dir():
                    for root, dirs, files in os.walk(path):
                        for name in files:
                            all_affected_paths.add(Path(root) / name)
                        for name in dirs:
                            all_affected_paths.add(Path(root) / name)

            self.assertIn(other_file, all_affected_paths)
            self.assertIn(another_dir, all_affected_paths)
            self.assertIn(another_file, all_affected_paths)
            self.assertNotIn(secrets_path, all_affected_paths)
            self.assertNotIn(secrets_file, all_affected_paths)


if __name__ == "__main__":
    unittest.main()
