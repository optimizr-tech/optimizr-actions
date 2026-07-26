"""Unit tests for VPS deployment secret handling."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = (
    ROOT / ".github/workflows/_vps-self-hosted-deploy.yml",
    ROOT / ".github/workflows/_vps-monorepo-deploy.yml",
)


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

            paths_to_chown_recursively = [
                path for path in deploy_path.iterdir() if path.name != ".secrets"
            ]

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

    def test_workflows_run_find_unprivileged_and_chown_only_selected_paths(self) -> None:
        for workflow in WORKFLOWS:
            with self.subTest(workflow=workflow.name):
                content = workflow.read_text(encoding="utf-8")
                self.assertNotIn('sudo find "$DEPLOY_PATH"', content)
                self.assertIn("while IFS= read -r -d '' path; do", content)
                self.assertIn(
                    'sudo chown -R "$(id -un):$(id -gn)" "$path"', content
                )
                self.assertIn("-not -name '.secrets' -print0", content)

    def test_configuration_backups_exclude_runtime_secret_directories(self) -> None:
        required_exclusions = (
            "--exclude='.secrets'",
            "--exclude='*/.secrets'",
            "--exclude='.secrets/*'",
            "--exclude='*/.secrets/*'",
        )
        for workflow in WORKFLOWS:
            with self.subTest(workflow=workflow.name):
                content = workflow.read_text(encoding="utf-8")
                for exclusion in required_exclusions:
                    self.assertIn(exclusion, content)


if __name__ == "__main__":
    unittest.main()
