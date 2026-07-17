"""Regression checks for secret-safe deployment snapshots."""

from __future__ import annotations

from pathlib import Path
import unittest


REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = (
    REPO_ROOT / ".github/workflows/_vps-self-hosted-deploy.yml",
    REPO_ROOT / ".github/workflows/_vps-monorepo-deploy.yml",
)


class DeploySnapshotHardeningTests(unittest.TestCase):
    def test_snapshots_exclude_secret_files_and_use_private_modes(self) -> None:
        for workflow in WORKFLOWS:
            content = workflow.read_text(encoding="utf-8")
            with self.subTest(workflow=workflow.name):
                self.assertIn('sudo chmod 750 "$BACKUP_ROOT"', content)
                self.assertIn("umask 077", content)
                self.assertIn("--exclude='.env'", content)
                self.assertIn("--exclude='.env.*'", content)
                self.assertIn("--exclude='*.pem'", content)
                self.assertIn("--exclude='*.key'", content)
                self.assertIn("--exclude='*.p12'", content)
                self.assertIn("--exclude='*.pfx'", content)
                self.assertIn("chmod 600", content)
                self.assertIn("Secret-free", content)


if __name__ == "__main__":
    unittest.main()
