from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from release_badge.resolver import BadgeError, resolve_version, validate_inputs


class BadgeRecoveryTests(unittest.TestCase):
    def test_rejects_invalid_semver_branch_and_path(self):
        with self.assertRaises(BadgeError):
            resolve_version("v1.2; rm -rf /", "", Path.cwd())
        with self.assertRaises(BadgeError):
            validate_inputs("main && id", "assets/badges/release.svg")
        with self.assertRaises(BadgeError):
            validate_inputs("main", "../release.svg")

    def test_resolves_explicit_or_latest_valid_semver_tag(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
            subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, check=True)
            subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=repo, check=True)
            (repo / "README.md").write_text("x")
            subprocess.run(["git", "add", "README.md"], cwd=repo, check=True)
            subprocess.run(["git", "commit", "-qm", "init"], cwd=repo, check=True)
            for tag in ("v1.2.3", "not-semver", "v2.0.0-rc.1", "v1.10.0"):
                subprocess.run(["git", "tag", tag], cwd=repo, check=True)
            self.assertEqual(resolve_version("v3.4.5", "", repo), "v3.4.5")
            self.assertEqual(resolve_version("", "v4.0.0", repo), "v4.0.0")
            self.assertEqual(resolve_version("", "", repo), "v2.0.0-rc.1")


if __name__ == "__main__":
    unittest.main()
