"""Public repository boundary regression tests."""

from __future__ import annotations

from pathlib import Path
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]


class PublicRepositoryPolicyTests(unittest.TestCase):
    def test_public_contract_documents_exist_and_bytecode_is_not_tracked(self) -> None:
        self.assertTrue((ROOT / "README.md").is_file())
        self.assertTrue((ROOT / "SECURITY.md").is_file())
        self.assertTrue((ROOT / "docs" / "TESTING.md").is_file())
        tracked_bytecode = subprocess.run(
            ["git", "ls-files", "*.pyc"],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        self.assertEqual("", tracked_bytecode)

    def test_ignore_rules_cover_generated_python_files_and_local_worktrees(self) -> None:
        gitignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
        self.assertIn("__pycache__/", gitignore)
        self.assertIn("*.py[cod]", gitignore)
        self.assertIn(".worktrees/", gitignore)


if __name__ == "__main__":
    unittest.main()
