from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class CiSkipContractTests(unittest.TestCase):
    def _read_template(self, name: str) -> str:
        return (ROOT / "templates" / "workflows" / name).read_text(
            encoding="utf-8"
        )

    def test_commitlint_template_guards_the_reusable_at_the_caller(self) -> None:
        content = self._read_template("commitlint.yml")

        self.assertIn("github.event.pull_request.title", content)
        self.assertIn("!contains", content)
        self.assertIn("'[skip-tests]'", content)
        self.assertIn("_commitlint.yml@v1", content)
        self.assertIn("base_sha:", content)
        self.assertIn("head_sha:", content)

    def test_validate_pr_template_guards_the_reusable_at_the_caller(self) -> None:
        content = self._read_template("validate-pr.yml")

        self.assertIn("github.event.pull_request.title", content)
        self.assertIn("!contains", content)
        self.assertIn("'[skip-tests]'", content)
        self.assertIn("_validate-pr.yml@v1", content)
        self.assertIn("pr_title:", content)
        self.assertIn("pr_body:", content)
        self.assertIn("base_sha:", content)
        self.assertIn("head_sha:", content)

    def test_release_reusable_does_not_implement_test_skip_markers(self) -> None:
        release = (ROOT / ".github" / "workflows" / "_semantic-release.yml").read_text(
            encoding="utf-8"
        )

        self.assertNotIn(
            "contains(github.event.head_commit.message, '[skip-tests]')",
            release,
        )


if __name__ == "__main__":
    unittest.main()
