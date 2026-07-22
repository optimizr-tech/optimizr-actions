from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
REUSABLE = ROOT / ".github" / "workflows" / "_dependabot-security-automerge.yml"
TEMPLATE = ROOT / "templates" / "workflows" / "dependabot-security-automerge.yml"


class DependabotAutomergeContractTests(unittest.TestCase):
    def test_reusable_enables_only_native_patch_or_opted_in_minor_automerge(self) -> None:
        content = REUSABLE.read_text(encoding="utf-8")

        self.assertIn("github.event.pull_request.user.login == 'dependabot[bot]'", content)
        self.assertIn(
            "dependabot/fetch-metadata@d7267f607e9d3fb96fc2fbe83e0af444713e90b7",
            content,
        )
        self.assertIn("version-update:semver-patch", content)
        self.assertIn("version-update:semver-minor", content)
        self.assertIn("inputs.allow_minor", content)
        self.assertIn('gh pr merge --auto --squash "$PR_URL"', content)
        self.assertNotIn("gh pr review --approve", content)
        self.assertNotIn("actions/checkout", content)
        self.assertNotIn("secrets: inherit", content)
        self.assertNotIn("self-hosted", content)

    def test_consumer_template_uses_base_context_without_pr_code(self) -> None:
        content = TEMPLATE.read_text(encoding="utf-8")

        self.assertIn("pull_request_target:", content)
        self.assertIn("types: [opened, synchronize, reopened]", content)
        self.assertIn(
            "optimizr-tech/optimizr-actions/.github/workflows/"
            "_dependabot-security-automerge.yml@v1",
            content,
        )
        self.assertNotIn("actions/checkout", content)
        self.assertNotIn("secrets: inherit", content)


if __name__ == "__main__":
    unittest.main()
