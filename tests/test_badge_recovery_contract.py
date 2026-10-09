from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class BadgeRecoveryContractTests(unittest.TestCase):
    def test_workflow_has_write_only_where_needed_and_serializes_updates(self):
        text = (ROOT / ".github/workflows/_release-badge-recovery.yml").read_text()
        self.assertIn("contents: write", text)
        self.assertIn("cancel-in-progress: false", text)
        self.assertIn("fromJSON(inputs.runner_json)", text)
        self.assertNotIn("secrets: inherit", text)
        self.assertIn("actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1", text)
        self.assertIn("update-release-badge@v1", text)
        self.assertIn("release-badge-resolver@v1", text)
        resolver = (ROOT / ".github/actions/release-badge-resolver/action.yml").read_text()
        self.assertIn("release_badge/resolver.py", resolver)
        self.assertNotIn("git clone", text)

    def test_v1_runner_default_is_preserved_and_v2_requires_group_and_label(self):
        v1 = (ROOT / ".github/workflows/_release-badge-recovery.yml").read_text()
        v2 = (ROOT / ".github/workflows/_release-badge-recovery-v2.yml").read_text()
        docs = (ROOT / "docs/RELEASE_BADGE_RECOVERY.md").read_text()

        self.assertIn(
            "default: '[\"self-hosted\",\"Linux\",\"release\"]'", v1
        )
        self.assertIn(
            """      runner_group:
        description: Authorized runner group for this repository
        required: true
        type: string""",
            v2,
        )
        self.assertIn(
            """      runner_label:
        description: Required runner label within the selected group
        required: true
        type: string""",
            v2,
        )
        runner_group_contract = v2.split("      runner_group:\n", 1)[1].split(
            "      runner_label:", 1
        )[0]
        runner_label_contract = v2.split("      runner_label:\n", 1)[1].split(
            "    outputs:", 1
        )[0]
        self.assertNotIn("default:", runner_group_contract)
        self.assertNotIn("default:", runner_label_contract)
        self.assertIn(
            """    runs-on:
      group: ${{ inputs.runner_group }}
      labels: ${{ inputs.runner_label }}""",
            v2,
        )
        self.assertNotIn("runner_json", v2)
        self.assertIn("permissions:\n  contents: none", v2)
        self.assertIn("    permissions:\n      contents: write", v2)
        self.assertNotIn("secrets: inherit", v2)
        self.assertIn(
            "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1", v2
        )
        self.assertIn("release-badge-resolver@v1", v2)
        self.assertIn("update-release-badge@v1", v2)
        self.assertIn("_release-badge-recovery-v2.yml@v2", docs)
        self.assertIn(
            "Runner-group membership and repository access define the pool boundary",
            docs,
        )


if __name__ == "__main__":
    unittest.main()
