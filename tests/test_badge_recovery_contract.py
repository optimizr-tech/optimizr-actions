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

    def test_v1_defaults_to_local_docker_and_keeps_explicit_override(self):
        workflow = (ROOT / ".github/workflows/_release-badge-recovery.yml").read_text()
        docs = (ROOT / "docs/RELEASE_BADGE_RECOVERY.md").read_text()

        runner_input = workflow.split("      runner_json:\n", 1)[1].split(
            "    outputs:", 1
        )[0]
        self.assertIn(
            "default: '{\"group\":\"local-docker\",\"labels\":[\"self-hosted\",\"Linux\",\"X64\",\"local-docker\"]}'",
            runner_input,
        )
        self.assertIn("runs-on: ${{ fromJSON(inputs.runner_json) }}", workflow)
        self.assertIn("actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1", workflow)
        self.assertIn("release-badge-resolver@v1", workflow)
        self.assertIn("update-release-badge@v1", workflow)
        self.assertNotIn("runner_group", workflow)
        self.assertFalse(
            (ROOT / ".github/workflows/_release-badge-recovery-v2.yml").exists()
        )
        self.assertIn("`local-docker`", docs)
        self.assertIn("Both the group and labels must match", docs)
        self.assertIn("other organization", docs)
        self.assertIn("explicitly passes `runner_json`", docs)
        self.assertNotIn("@v2", docs)


if __name__ == "__main__":
    unittest.main()
