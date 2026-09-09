import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "_testsprite.yml"
VALIDATOR = ROOT / "scripts" / "testsprite" / "validate_target.py"


class TestSpriteWorkflowContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = WORKFLOW.read_text(encoding="utf-8")
        cls.validator = VALIDATOR.read_text(encoding="utf-8")

    def test_reusable_workflow_declares_portable_inputs_and_secret(self) -> None:
        for input_name in (
            "base_url",
            "expected_base_url",
            "environment_name",
            "runner_json",
            "suite_path",
            "forbidden_hosts_json",
        ):
            self.assertIn(f"      {input_name}:", self.workflow)
        self.assertIn("      TESTSPRITE_API_KEY:", self.workflow)
        self.assertIn("workflow_call:", self.workflow)
        self.assertIn("value: ${{ jobs.testsprite.outputs.result }}", self.workflow)

    def test_preflight_is_secret_free_and_fail_closed(self) -> None:
        preflight = self.workflow.split("  preflight:\n", 1)[1].split(
            "  testsprite:\n", 1
        )[0]
        self.assertIn("runs-on: ${{ fromJSON(inputs.runner_json) }}", preflight)
        self.assertNotIn("runs-on: ubuntu-latest", preflight)
        self.assertNotIn("TESTSPRITE_API_KEY", preflight)
        self.assertIn('--event-name "$EVENT_NAME"', self.workflow)
        self.assertIn('--ref "$REF"', self.workflow)
        self.assertIn('event_name not in {"push", "workflow_dispatch"}', self.validator)
        self.assertIn('ref != "refs/heads/main"', self.validator)
        self.assertIn("self-hosted and Linux labels", self.validator)
        self.assertIn("environment_name must not identify production", self.validator)

    def test_execution_uses_exact_revisions_and_blocking_action(self) -> None:
        self.assertEqual(self.workflow.count("actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"), 2)
        self.assertIn("repository: ${{ job.workflow_repository }}", self.workflow)
        self.assertIn("ref: ${{ job.workflow_sha }}", self.workflow)
        self.assertIn(
            "TestSprite/run-action@e1793b89af73cf22d267b025e827fdb94d2c4e7d",
            self.workflow,
        )
        self.assertIn('blocking: "true"', self.workflow)
        self.assertIn("Require a committed generated suite", self.workflow)

    def test_workflow_does_not_depend_on_private_operational_repository(self) -> None:
        self.assertNotIn("optimizr-infra-ops", self.workflow)


if __name__ == "__main__":
    unittest.main()
