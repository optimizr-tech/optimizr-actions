"""Policy tests for the repository pull-request validation workflow."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "validate-pr.yml"
METADATA_WORKFLOW = ROOT / ".github" / "workflows" / "_pr-metadata.yml"


class PullRequestValidationWorkflowTests(unittest.TestCase):
    @staticmethod
    def runner_contract_script() -> str:
        workflow = yaml.safe_load(METADATA_WORKFLOW.read_text(encoding="utf-8"))
        runner_step = next(
            step
            for step in workflow["jobs"]["metadata"]["steps"]
            if step["name"] == "Validate metadata runner trust contract"
        )
        run_script = runner_step["run"]
        marker = "python3 - <<'PY'\n"
        return run_script.split(marker, 1)[1].rsplit("\nPY", 1)[0]

    def run_runner_contract(
        self, event_name: str, mode: str, labels: list[str]
    ) -> subprocess.CompletedProcess[str]:
        environment = {
            "RUNNER_JSON": json.dumps(labels),
            "SELF_HOSTED_MODE": mode,
            "EVENT_NAME": event_name,
        }
        return subprocess.run(
            [sys.executable, "-c", self.runner_contract_script()],
            capture_output=True,
            check=False,
            env=environment,
            text=True,
        )

    def test_pr_metadata_validation_uses_authorized_self_hosted_runner_with_read_only_permissions(self) -> None:
        content = WORKFLOW.read_text(encoding="utf-8")

        self.assertIn("  pull_request_target:", content)
        self.assertNotIn("  pull_request:", content)
        self.assertIn(
            "    types: [opened, edited, synchronize, reopened]",
            content,
        )
        self.assertIn(
            'runner_json: \'["self-hosted","Linux","local-docker"]\'', content
        )
        self.assertIn("self_hosted_mode: metadata-pr", content)
        self.assertIn("permissions:\n  contents: read", content)
        self.assertIn("pull-requests: read", content)
        self.assertNotIn("contents: write", content)

    def test_persistent_metadata_contract_accepts_pull_request_events_only(self) -> None:
        persistent = ["self-hosted", "Linux", "local-docker"]
        for event_name in ("pull_request", "pull_request_target"):
            with self.subTest(event_name=event_name):
                accepted = self.run_runner_contract(
                    event_name, "metadata-pr", persistent
                )
                self.assertEqual(0, accepted.returncode, accepted.stderr)

        for event_name in ("push", "workflow_dispatch"):
            with self.subTest(event_name=event_name):
                rejected = self.run_runner_contract(
                    event_name, "metadata-pr", persistent
                )
                self.assertNotEqual(0, rejected.returncode)
                self.assertIn(
                    "metadata-pr requires a pull_request or pull_request_target event",
                    rejected.stderr,
                )

    def test_ephemeral_metadata_contract_accepts_pull_request_only(self) -> None:
        ephemeral = ["self-hosted", "Linux", "local-docker", "ephemeral"]
        accepted = self.run_runner_contract("pull_request", "ephemeral-pr", ephemeral)
        self.assertEqual(0, accepted.returncode, accepted.stderr)

        for event_name, labels in (
            ("pull_request_target", ephemeral),
            ("push", ephemeral),
            ("pull_request", ["self-hosted", "Linux", "local-docker"]),
        ):
            with self.subTest(event_name=event_name, labels=labels):
                rejected = self.run_runner_contract(
                    event_name, "ephemeral-pr", labels
                )
                self.assertNotEqual(0, rejected.returncode)

    def test_metadata_job_never_checks_out_or_executes_candidate_code(self) -> None:
        content = WORKFLOW.read_text(encoding="utf-8")
        metadata_job = content.split("  validate:\n", 1)[1].split(
            "  validate-candidate:\n", 1
        )[0]
        self.assertIn(
            "uses: optimizr-tech/optimizr-actions/.github/workflows/_pr-metadata.yml@v1",
            metadata_job,
        )
        self.assertNotIn("uses: ./.github/workflows/_pr-metadata.yml", metadata_job)
        for forbidden in (
            "actions/checkout", "steps:", "run:", "docker ",
            "python3 -m unittest", "secrets:", "workflow_dispatch:",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, metadata_job)
        for field in ("pr_number", "pr_title", "pr_body", "base_sha", "head_sha"):
            with self.subTest(field=field):
                self.assertIn(f"      {field}:", metadata_job)

    def test_candidate_code_is_not_run_by_the_pull_request_workflow(self) -> None:
        content = WORKFLOW.read_text(encoding="utf-8")
        jobs = content.split("jobs:\n", 1)[1]
        job_names = [
            line.strip()[:-1]
            for line in jobs.splitlines()
            if line.startswith("  ") and not line.startswith("    ") and line.rstrip().endswith(":")
        ]
        self.assertEqual(["validate"], job_names)
        self.assertNotIn("validate-candidate:", content)
        self.assertNotIn("runs-on:", content)
        self.assertNotIn("actions/checkout", content)
        self.assertNotIn("python3 -m unittest discover -v", content)
        self.assertNotIn("secrets:", content)

        move_v1 = (ROOT / ".github/workflows/move-v1.yml").read_text(encoding="utf-8")
        scope_job = move_v1.split("  scope:\n", 1)[1].split("  validate:\n", 1)[0]
        validate_job = move_v1.split("  validate:\n", 1)[1].split("  move-v1:\n", 1)[0]
        self.assertIn("|| 'local-docker'", scope_job)
        self.assertIn("python3 -m unittest discover -v", validate_job)
        self.assertIn("needs: [scope, validate]", move_v1)


if __name__ == "__main__":
    unittest.main()
