from __future__ import annotations

import os
from pathlib import Path
import re
import subprocess
import sys
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/_ci-status-gate.yml"
WORKFLOW_DATA = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
JOB = WORKFLOW_DATA["jobs"]["ci-status-gate"]
RUN_SCRIPT = JOB["steps"][0]["run"]
PYTHON_SCRIPT = re.search(
    r"python3 - <<'PY'\n(?P<script>.*?)\nPY\s*$",
    RUN_SCRIPT,
    re.DOTALL,
).group("script")


class CIStatusGateWorkflowTests(unittest.TestCase):
    def run_gate(
        self,
        *,
        event: str,
        test_result: str = "success",
        metadata_result: str = "success",
        head_commit_message: str = "",
        runner_json: str = '["self-hosted","Linux","local-docker"]',
    ) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env.update(
            {
                "RUNNER_JSON": runner_json,
                "TEST_RESULT": test_result,
                "METADATA_RESULT": metadata_result,
                "EVENT_NAME": event,
                "HEAD_COMMIT_MESSAGE": head_commit_message,
            }
        )
        return subprocess.run(
            [sys.executable, "-c", PYTHON_SCRIPT],
            check=False,
            capture_output=True,
            text=True,
            env=env,
        )

    def test_status_gate_is_a_trusted_minimal_reusable_workflow(self) -> None:
        workflow_text = WORKFLOW.read_text(encoding="utf-8")
        workflow_call = WORKFLOW_DATA.get("on", WORKFLOW_DATA.get(True, {}))["workflow_call"]
        self.assertTrue(workflow_call["inputs"]["runner_json"]["required"])
        self.assertEqual({}, WORKFLOW_DATA["permissions"])
        self.assertIn("fromJSON(inputs.runner_json)", JOB["runs-on"])
        self.assertNotIn("uses:", workflow_text)
        for forbidden in (
            "actions/checkout",
            "secrets:",
            "GITHUB_TOKEN",
            "github.token",
            "docker ",
            "npm ",
            "pip ",
            "pull-requests: write",
        ):
            self.assertNotIn(forbidden, workflow_text)

    def test_pull_request_accepts_metadata_and_optional_candidate_suite_only(self) -> None:
        optional = self.run_gate(
            event="pull_request",
            test_result="skipped",
            metadata_result="success",
        )
        self.assertEqual(0, optional.returncode, optional.stderr)
        self.assertIn("not evidence that candidate code was tested", optional.stdout)

        failed_metadata = self.run_gate(
            event="pull_request",
            test_result="skipped",
            metadata_result="failure",
        )
        self.assertNotEqual(0, failed_metadata.returncode)

        failed_tests = self.run_gate(
            event="pull_request",
            test_result="failure",
            metadata_result="success",
        )
        self.assertNotEqual(0, failed_tests.returncode)

    def test_trusted_main_skip_marker_is_push_only(self) -> None:
        skipped_push = self.run_gate(
            event="push",
            test_result="skipped",
            metadata_result="skipped",
            head_commit_message=":memo: docs: update [skip-tests]",
        )
        self.assertEqual(0, skipped_push.returncode, skipped_push.stderr)

        skipped_dispatch = self.run_gate(
            event="workflow_dispatch",
            test_result="skipped",
            metadata_result="skipped",
            head_commit_message="[skip-tests]",
        )
        self.assertNotEqual(0, skipped_dispatch.returncode)

        skipped_push_without_marker = self.run_gate(
            event="push",
            test_result="skipped",
            metadata_result="skipped",
        )
        self.assertNotEqual(0, skipped_push_without_marker.returncode)

    def test_invalid_inputs_and_unknown_events_fail_closed(self) -> None:
        self.assertNotEqual(
            0,
            self.run_gate(event="pull_request", runner_json="[]").returncode,
        )
        self.assertNotEqual(
            0,
            self.run_gate(event="pull_request", test_result="queued").returncode,
        )
        self.assertNotEqual(
            0,
            self.run_gate(event="workflow_run").returncode,
        )


if __name__ == "__main__":
    unittest.main()
