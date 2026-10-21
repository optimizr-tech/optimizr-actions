import os
import re
import textwrap
import unittest
from pathlib import Path
from urllib.parse import urlsplit
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "move-v1.yml"
RUNBOOK = ROOT / "docs" / "V1_MOVE_RECOVERY.md"


class MoveV1RecoveryContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.workflow = WORKFLOW.read_text(encoding="utf-8")
        self.runbook = RUNBOOK.read_text(encoding="utf-8")

    def _trusted_main_guard(self):
        marker = self.workflow.index("name: Validate trusted main event")
        heredoc = "python3 - <<'PY'\n"
        start = self.workflow.index(heredoc, marker) + len(heredoc)
        end = self.workflow.index("\n          PY", start)
        script = textwrap.dedent(self.workflow[start:end])
        return compile(script, "move-v1-trusted-main-guard", "exec")

    def _run_guard(self, *, event, mode, confirmed, evidence, ref="refs/heads/main"):
        env = {
            "EVENT_NAME": event,
            "EVENT_REF": ref,
            "PR_MERGED": "",
            "PR_BASE_REF": "",
            "RUNNER_MODE": mode,
            "CONFIRM_OWNER_OFFLINE": confirmed,
            "OUTAGE_EVIDENCE_URL": evidence,
        }
        with patch.dict(os.environ, env, clear=True):
            exec(self._trusted_main_guard(), {"os": os, "re": re, "urlsplit": urlsplit})

    def test_dispatch_defaults_to_local_and_requires_manual_recovery_inputs(self):
        dispatch = self.workflow.split("  workflow_dispatch:\n", 1)[1].split(
            "\n\npermissions:", 1
        )[0]
        self.assertIn("type: choice", dispatch)
        self.assertIn("- local-docker", dispatch)
        self.assertIn("- github-hosted-recovery", dispatch)
        self.assertIn("default: local-docker", dispatch)
        self.assertIn("confirm_local_docker_owner_offline:", dispatch)
        self.assertIn("default: false", dispatch)
        self.assertIn("outage_evidence_url:", dispatch)

    def test_only_manual_recovery_routes_all_three_jobs_to_hosted(self):
        self.assertIn(
            "github.event_name == 'workflow_dispatch' && "
            "github.event.inputs.runner_mode == 'github-hosted-recovery' && "
            "'ubuntu-latest'",
            self.workflow,
        )
        self.assertEqual(
            self.workflow.count(
                "needs.scope.outputs.runner_mode == 'github-hosted-recovery' "
                "&& 'ubuntu-latest'"
            ),
            2,
        )
        self.assertEqual(
            self.workflow.count("fromJSON('[\"self-hosted\",\"Linux\",\"local-docker\"]')"),
            3,
        )
        self.assertIn("runner_mode: ${{ steps.scope.outputs.runner_mode }}", self.workflow)
        self.assertIn('echo "runner_mode=$runner_mode"', self.workflow)
        self.assertIn(
            "RUNNER_MODE: ${{ github.event.inputs.runner_mode || 'local-docker' }}",
            self.workflow,
        )

    def test_guard_accepts_confirmed_infraops_queue_watch_evidence(self):
        self._run_guard(
            event="workflow_dispatch",
            mode="github-hosted-recovery",
            confirmed="true",
            evidence="https://github.com/optimizr-tech/optimizr-infra-ops/actions/runs/123",
        )

    def test_guard_accepts_confirmed_org_runner_inventory_evidence(self):
        self._run_guard(
            event="workflow_dispatch",
            mode="github-hosted-recovery",
            confirmed="true",
            evidence="https://github.com/organizations/optimizr-tech/settings/actions/runners",
        )

    def test_guard_rejects_recovery_without_confirmation_or_valid_evidence(self):
        invalid_cases = (
            ("false", "https://github.com/optimizr-tech/optimizr-infra-ops/actions/runs/123"),
            ("true", "https://example.com/optimizr-tech/optimizr-infra-ops/actions/runs/123"),
            ("true", "https://github.com/optimizr-tech/optimizr-actions/actions/runs/123"),
            ("true", "https://github.com/optimizr-tech/optimizr-infra-ops/actions/runs/123?view=1"),
        )
        for confirmed, evidence in invalid_cases:
            with self.subTest(confirmed=confirmed, evidence=evidence):
                with self.assertRaises(SystemExit):
                    self._run_guard(
                        event="workflow_dispatch",
                        mode="github-hosted-recovery",
                        confirmed=confirmed,
                        evidence=evidence,
                    )

    def test_guard_rejects_automatic_hosted_fallback_and_misleading_inputs(self):
        with self.assertRaises(SystemExit):
            self._run_guard(
                event="push",
                mode="github-hosted-recovery",
                confirmed="true",
                evidence="https://github.com/optimizr-tech/optimizr-infra-ops/actions/runs/123",
            )
        with self.assertRaises(SystemExit):
            self._run_guard(
                event="workflow_dispatch",
                mode="local-docker",
                confirmed="true",
                evidence="",
            )

    def test_release_permissions_and_exact_main_sha_gate_are_unchanged(self):
        move_job = self.workflow.split("  move-v1:\n", 1)[1]
        self.assertIn("permissions:\n      contents: write", move_job)
        self.assertEqual(self.workflow.count("secrets.GITHUB_TOKEN"), 2)
        self.assertIn('if [ "$current_main_sha" != "$TARGET_SHA" ]; then', move_job)
        self.assertIn("needs: [scope, validate]", move_job)

    def test_runbook_keeps_manual_fallback_and_cost_scope_explicit(self):
        self.assertIn("manual `workflow_dispatch`", self.runbook)
        self.assertIn("automatic fallback", self.runbook)
        self.assertIn("vps-org-release", self.runbook)
        self.assertIn("container-build", self.runbook)
        self.assertIn("$0.12", self.runbook)
        self.assertIn("does not fetch or verify", self.runbook)


if __name__ == "__main__":
    unittest.main()
