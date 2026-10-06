from pathlib import Path
import os
import re
import textwrap
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "move-v1.yml"


class MoveV1CatalogScopeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.workflow = WORKFLOW.read_text(encoding="utf-8")

    def test_catalog_changes_trigger_trusted_main_validation(self) -> None:
        self.assertIn('  push:\n    branches: [main]\n', self.workflow)
        self.assertNotRegex(self.workflow, r'(?m)^  pull_request:')
        self.assertIn('      - "catalog/**"', self.workflow)
        self.assertIn('      - "tests/**"', self.workflow)
        self.assertIn('      - "requirements-ci.txt"', self.workflow)
        self.assertEqual(
            self.workflow.count("runs-on: [self-hosted, Linux, local-docker]"), 3
        )
        self.assertNotIn("runs-on: ubuntu-latest", self.workflow)

    def test_recovery_path_recognizes_catalog_changes(self) -> None:
        self.assertIn(
            r'templates/|presets/|scripts/|catalog/|tests/|requirements-ci\.txt$)',
            self.workflow,
        )

    def test_pull_request_validation_never_moves_v1(self) -> None:
        expected = "if: needs.scope.outputs.publish == 'true' && github.ref == 'refs/heads/main' && github.event_name != 'pull_request'"
        self.assertIn(expected, self.workflow)

    def test_validation_is_a_required_release_gate(self) -> None:
        self.assertIn("needs: [scope, validate]", self.workflow)
        self.assertIn("needs: [scope]", self.workflow)
        self.assertIn("python3 -m unittest discover -v", self.workflow)
        self.assertIn("python3 -m compileall scripts tests", self.workflow)
        self.assertIn("git diff --check", self.workflow)
        self.assertNotIn("continue-on-error: true", self.workflow)
        self.assertNotIn("if: always()", self.workflow)
        self.assertIn('if [ "$current_main_sha" != "$TARGET_SHA" ]', self.workflow)

    def test_contract_dependencies_are_installed_per_job_before_tests(self) -> None:
        self.assertLess(
            self.workflow.index("Prepare job-local contract dependencies"),
            self.workflow.index("Run Python contract tests"),
        )
        self.assertIn('--python 3.14', self.workflow)
        self.assertIn('--requirement requirements-ci.txt', self.workflow)
        self.assertIn('${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}', self.workflow)
        self.assertNotIn("pip install --user", self.workflow)

    def test_trusted_event_guard_runs_before_candidate_resolution(self) -> None:
        self.assertLess(
            self.workflow.index("Validate trusted main event"),
            self.workflow.index("Detect portable-contract changes"),
        )
        self.assertIn("persist-credentials: false", self.workflow)

    def test_trusted_main_event_guard_accepts_only_reviewed_main_paths(self) -> None:
        match = re.search(r"python3 - <<'PY'\n(.*?)\n          PY", self.workflow, re.DOTALL)
        self.assertIsNotNone(match, "trusted-main event guard is required")
        guard = compile(textwrap.dedent(match.group(1)), "trusted-main-guard", "exec")
        cases = (
            ("push", "refs/heads/main", "", "", True),
            ("workflow_dispatch", "refs/heads/main", "", "", True),
            ("pull_request_target", "refs/heads/main", "true", "main", True),
            ("pull_request", "refs/heads/main", "", "main", False),
            ("push", "refs/heads/dev", "", "", False),
            ("workflow_dispatch", "refs/heads/codex/candidate", "", "", False),
            ("pull_request_target", "refs/heads/main", "false", "main", False),
            ("pull_request_target", "refs/heads/main", "true", "dev", False),
            ("schedule", "refs/heads/main", "", "", False),
        )
        for event, ref, merged, base_ref, allowed in cases:
            with self.subTest(event=event, ref=ref, merged=merged, base_ref=base_ref):
                env = {"EVENT_NAME": event, "EVENT_REF": ref,
                       "PR_MERGED": merged, "PR_BASE_REF": base_ref}
                with patch.dict(os.environ, env, clear=True):
                    if allowed:
                        exec(guard, {})
                    else:
                        with self.assertRaises(SystemExit):
                            exec(guard, {})

    def test_container_steps_run_as_the_runner_user(self) -> None:
        # 2026-10-06 (run 37504666776): the self-hosted checkout is mode 0700
        # owned by the runner user; container root cannot read it through the
        # Docker Desktop mount, so both container steps must run as that user.
        self.assertEqual(
            self.workflow.count('--user "$(id -u):$(id -g)"'),
            2,
        )

    def test_catalog_check_runs_before_general_contract_tests(self) -> None:
        catalog_check = "python3 -m scripts.capability_catalog.generate --check"
        unittest_run = "python3 -m unittest discover -v"
        self.assertIn(catalog_check, self.workflow)
        self.assertLess(self.workflow.index(catalog_check), self.workflow.index(unittest_run))


if __name__ == "__main__":
    unittest.main()
