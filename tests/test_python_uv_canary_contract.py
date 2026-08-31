from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/_python-uv-test.yml"
ACTION = ROOT / ".github/actions/python-uv-test-steps/action.yml"
CANARY = ROOT / ".github/workflows/python-uv-test-canary.yml"
FAILURE_CANARY = ROOT / ".github/workflows/python-uv-test-failure-canary.yml"
FIXTURE = ROOT / "tests/fixtures/python-uv-test-canary"


class PythonUvCanaryContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.workflow = WORKFLOW.read_text(encoding="utf-8")
        self.action = ACTION.read_text(encoding="utf-8")

    def test_working_directory_is_additive_and_defaults_to_repository_root(self) -> None:
        self.assertRegex(
            self.workflow,
            r"working_directory:\n\s+description:.*\n\s+required: false\n\s+type: string\n\s+default: \"\.\"",
        )
        self.assertRegex(
            self.action,
            r"working_directory:\n\s+description:.*\n\s+required: false\n\s+default: \"\.\"",
        )
        self.assertGreaterEqual(
            self.workflow.count("working_directory: ${{ inputs.working_directory }}"),
            4,
        )
        self.assertEqual(
            2,
            self.workflow.count(
                "${{ inputs.working_directory }}/.coverage.shard-${{ matrix.shard_index }}"
            ),
        )
        self.assertIn("working-directory: ${{ inputs.working_directory }}", self.action)

    def test_working_directory_validation_rejects_traversal_and_missing_paths(self) -> None:
        self.assertIn('[[ "$WORKING_DIRECTORY" = /* ]]', self.action)
        self.assertIn('[[ "$WORKING_DIRECTORY" == *..* ]]', self.action)
        self.assertIn('if [ ! -d "$WORKING_DIRECTORY" ]', self.action)

    def test_manual_canary_exercises_legacy_sharded_and_fail_closed_paths(self) -> None:
        canary = CANARY.read_text(encoding="utf-8")
        failure_canary = FAILURE_CANARY.read_text(encoding="utf-8")

        self.assertIn("workflow_dispatch:", canary)
        for job_name in ("legacy:", "sharded:", "action-sharded:", "assert-positive:"):
            with self.subTest(job_name=job_name):
                self.assertIn(job_name, canary)
        self.assertEqual(2, canary.count("uses: ./.github/workflows/_python-uv-test.yml"))
        self.assertIn("uses: ./.github/actions/python-uv-test-steps", canary)
        self.assertIn("actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1", canary)
        self.assertIn("shard_count: 2", canary)
        self.assertIn("coverage_artifact_prefix: canary-sharded-coverage", canary)
        self.assertNotIn("secrets: inherit", canary)

        self.assertIn("workflow_dispatch:", failure_canary)
        self.assertIn("failure-path:", failure_canary)
        self.assertIn("assert-failure:", failure_canary)
        self.assertIn("needs.failure-path.result", failure_canary)
        self.assertIn("test \"$FAILURE_RESULT\" = \"failure\"", failure_canary)
        self.assertNotIn("continue-on-error", failure_canary)

    def test_fixture_is_a_reproducible_project_with_a_failure_switch(self) -> None:
        pyproject = FIXTURE / "pyproject.toml"
        lockfile = FIXTURE / "uv.lock"
        conftest = FIXTURE / "tests/conftest.py"
        test_file = FIXTURE / "tests/test_canary.py"

        for path in (pyproject, lockfile, conftest, test_file):
            with self.subTest(path=path):
                self.assertTrue(path.is_file(), f"missing canary fixture file: {path}")

        project = pyproject.read_text(encoding="utf-8")
        self.assertIn('name = "optimizr-actions-python-uv-canary"', project)
        self.assertIn("test = [", project)
        self.assertIn('pytest-cov', project)
        self.assertIn('ruff', project)
        self.assertIn("CANARY_FAILURE_MODE", conftest.read_text(encoding="utf-8"))
        self.assertIn("pytestconfig", test_file.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
