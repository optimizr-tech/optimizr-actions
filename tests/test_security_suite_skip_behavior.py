from pathlib import Path
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[1]


def summary_script() -> str:
    text = (ROOT / ".github/workflows/_security-suite.yml").read_text()
    summary = text.split("- name: Write sanitized suite result", 1)[1]
    return textwrap.dedent(
        summary.split("python3 - <<'PY'", 1)[1].split("\n          PY", 1)[0]
    )


class SecuritySuiteSkipBehaviorTests(unittest.TestCase):
    def run_summary(self, **overrides: str) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env.update(
            PROFILE="python",
            IMAGE_REFS="",
            PROFILE_RESULT="success",
            STATIC_RESULT="success",
            FILESYSTEM_RESULT="success",
            DEPENDENCY_RESULT="success",
            SAST_RESULT="success",
            SUPPLY_CHAIN_RESULT="skipped",
        )
        env.update(overrides)
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "artifacts/security-suite").mkdir(parents=True)
            return subprocess.run(
                [sys.executable, "-c", summary_script()],
                cwd=tmp,
                env=env,
                text=True,
                capture_output=True,
            )

    def test_harness_extracts_summary_block(self):
        script = summary_script()
        self.assertIn("allowed_results", script)
        self.assertNotIn("RUNNER_JSON", script)

    def test_required_python_job_cannot_be_skipped(self):
        result = self.run_summary(DEPENDENCY_RESULT="skipped")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unexpectedly skipped", result.stderr)

    def test_optional_supply_chain_skip_is_allowed_without_images(self):
        result = self.run_summary(
            PROFILE="infra",
            DEPENDENCY_RESULT="skipped",
            SAST_RESULT="skipped",
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_supply_chain_becomes_required_when_images_are_declared(self):
        result = self.run_summary(
            PROFILE="infra",
            IMAGE_REFS="app:local",
            DEPENDENCY_RESULT="skipped",
            SAST_RESULT="skipped",
            SUPPLY_CHAIN_RESULT="skipped",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unexpectedly skipped", result.stderr)


if __name__ == "__main__":
    unittest.main()
