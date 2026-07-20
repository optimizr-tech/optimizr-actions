"""Static contract tests for deploy-manifest composite actions."""

from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
WRITER_ACTION = ROOT / ".github" / "actions" / "write-deploy-manifest" / "action.yml"
RECORDER_ACTION = ROOT / ".github" / "actions" / "record-deploy-manifest" / "action.yml"


class DeployManifestActionTests(unittest.TestCase):
    def test_writer_action_is_a_thin_adapter_to_python(self) -> None:
        content = WRITER_ACTION.read_text(encoding="utf-8")
        self.assertIn(
            'python3 "$GITHUB_ACTION_PATH/../../../scripts/deploy_manifest/write.py"',
            content,
        )
        self.assertIn("args=(", content)
        self.assertIn('"${args[@]}"', content)
        self.assertIn('>> "$GITHUB_OUTPUT"', content)
        self.assertNotIn("python - <<", content)
        self.assertNotIn("python3 - <<", content)

    def test_writer_exposes_only_sanitized_metadata_inputs(self) -> None:
        content = WRITER_ACTION.read_text(encoding="utf-8")
        expected_inputs = {
            "deploy_path",
            "status",
            "repository",
            "deployed_sha",
            "deployed_ref",
            "environment",
            "workflow",
            "run_id",
            "services_json",
            "images_json",
            "healthchecks_json",
            "migration_result",
            "optional_build_result",
            "rollback_of",
            "retention",
        }
        actual_inputs: set[str] = set()
        in_inputs = False
        for line in content.splitlines():
            if line == "inputs:":
                in_inputs = True
                continue
            if in_inputs and line and not line.startswith(" "):
                break
            if in_inputs and line.startswith("  ") and not line.startswith("    "):
                actual_inputs.add(line.strip().removesuffix(":"))
        self.assertEqual(expected_inputs, actual_inputs)
        for prohibited in ("password", "secret", "token", "cookie", "authorization", "env_file"):
            self.assertNotIn(f"  {prohibited}:", content.lower())

    def test_recorder_collects_through_one_canonical_python_entrypoint(self) -> None:
        content = RECORDER_ACTION.read_text(encoding="utf-8")
        self.assertIn("scripts/deploy_manifest/record.py", content)
        self.assertNotIn("bash -c", content)
        self.assertNotIn("eval ", content)
        self.assertIn("optional_build_result:", content)
        self.assertIn("migration_result:", content)

    def test_outputs_are_forwarded(self) -> None:
        for action, step in ((WRITER_ACTION, "write"), (RECORDER_ACTION, "record")):
            content = action.read_text(encoding="utf-8")
            self.assertIn("manifest_path:", content)
            self.assertIn(f"value: ${{{{ steps.{step}.outputs.manifest_path }}}}", content)
            self.assertIn("last_successful_path:", content)
            self.assertIn(f"value: ${{{{ steps.{step}.outputs.last_successful_path }}}}", content)


if __name__ == "__main__":
    unittest.main()
