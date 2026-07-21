"""Static contracts for the repository-owned local validation action."""

from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
ACTION = ROOT / ".github" / "actions" / "local-validation" / "action.yml"
PRESET = ROOT / "presets" / "fiscal.json"


class LocalValidationActionTests(unittest.TestCase):
    def test_action_uses_preset_owned_entrypoint_runner(self) -> None:
        content = ACTION.read_text(encoding="utf-8")
        self.assertIn("scripts/local_validation/run.py", content)
        self.assertIn('--workspace "$GITHUB_WORKSPACE"', content)
        self.assertIn('--command-args-json "$INPUT_COMMAND_ARGS_JSON"', content)
        self.assertNotIn("command_json:", content)
        self.assertNotIn("services:", content)
        self.assertNotIn("bash -c", content)
        self.assertNotIn("eval ", content)

    def test_action_inputs_cannot_carry_service_or_secret_metadata(self) -> None:
        content = ACTION.read_text(encoding="utf-8").lower()
        for prohibited in (
            "password:",
            "secret:",
            "token:",
            "services:",
            "service_versions:",
            "command_json:",
        ):
            self.assertNotIn(f"  {prohibited}", content)

    def test_fiscal_preset_binds_real_services_and_conformance(self) -> None:
        content = PRESET.read_text(encoding="utf-8")
        for required in (
            '"python": "3.14"',
            '"postgres"',
            '"rabbitmq"',
            '"minio"',
            '"keycloak"',
            '"redis"',
            '"minio-object-lock"',
            '"rls-fail-closed"',
            '"real-service-integration"',
            '"migration-rls"',
        ):
            self.assertIn(required, content)


if __name__ == "__main__":
    unittest.main()
