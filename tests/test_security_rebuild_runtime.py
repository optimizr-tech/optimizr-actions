from __future__ import annotations

from pathlib import Path
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
ACTION = ROOT / ".github" / "actions" / "security-rebuild" / "action.yml"


class SecurityRebuildRuntimeTests(unittest.TestCase):
    def test_action_uses_fixed_pull_and_bounded_build_commands(self) -> None:
        payload = yaml.safe_load(ACTION.read_text(encoding="utf-8"))
        script = payload["runs"]["steps"][0]["run"]

        self.assertIn(
            'compose -f "$INPUT_COMPOSE_FILE" pull --ignore-buildable', script
        )
        self.assertIn("build_args=(--pull)", script)
        self.assertIn("build_args+=(--no-cache)", script)
        self.assertNotIn("eval ", script)
        self.assertNotIn("bash -c", script)
        self.assertNotIn("${{ inputs.command", script)

    def test_action_validates_service_names_and_deploy_path(self) -> None:
        payload = yaml.safe_load(ACTION.read_text(encoding="utf-8"))
        script = payload["runs"]["steps"][0]["run"]

        self.assertIn("deploy_path must remain below /opt/optimizr", script)
        self.assertIn("invalid Compose service name", script)
        self.assertIn("retry occurs once", script)


if __name__ == "__main__":
    unittest.main()
