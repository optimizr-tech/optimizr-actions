"""Contract tests for the reusable VPS Docker access mode."""

from __future__ import annotations

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = (
    ROOT / ".github/workflows/_vps-self-hosted-deploy.yml",
    ROOT / ".github/workflows/_vps-monorepo-deploy.yml",
)


class VpsDockerModeContractTests(unittest.TestCase):
    def test_workflows_define_legacy_sudo_default_and_direct_mode(self) -> None:
        for workflow in WORKFLOWS:
            content = workflow.read_text(encoding="utf-8")
            self.assertRegex(
                content,
                r"docker_mode:\n\s+description:.*\n\s+required: false\n\s+type: string\n\s+default: sudo",
            )
            self.assertIn("direct", content)

    def test_docker_steps_dispatch_through_mode_aware_function(self) -> None:
        for workflow in WORKFLOWS:
            content = workflow.read_text(encoding="utf-8")
            self.assertEqual(content.count("docker_cmd() {"), 1)
            self.assertNotRegex(
                content,
                r"(?m)^\s*(?:sudo\s+)?docker(?:\s+compose)?\s+",
            )
            self.assertIn("DOCKER_MODE: ${{ inputs.docker_mode }}", content)

    def test_direct_mode_never_invokes_sudo(self) -> None:
        for workflow in WORKFLOWS:
            content = workflow.read_text(encoding="utf-8")
            helper_blocks = re.findall(
                r"docker_cmd\(\) \{(?P<body>.*?^\s*\})",
                content,
                flags=re.MULTILINE | re.DOTALL,
            )
            self.assertTrue(helper_blocks)
            for body in helper_blocks:
                self.assertIn('direct) command docker "$@" ;;', body)
                self.assertIn('sudo|auto) command sudo docker "$@" ;;', body)

    def test_docker_access_mode_is_configured_before_networks_and_volumes(self) -> None:
        for workflow in WORKFLOWS:
            content = workflow.read_text(encoding="utf-8")
            configure_index = content.index("- name: Configure Docker access mode")
            ensure_index = content.index("- name: Ensure networks and verify volumes")
            self.assertLess(
                configure_index,
                ensure_index,
                f"{workflow.name} must configure docker_cmd before ensuring networks or volumes",
            )


if __name__ == "__main__":
    unittest.main()
