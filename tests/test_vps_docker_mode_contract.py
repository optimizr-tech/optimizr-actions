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
            docker_cmd_match = re.search(
                r"(?ms)^[ \t]*docker_cmd\(\) \{.*?^[ \t]*\}",
                content,
            )
            self.assertIsNotNone(docker_cmd_match)
            content_without_docker_cmd = (
                content[: docker_cmd_match.start()]
                + content[docker_cmd_match.end() :]
            )
            self.assertNotRegex(
                content_without_docker_cmd,
                r"(?m)^[ \t]*(?:(?:command|sudo)[ \t]+)*docker(?:[ \t]+compose)?[ \t]+",
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
                self.assertIn("direct)", body)
                self.assertIn('command docker "$@"', body)
                self.assertIn("sudo|auto)", body)
                self.assertIn('command sudo docker "$@"', body)

    def test_registry_config_is_forwarded_to_direct_and_sudo_docker(self) -> None:
        for workflow in WORKFLOWS:
            content = workflow.read_text(encoding="utf-8")
            with self.subTest(workflow=workflow.name):
                self.assertIn('env "DOCKER_CONFIG=$DOCKER_CONFIG" docker "$@"', content)
                self.assertIn(
                    'sudo docker --config "$DOCKER_CONFIG" "$@"',
                    content,
                )
                self.assertNotIn(
                    'sudo env "DOCKER_CONFIG=$DOCKER_CONFIG" docker "$@"',
                    content,
                )

    def test_registry_credentials_do_not_leak_to_filesystem_security_scan(self) -> None:
        content = WORKFLOWS[0].read_text(encoding="utf-8")
        self.assertNotIn(
            'echo "DOCKER_CONFIG=$DOCKER_CONFIG_DIR" >> "$GITHUB_ENV"',
            content,
        )

        prepare_start = content.index("- name: Prepare immutable registry images")
        filesystem_start = content.index("- name: Security gate (filesystem)")
        pull_start = content.index("- name: Pull declared runtime images")
        discover_start = content.index("- name: Discover declarative Compose images")
        filesystem_end = content.index("\n      - name:", filesystem_start)
        filesystem_step = content[filesystem_start:filesystem_end]
        pull_step = content[pull_start:discover_start]

        self.assertLess(prepare_start, filesystem_start)
        self.assertLess(filesystem_start, pull_start)
        self.assertNotIn("DOCKER_CONFIG", filesystem_step)
        self.assertIn(
            "DOCKER_CONFIG_DIR: ${{ runner.temp }}/optimizr-ghcr-docker-config",
            pull_step,
        )
        self.assertIn("REGISTRY_AUTH_MODE: ${{ inputs.registry_auth_mode }}", pull_step)
        self.assertIn(
            'if [ "$DEPLOYMENT_MODE" = prebuilt-images ] && [ "$REGISTRY_AUTH_MODE" != anonymous ]; then',
            pull_step,
        )
        self.assertIn('export DOCKER_CONFIG="$DOCKER_CONFIG_DIR"', pull_step)

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
