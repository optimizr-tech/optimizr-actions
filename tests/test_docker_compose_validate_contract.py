from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "_docker-compose-validate.yml"


class DockerComposeValidateContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.text = WORKFLOW.read_text(encoding="utf-8")

    def test_workflow_resolves_governed_docker_access_before_checkout(self) -> None:
        self.assertIn("docker_mode:", self.text)
        self.assertIn("default: auto", self.text)
        self.assertIn("Resolve Docker access mode", self.text)
        self.assertIn('docker info >/dev/null 2>&1', self.text)
        self.assertIn('sudo -n docker info >/dev/null 2>&1', self.text)
        self.assertIn("docker_mode must be auto, direct, or sudo", self.text)
        self.assertIn("Docker is unavailable through direct access", self.text)
        self.assertIn('echo "mode=${resolved}" >> "$GITHUB_OUTPUT"', self.text)
        self.assertLess(
            self.text.index("Resolve Docker access mode"),
            self.text.index("- name: Checkout"),
        )

    def test_compose_commands_use_the_resolved_mode(self) -> None:
        self.assertGreaterEqual(
            self.text.count("DOCKER_MODE: ${{ steps.docker.outputs.mode }}"),
            2,
        )
        self.assertGreaterEqual(self.text.count("docker_compose()"), 2)
        self.assertGreaterEqual(
            self.text.count('\n              sudo -n docker compose "$@"'),
            2,
        )
        self.assertGreaterEqual(
            self.text.count('\n              docker compose "$@"'),
            2,
        )
        self.assertNotIn('docker compose -f "$f" config --quiet', self.text)
        self.assertNotIn(
            'docker compose "${args[@]}" config --quiet',
            self.text,
        )

    def test_buildx_requires_direct_docker_access(self) -> None:
        self.assertIn("BUILD_IMAGE: ${{ inputs.build_image }}", self.text)
        self.assertIn("build_image requires direct Docker access", self.text)


if __name__ == "__main__":
    unittest.main()
