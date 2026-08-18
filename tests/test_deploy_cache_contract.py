from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


class DeployCacheContractTests(unittest.TestCase):
    def test_self_hosted_normal_build_uses_cache_by_default(self) -> None:
        content = read(".github/workflows/_vps-self-hosted-deploy.yml")

        build_input = content[content.index("      build_no_cache:") :]
        self.assertIn("default: false", build_input.split("health_timeout:", 1)[0])
        self.assertIn('if [ "${{ inputs.build_no_cache }}" = true ]; then', content)
        self.assertIn("compose_cmd build", content)

    def test_monorepo_service_build_uses_cache_by_default(self) -> None:
        content = read(".github/workflows/_vps-monorepo-deploy.yml")

        services_input = content[content.index("      services_build:") :]
        block = services_input.split("services_up:", 1)[0]
        self.assertIn("services_build_no_cache:", block)
        self.assertIn("default: false", block)
        self.assertIn('if [ "${{ inputs.services_build_no_cache }}" = true ]; then', content)

    def test_security_retry_keeps_explicit_no_cache_contract(self) -> None:
        for path in (
            ".github/workflows/_vps-self-hosted-deploy.yml",
            ".github/workflows/_vps-monorepo-deploy.yml",
        ):
            with self.subTest(workflow=path):
                content = read(path)
                self.assertIn("security_rebuild_retry_no_cache:", content)
                self.assertIn("no_cache: ${{ inputs.security_rebuild_retry_no_cache }}", content)

    def test_pre_deploy_does_not_require_consumer_specific_sudo_lease_refresh(self) -> None:
        content = read(".github/workflows/_vps-monorepo-deploy.yml")
        step = content[content.index("      - name: Pre-deploy commands") : content.index(
            "      - name: Build required services"
        )]

        self.assertIn("${{ inputs.pre_deploy_commands }}", step)
        self.assertNotIn("PRE_DEPLOY_COMMANDS:", step)
        self.assertNotIn("sudo -n -v", step)
        self.assertNotIn("sudo_refresh_pid", step)
        self.assertNotIn("pre_deploy_pid", step)
        self.assertNotIn('eval "$PRE_DEPLOY_COMMANDS"', step)


if __name__ == "__main__":
    unittest.main()
