"""Regression checks for the deploy cleanup contract."""

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ACTION = ROOT / ".github/actions/docker-prune-safe/action.yml"
WORKFLOWS = (
    ROOT / ".github/workflows/_vps-self-hosted-deploy.yml",
    ROOT / ".github/workflows/_vps-monorepo-deploy.yml",
)


class DockerPruneContractTests(unittest.TestCase):
    def test_safe_prune_action_is_owned_by_this_public_repository(self) -> None:
        content = ACTION.read_text(encoding="utf-8")

        self.assertIn(
            "optimizr-tech/optimizr-actions/.github/actions/docker-prune-safe",
            content,
        )
        self.assertNotIn("optimizr-tech/optimizr-infra-ops", content)
        self.assertNotIn("PRODUCTION_DEPLOY_HYGIENE.md", content)
        self.assertIn("Disk before cleanup", content)
        self.assertIn("Disk after cleanup", content)
        self.assertNotIn("docker volume prune", content)
        self.assertNotIn("docker network prune", content)

    def test_vps_deploys_delegate_pruning_to_the_canonical_action(self) -> None:
        for workflow in WORKFLOWS:
            content = workflow.read_text(encoding="utf-8")
            with self.subTest(workflow=workflow.name):
                self.assertIn(
                    "uses: optimizr-tech/optimizr-actions/.github/actions/"
                    "docker-prune-safe@v1",
                    content,
                )
                self.assertNotIn("docker container prune", content)
                self.assertNotIn("docker image prune", content)
                self.assertNotIn("docker builder prune", content)

    def test_workspace_cleanup_runs_with_or_without_docker_prune(self) -> None:
        for workflow in WORKFLOWS:
            content = workflow.read_text(encoding="utf-8")
            workspace_step = content.split(
                "      - name: Clean runner workspace", 1
            )[1].split("      - name: Checkout coherent deploy-manifest recorder", 1)[0]
            with self.subTest(workflow=workflow.name):
                self.assertIn("if: always()", workspace_step)
                self.assertNotIn("!inputs.run_prune", workspace_step)
                self.assertIn(
                    'sudo find "$GITHUB_WORKSPACE" -mindepth 1 -delete',
                    workspace_step,
                )


if __name__ == "__main__":
    unittest.main()
