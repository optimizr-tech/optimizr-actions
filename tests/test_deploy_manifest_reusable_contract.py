"""Static contracts for deploy-manifest integration in VPS reusables."""

from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class DeployManifestReusableContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.generic = (ROOT / ".github/workflows/_vps-self-hosted-deploy.yml").read_text(
            encoding="utf-8"
        )
        self.monorepo = (ROOT / ".github/workflows/_vps-monorepo-deploy.yml").read_text(
            encoding="utf-8"
        )

    def test_manifest_inputs_are_optional_and_backward_compatible(self) -> None:
        for workflow in (self.generic, self.monorepo):
            self.assertIn("deploy_manifest_enabled:", workflow)
            self.assertIn("default: false", workflow)
            self.assertIn("deploy_manifest_retention:", workflow)
            self.assertIn("default: 50", workflow)
            self.assertIn("deploy_manifest_migration_result:", workflow)
            self.assertIn("default: not-reported", workflow)

    def test_recorder_source_is_bound_to_the_reusable_revision(self) -> None:
        for workflow in (self.generic, self.monorepo):
            self.assertIn("repository: ${{ job.workflow_repository }}", workflow)
            self.assertIn("ref: ${{ job.workflow_sha }}", workflow)
            self.assertIn(
                "uses: ./.optimizr-actions-manifest/.github/actions/record-deploy-manifest",
                workflow,
            )
            self.assertIn("if: always() && inputs.deploy_manifest_enabled", workflow)
            self.assertIn("job.status == 'success'", workflow)

    def test_monorepo_has_no_legacy_runtime_action_dependency(self) -> None:
        self.assertNotIn("optimizr-infra-ops/.github/actions/wait-for-healthcheck", self.monorepo)
        self.assertIn("id: optional-builds", self.monorepo)
        self.assertIn("optional_build_result:", self.monorepo)
        self.assertIn("steps.optional-builds.outputs.result", self.monorepo)

    def test_third_party_actions_remain_pinned(self) -> None:
        for workflow in (self.generic, self.monorepo):
            self.assertNotIn("actions/checkout@v", workflow)
            self.assertNotIn("actions/upload-artifact@v", workflow)
            self.assertIn("actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a", workflow)


if __name__ == "__main__":
    unittest.main()
