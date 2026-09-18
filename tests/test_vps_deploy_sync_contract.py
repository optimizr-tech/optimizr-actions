"""Regression contracts for fail-closed VPS deployment synchronization."""

from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = (
    ROOT / ".github/workflows/_vps-self-hosted-deploy.yml",
    ROOT / ".github/workflows/_vps-monorepo-deploy.yml",
)


class VpsDeploySyncContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.contents = {
            workflow.name: workflow.read_text(encoding="utf-8")
            for workflow in WORKFLOWS
        }

    def test_deploys_are_serialized_per_service_across_refs(self) -> None:
        for workflow_name, content in self.contents.items():
            with self.subTest(workflow=workflow_name):
                self.assertIn("group: deploy-${{ inputs.service_name }}", content)
                self.assertNotIn(
                    "group: deploy-${{ inputs.service_name }}-${{ github.ref }}",
                    content,
                )

    def test_rsync_uses_content_checksums_for_change_detection(self) -> None:
        for workflow_name, content in self.contents.items():
            with self.subTest(workflow=workflow_name):
                rsync_args_start = content.index("rsync_args=(")
                dry_run_start = content.index("dry_run_output=", rsync_args_start)
                rsync_args = content[rsync_args_start:dry_run_start]

                self.assertIn("--checksum", rsync_args)

    def test_deploy_fails_closed_when_post_sync_content_parity_drifts(self) -> None:
        for workflow_name, content in self.contents.items():
            with self.subTest(workflow=workflow_name):
                sync_call = 'rsync "${rsync_args[@]}" "$GITHUB_WORKSPACE/" "$DEPLOY_PATH/"'
                sync_index = content.index(sync_call)
                verify_index = content.index(
                    "# Post-sync content parity verification",
                    sync_index,
                )
                verify_block_end = content.index(
                    'find "$DEPLOY_PATH" -name',
                    verify_index,
                )
                verify_block = content[verify_index:verify_block_end]

                self.assertLess(sync_index, verify_index)
                self.assertIn('parity_output="$(mktemp)"', verify_block)
                self.assertIn(
                    'rsync "${parity_args[@]}" --dry-run --itemize-changes',
                    verify_block,
                )
                self.assertIn('if [ -s "$parity_output" ]; then', verify_block)
                self.assertIn("wc -l", verify_block)
                self.assertIn("exit 1", verify_block)


if __name__ == "__main__":
    unittest.main()
