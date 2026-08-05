from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "release" / "prepare_protected_releaserc.py"
WORKFLOW = ROOT / ".github" / "workflows" / "_semantic-release.yml"
DOC = ROOT / "docs" / "SEMANTIC_RELEASE.md"

spec = importlib.util.spec_from_file_location("prepare_protected_releaserc", SCRIPT)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)


class ProtectedReleaseConfigTests(unittest.TestCase):
    def test_removes_branch_mutating_plugins_and_preserves_release_plugins(self) -> None:
        config = {
            "plugins": [
                "@semantic-release/commit-analyzer",
                ["@semantic-release/changelog", {"changelogFile": "CHANGELOG.md"}],
                ["@semantic-release/npm", {"npmPublish": False}],
                "@semantic-release/github",
                ["@semantic-release/git", {"assets": ["CHANGELOG.md"]}],
            ]
        }

        protected, removed = module.prepare_protected_config(config)

        names = [module.plugin_name(item) for item in protected["plugins"]]
        self.assertEqual(
            [
                "@semantic-release/commit-analyzer",
                "@semantic-release/npm",
                "@semantic-release/github",
            ],
            names,
        )
        self.assertEqual(
            ["@semantic-release/changelog", "@semantic-release/git"],
            removed,
        )

    def test_rejects_config_without_github_release_plugin(self) -> None:
        with self.assertRaisesRegex(module.ProtectedReleaseError, "github release plugin"):
            module.prepare_protected_config({"plugins": ["@semantic-release/commit-analyzer"]})

    def test_cli_writes_filtered_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / ".releaserc.json"
            path.write_text(
                json.dumps(
                    {
                        "plugins": [
                            "@semantic-release/commit-analyzer",
                            "@semantic-release/github",
                            "@semantic-release/git",
                        ]
                    }
                ),
                encoding="utf-8",
            )
            self.assertEqual(0, module.main([str(path)]))
            payload = json.loads(path.read_text(encoding="utf-8"))
            self.assertNotIn("@semantic-release/git", payload["plugins"])


class ProtectedReleaseWorkflowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.workflow = WORKFLOW.read_text(encoding="utf-8")

    def test_workflow_exposes_backward_compatible_opt_in(self) -> None:
        self.assertIn("protected_main_mode:", self.workflow)
        self.assertIn("default: false", self.workflow)

    def test_protected_mode_requires_canonical_config_and_no_badge_push(self) -> None:
        self.assertIn("protected_main_mode requires releaserc_source=canonical", self.workflow)
        self.assertIn("protected_main_mode is incompatible with update_release_badge=true", self.workflow)

    def test_protected_assets_use_serialized_exact_workflow_identity(self) -> None:
        self.assertIn("JOB_CONTEXT_JSON: ${{ toJSON(job) }}", self.workflow)
        self.assertIn('job_context = json.loads(os.environ["JOB_CONTEXT_JSON"])', self.workflow)
        self.assertIn('SOURCE_REPOSITORY="$WORKFLOW_REPOSITORY"', self.workflow)
        self.assertIn('SOURCE_REF="$WORKFLOW_SHA"', self.workflow)
        self.assertIn(
            '"repos/${SOURCE_REPOSITORY}/contents/scripts/release/prepare_protected_releaserc.py?ref=${SOURCE_REF}"',
            self.workflow,
        )
        self.assertIn("$RUNNER_TEMP/prepare_protected_releaserc.py", self.workflow)
        self.assertNotIn("${{ job.workflow_repository }}", self.workflow)
        self.assertNotIn("${{ job.workflow_sha }}", self.workflow)

    def test_normal_mode_preserves_requested_actions_ref(self) -> None:
        self.assertIn("REQUESTED_REF: ${{ inputs.actions_ref }}", self.workflow)
        self.assertIn('SOURCE_REF="$REQUESTED_REF"', self.workflow)

    def test_badge_push_is_unreachable_in_protected_mode(self) -> None:
        self.assertIn(
            "inputs.update_release_badge && !inputs.protected_main_mode",
            self.workflow,
        )

    def test_documentation_explains_protected_mode_and_rollback(self) -> None:
        text = DOC.read_text(encoding="utf-8")
        self.assertIn("protected_main_mode: true", text)
        self.assertIn("does not commit generated files to `main`", text)
        self.assertIn("separate reviewed pull request", text)
        self.assertIn("`job.workflow_sha`", text)
        self.assertIn("Disable `protected_main_mode` before ruleset activation", text)


if __name__ == "__main__":
    unittest.main()
