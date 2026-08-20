from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/_semantic-release.yml"
DOC = ROOT / "docs/SEMANTIC_RELEASE.md"


class SemanticReleaseRuntimeContractTests(unittest.TestCase):
    def test_workflow_uses_controlled_node_and_npm_runtime(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("node_version:", text)
        self.assertIn('default: "24"', text)
        self.assertIn("npm_version:", text)
        self.assertIn('default: "12.0.2"', text)
        self.assertRegex(text, r"actions/setup-node@[0-9a-f]{40}")
        self.assertIn("Setup controlled npm", text)
        self.assertIn('npm install --global --no-audit --no-fund "npm@${NPM_VERSION}"', text)
        self.assertIn("node --version", text)
        self.assertIn("npm --version", text)

        setup_index = text.index("Setup controlled npm")
        install_index = text.index("- name: Install dependencies")
        self.assertLess(setup_index, install_index)

    def test_release_runtime_is_lockfile_neutral_and_fail_closed(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("run: ${{ inputs.install_command }}", text)
        self.assertIn("--package-lock=false", text)
        self.assertNotIn("npm install --package-lock-only", text)
        self.assertNotIn("continue-on-error", text)
        self.assertIn("npx semantic-release --dry-run", text)
        self.assertIn("run: npx semantic-release", text)

    def test_workflow_validates_conventional_commits_preset_writer_matrix(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("Validate changelog preset compatibility", text)
        self.assertIn("conventional-changelog-conventionalcommits", text)
        self.assertIn("conventional-changelog-writer", text)
        self.assertIn("package-lock.json", text)
        self.assertIn("preset 9.x + writer 8.x", text)
        self.assertIn("preset 10.x + writer 9.x", text)

        compatibility_index = text.index("Validate changelog preset compatibility")
        dry_run_index = text.index("npx semantic-release --dry-run")
        self.assertLess(compatibility_index, dry_run_index)

    def test_existing_release_and_badge_contracts_are_preserved(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("releaserc_source:", text)
        self.assertIn("actions_ref:", text)
        self.assertIn("update_release_badge:", text)
        self.assertIn("protected_main_mode:", text)
        self.assertIn("skip:", text)
        self.assertIn(
            "inputs.update_release_badge && !inputs.protected_main_mode && needs.release.result == 'success'",
            text,
        )
        self.assertRegex(text, r"actions/checkout@[0-9a-f]{40}")
        self.assertRegex(text, r"optimizr-tech/optimizr-actions/.github/actions/update-release-badge@[0-9a-f]{40}")

    def test_documentation_defines_runtime_migration_and_rollback(self):
        text = DOC.read_text(encoding="utf-8")
        self.assertIn("Node 24", text)
        self.assertIn("npm 12.0.2", text)
        self.assertIn("controlled npm", text)
        self.assertIn("does not regenerate `package-lock.json`", text)
        self.assertIn("optimizr-infra-ops", text)
        self.assertIn("Rollback", text)


if __name__ == "__main__":
    unittest.main()
