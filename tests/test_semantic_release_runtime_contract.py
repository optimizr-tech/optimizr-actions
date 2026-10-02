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

    def test_default_plugins_are_not_reinstalled_over_semantic_release_runtime(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        runtime_step = text.split("- name: Install semantic-release runtime", 1)[1].split(
            "- name: Validate changelog preset compatibility", 1
        )[0]

        default_plugins = (
            "@semantic-release/commit-analyzer",
            "@semantic-release/release-notes-generator",
            "@semantic-release/npm",
            "@semantic-release/github",
        )
        self.assertIn('case "$pkg" in', runtime_step)
        for plugin in default_plugins:
            with self.subTest(plugin=plugin):
                self.assertIn(f'"{plugin}"', runtime_step)
        self.assertIn('install_packages+=("$pkg")', runtime_step)

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
        self.assertIn('default: "v1"', text)
        self.assertIn("update_release_badge:", text)
        self.assertIn("protected_main_mode:", text)
        self.assertIn("skip:", text)
        self.assertIn(
            "inputs.update_release_badge && !inputs.protected_main_mode && needs.release.result == 'success'",
            text,
        )
        self.assertRegex(text, r"actions/checkout@[0-9a-f]{40}")
        self.assertIn(
            "optimizr-tech/optimizr-actions/.github/actions/update-release-badge@v1",
            text,
        )

    def test_canonical_assets_do_not_rely_on_the_callers_repository_token(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        resolver = text.split("- name: Resolve canonical release assets", 1)[1].split(
            "- name: Prepare protected-main release config", 1
        )[0]

        self.assertNotIn("GH_TOKEN:", resolver)
        self.assertNotIn("gh api", resolver)
        self.assertIn(
            "curl --fail --silent --show-error --connect-timeout 15 --max-time 60 --get",
            resolver,
        )
        self.assertIn('Accept: application/vnd.github.raw+json', resolver)
        self.assertNotIn('Authorization:', resolver)
        self.assertIn('if [[ -z "$SOURCE_REF" ]]', resolver)
        self.assertIn("canonical assets require a non-empty source ref", resolver)

    def test_canonical_assets_use_one_urlencoded_source_ref_for_both_files(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        resolver = text.split("- name: Resolve canonical release assets", 1)[1].split(
            "- name: Prepare protected-main release config", 1
        )[0]

        self.assertIn('--data-urlencode "ref=${SOURCE_REF}"', resolver)
        self.assertIn(
            'https://api.github.com/repos/${SOURCE_REPOSITORY}/contents/${ASSET_PATH}',
            resolver,
        )
        self.assertIn('fetch_asset "templates/.releaserc.json" "$DEST"', resolver)
        self.assertIn(
            'fetch_asset "scripts/release/prepare_protected_releaserc.py" "$TRANSFORMER"',
            resolver,
        )
        self.assertIn('SOURCE_REF="$REQUESTED_REF"', resolver)
        self.assertIn('SOURCE_REF="$WORKFLOW_SHA"', resolver)

    def test_documentation_defines_runtime_migration_and_rollback(self):
        text = DOC.read_text(encoding="utf-8")
        self.assertIn("Node 24", text)
        self.assertIn("npm 12.0.2", text)
        self.assertIn("unauthenticated GitHub Contents API", text)
        self.assertIn("does not use the caller's `GITHUB_TOKEN`", text)
        self.assertIn("controlled npm", text)
        self.assertIn("does not regenerate `package-lock.json`", text)
        self.assertIn("optimizr-infra-ops", text)
        self.assertIn("Rollback", text)


if __name__ == "__main__":
    unittest.main()
