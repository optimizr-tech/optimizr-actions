from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/_semantic-release.yml"
DOC = ROOT / "docs/SEMANTIC_RELEASE.md"
VALIDATOR = ROOT / "scripts/release/validate_changelog_compatibility.py"
PACKAGE_LESS_CANARY = ROOT / ".github/workflows/semantic-release-package-less-canary.yml"


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

    def test_package_less_mode_is_opt_in_and_never_runs_release_or_badge_in_validation_only(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("package_mode:", text)
        self.assertIn('default: "node"', text)
        self.assertIn("if: inputs.package_mode == 'node'", text)
        self.assertIn("if: inputs.package_mode == 'package-less'", text)
        install_step = text.split("- name: Install dependencies", 1)[1].split(
            "- name: Resolve canonical release assets", 1
        )[0]
        self.assertIn("if: inputs.package_mode == 'node'", install_step)
        self.assertIn("working-directory: ${{ inputs.working_directory }}", install_step)
        self.assertIn("run: ${{ inputs.install_command }}", install_step)
        self.assertIn("validate_only:", text)
        self.assertIn("if: ${{ !inputs.validate_only }}", text)
        self.assertIn("persist-credentials: ${{ !inputs.validate_only }}", text)
        self.assertIn(
            "!inputs.validate_only && needs.release.result == 'success'",
            text,
        )

    def test_release_working_directory_is_confined_and_node_mode_stays_at_root(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("working_directory:", text)
        self.assertIn('default: "."', text)
        self.assertIn("configured_directory.is_absolute()", text)
        self.assertIn("resolved_directory.relative_to(checkout_root)", text)
        self.assertIn(
            'os.environ["PACKAGE_MODE"] == "node" and resolved_directory != checkout_root',
            text,
        )
        self.assertIn("working-directory: ${{ inputs.working_directory }}", text)

    def test_compatibility_validator_is_fetched_from_exact_reusable_workflow_sha(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        fetch_step = text.split(
            "- name: Fetch changelog validator from the called workflow revision", 1
        )[1].split("- name: Setup Node.js with project cache", 1)[0]
        self.assertIn("if: inputs.package_mode == 'package-less'", fetch_step)
        self.assertIn('WORKFLOW_SHA="${workflow_identity[1]:-}"', fetch_step)
        self.assertIn('SOURCE_REPOSITORY="${workflow_identity[0]:-}"', fetch_step)
        self.assertIn('"$SOURCE_REPOSITORY" != "optimizr-tech/optimizr-actions"', fetch_step)
        self.assertIn('"$WORKFLOW_SHA" =~ ^[0-9a-f]{40}$', fetch_step)
        self.assertIn(
            "https://raw.githubusercontent.com/${SOURCE_REPOSITORY}/${WORKFLOW_SHA}/scripts/release/validate_changelog_compatibility.py",
            fetch_step,
        )
        self.assertIn("validate_changelog_compatibility.py", fetch_step)
        self.assertIn("$RUNNER_TEMP/validate_changelog_compatibility.py", fetch_step)
        self.assertIn(
            'python3 "$RUNNER_TEMP/validate_changelog_compatibility.py"',
            text,
        )
        self.assertNotIn(
            "python3 scripts/release/validate_changelog_compatibility.py",
            text,
        )

    def test_package_less_canary_uses_exact_same_commit_hosted_runner_and_read_only_token(self):
        text = PACKAGE_LESS_CANARY.read_text(encoding="utf-8")
        self.assertIn("uses: ./.github/workflows/_semantic-release.yml", text)
        self.assertIn("package_mode: package-less", text)
        self.assertIn("working_directory: tests/fixtures/package-less-release", text)
        self.assertIn("runs_on: '[\"ubuntu-latest\"]'", text)
        self.assertIn("releaserc_source: local", text)
        self.assertNotIn("protected_main_mode: true", text)
        self.assertIn("validate_only: true", text)
        self.assertIn("contents: read", text)
        self.assertNotIn("self-hosted", text)
        self.assertIn('"tests/fixtures/package-less-release/**"', text)

        fixture = ROOT / "tests/fixtures/package-less-release"
        self.assertTrue((fixture / ".releaserc.json").is_file())
        self.assertFalse((fixture / "package.json").exists())
        self.assertFalse((fixture / "package-lock.json").exists())

    def test_default_plugins_are_not_reinstalled_over_semantic_release_runtime(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        runtime_step = text.split("- name: Install semantic-release runtime", 1)[1].split(
            "- name: Validate Node changelog preset compatibility", 1
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
        validator = VALIDATOR.read_text(encoding="utf-8")
        self.assertIn("Validate Node changelog preset compatibility", text)
        self.assertIn("Validate package-less changelog preset compatibility", text)
        self.assertIn('if: inputs.package_mode == \'node\'', text)
        self.assertIn("validate_changelog_compatibility.py", text)
        self.assertIn("package-lock.json", text)
        self.assertIn("conventional-changelog-conventionalcommits", validator)
        self.assertIn("conventional-changelog-writer", validator)
        self.assertIn('workspace / "package-lock.json"', validator)
        self.assertIn("preset 9.x + writer 8.x", validator)
        self.assertIn("preset 10.x + writer 9.x", validator)

        compatibility_index = min(
            text.index("Validate Node changelog preset compatibility"),
            text.index("Validate package-less changelog preset compatibility"),
        )
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
            "inputs.update_release_badge && !inputs.protected_main_mode && !inputs.validate_only && needs.release.result == 'success'",
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
        self.assertIn("package_mode: package-less", text)
        self.assertIn("validate_only: true", text)
        self.assertIn("unauthenticated GitHub Contents API", text)
        self.assertIn("does not use the caller's `GITHUB_TOKEN`", text)
        self.assertIn("controlled npm", text)
        self.assertIn("does not regenerate `package-lock.json`", text)
        self.assertIn("optimizr-infra-ops", text)
        self.assertIn("Rollback", text)


if __name__ == "__main__":
    unittest.main()
