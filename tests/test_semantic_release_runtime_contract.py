from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/_semantic-release.yml"
DOC = ROOT / "docs/SEMANTIC_RELEASE.md"
VALIDATOR = ROOT / "scripts/release/validate_changelog_compatibility.py"
PACKAGE_LESS_CANARY = ROOT / ".github/workflows/semantic-release-package-less-canary.yml"
PACKAGE_LESS_ACTION = ROOT / ".github/actions/package-less-release-validation/action.yml"


class SemanticReleaseRuntimeContractTests(unittest.TestCase):
    def test_package_less_action_is_shared_and_non_publishing(self):
        text = PACKAGE_LESS_ACTION.read_text(encoding="utf-8")
        self.assertIn("using: composite", text)
        self.assertIn("actions/setup-node@820762786026740c76f36085b0efc47a31fe5020", text)
        self.assertIn("validate_changelog_compatibility.py", text)
        self.assertIn("--package-mode package-less", text)
        self.assertIn("npx semantic-release --dry-run", text)
        self.assertNotIn("run: npx semantic-release\n", text)
        self.assertNotIn("git push", text)
        self.assertIn("github-token:", text)
        self.assertIn('default: ""', text)

        tokenless_step = text.split(
            "- name: Verify release plan without GitHub token", 1
        )[1].split("- name: Verify release plan with GitHub token", 1)[0]
        self.assertIn("if: inputs.github-token == ''", tokenless_step)
        self.assertNotIn("GITHUB_TOKEN:", tokenless_step)

        token_step = text.split("- name: Verify release plan with GitHub token", 1)[1]
        self.assertIn("if: inputs.github-token != ''", token_step)
        self.assertIn("GITHUB_TOKEN: ${{ inputs.github-token }}", token_step)
        self.assertIn("run: npx semantic-release --dry-run", token_step)

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
        self.assertNotIn("tokenless_dry_run", text)
        self.assertNotIn("simulate_default_branch_for_dry_run", text)
        for step_name in (
            "Setup Node.js with project cache",
            "Setup controlled npm",
            "Install dependencies",
            "Install semantic-release runtime",
            "Verify release plan with GitHub token",
        ):
            step = text.split(f"- name: {step_name}", 1)[1].split("\n      - name:", 1)[0]
            self.assertIn("if: inputs.package_mode == 'node'", step)
        token_step = text.split("- name: Verify release plan with GitHub token", 1)[1].split(
            "- name: Release", 1
        )[0]
        self.assertIn("GITHUB_TOKEN: ${{ github.token }}", token_step)
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

    def test_package_less_reusable_loads_shared_action_at_its_exact_sha(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        identity_step = text.split(
            "- name: Validate package-less workflow identity", 1
        )[1].split("- name: Guard shared action checkout path", 1)[0]
        path_guard = text.split(
            "- name: Guard shared action checkout path", 1
        )[1].split("- name: Checkout shared package-less validation action", 1)[0]
        checkout_step = text.split(
            "- name: Checkout shared package-less validation action", 1
        )[1].split("- name:", 1)[0]
        action_step = text.split(
            "- name: Validate package-less release plan", 1
        )[1].split("- name:", 1)[0]

        self.assertIn("if: inputs.package_mode == 'package-less'", identity_step)
        self.assertIn("${{ job.workflow_repository }}", identity_step)
        self.assertIn('"$WORKFLOW_REPOSITORY" != "optimizr-tech/optimizr-actions"', identity_step)
        self.assertIn("${{ job.workflow_sha }}", identity_step)
        self.assertIn('"$WORKFLOW_SHA" =~ ^[0-9a-f]{40}$', identity_step)
        self.assertIn('[[ -e "$TARGET_PATH" || -L "$TARGET_PATH" ]]', path_guard)
        self.assertIn('TARGET_PATH="$GITHUB_WORKSPACE/.optimizr-actions-release"', path_guard)
        self.assertIn("repository: optimizr-tech/optimizr-actions", checkout_step)
        self.assertIn("ref: ${{ job.workflow_sha }}", checkout_step)
        self.assertIn("path: .optimizr-actions-release", checkout_step)
        self.assertIn("persist-credentials: false", checkout_step)
        self.assertIn(
            "uses: ./.optimizr-actions-release/.github/actions/package-less-release-validation",
            action_step,
        )
        self.assertIn("github-token: ${{ github.token }}", action_step)
        self.assertNotIn("tokenless_dry_run:", text)
        self.assertNotIn("simulate_default_branch_for_dry_run:", text)
        self.assertLess(text.index("Validate package-less workflow identity"), text.index("Guard shared action checkout path"))
        self.assertLess(text.index("Guard shared action checkout path"), text.index("Checkout shared package-less validation action"))
        self.assertLess(text.index("Checkout shared package-less validation action"), text.index("Validate package-less release plan"))

    def test_package_less_canary_exercises_reusable_with_read_only_tokenless_validation(self):
        text = PACKAGE_LESS_CANARY.read_text(encoding="utf-8")
        self.assertIn("permissions:\n  contents: read", text)
        self.assertNotIn("contents: write", text)
        self.assertNotIn("issues: write", text)
        self.assertNotIn("pull-requests: write", text)
        self.assertNotIn("GITHUB_TOKEN:", text)
        self.assertIn("    permissions:\n      contents: read", text)
        self.assertIn("uses: ./.github/workflows/_semantic-release.yml", text)
        self.assertIn("package_mode: package-less", text)
        self.assertIn("working_directory: tests/fixtures/package-less-release", text)
        self.assertIn("runs_on: '[\"ubuntu-latest\"]'", text)
        self.assertIn("releaserc_source: local", text)
        self.assertIn("validate_only: true", text)
        self.assertIn("tokenless_dry_run: true", text)
        self.assertIn("simulate_default_branch_for_dry_run: true", text)
        self.assertNotIn("run:", text)
        self.assertNotIn("self-hosted", text)
        self.assertIn('"tests/fixtures/package-less-release/**"', text)

        fixture = ROOT / "tests/fixtures/package-less-release"
        self.assertTrue((fixture / ".releaserc.json").is_file())
        self.assertFalse((fixture / "package.json").exists())
        self.assertFalse((fixture / "package-lock.json").exists())
        releaserc = (fixture / ".releaserc.json").read_text(encoding="utf-8")
        self.assertIn("@semantic-release/commit-analyzer", releaserc)
        self.assertIn("@semantic-release/release-notes-generator", releaserc)
        self.assertNotIn("@semantic-release/github", releaserc)
        self.assertNotIn("@semantic-release/npm", releaserc)

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
        action = PACKAGE_LESS_ACTION.read_text(encoding="utf-8")
        self.assertIn("Validate Node changelog preset compatibility", text)
        self.assertNotIn("Validate package-less changelog preset compatibility", text)
        self.assertIn('if: inputs.package_mode == \'node\'', text)
        self.assertIn("Validate package-less changelog preset compatibility", action)
        self.assertIn("validate_changelog_compatibility.py", action)
        self.assertIn("package-lock.json", text)
        self.assertIn("conventional-changelog-conventionalcommits", validator)
        self.assertIn("conventional-changelog-writer", validator)
        self.assertIn('workspace / "package-lock.json"', validator)
        self.assertIn("preset 9.x + writer 8.x", validator)
        self.assertIn("preset 10.x + writer 9.x", validator)

        compatibility_index = text.index("Validate Node changelog preset compatibility")
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
