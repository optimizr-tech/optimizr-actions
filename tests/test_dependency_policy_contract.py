from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class DependencyPolicyContractTests(unittest.TestCase):
    def test_action_scans_vulnerabilities_and_licenses_and_fails_closed(self):
        text = (ROOT / ".github/actions/dependency-policy/action.yml").read_text()
        self.assertIn("--scanners vuln,license", text)
        self.assertIn("--exit-code 0", text)
        self.assertIn("dependency_policy/policy.py", text)
        self.assertIn("uv lock --check", text)
        self.assertIn("project.get(\"requires-python\")", text)
        self.assertIn("requires-python must declare a minimum Python version", text)
        self.assertIn('uv python install "$python_version"', text)
        self.assertNotIn('uv python install "$python_requirement"', text)
        self.assertIn("\n        PY\n        )\"", text)
        self.assertIn("poetry check --lock", text)
        self.assertNotIn("continue-on-error", text)
        self.assertIn("realpath -e", text)
        self.assertIn("resolves outside the repository", text)

    def test_action_uses_controlled_node_and_immutable_npm_validation(self):
        text = (ROOT / ".github/actions/dependency-policy/action.yml").read_text()
        self.assertIn("node_version:", text)
        self.assertIn("npm_version:", text)
        self.assertIn('default: "24"', text)
        self.assertIn('default: "11"', text)
        self.assertRegex(text, r"actions/setup-node@[0-9a-f]{40}")
        self.assertIn("steps.ecosystems.outputs.node_required", text)
        self.assertIn("steps.ecosystems.outputs.npm_required", text)
        self.assertIn('npm install --global --no-audit --no-fund "npm@${NPM_VERSION}"', text)
        self.assertIn("npm ci --ignore-scripts --no-audit --no-fund", text)
        self.assertNotIn("npm install --package-lock-only", text)
        self.assertIn('mkdir -p "$GITHUB_WORKSPACE/$EVIDENCE_DIR"', text)

    def test_node_toolchain_inputs_propagate_through_reusables(self):
        workflow_paths = [
            ROOT / ".github/workflows/_dependency-policy.yml",
            ROOT / ".github/workflows/_security-suite.yml",
            ROOT / ".github/workflows/_validation-gate.yml",
        ]
        for path in workflow_paths:
            with self.subTest(path=path.name):
                text = path.read_text()
                self.assertIn("node_version:", text)
                self.assertIn("npm_version:", text)
                self.assertIn('default: "24"', text)
                self.assertIn('default: "11"', text)
                self.assertIn("node_version: ${{ inputs.node_version }}", text)
                self.assertIn("npm_version: ${{ inputs.npm_version }}", text)

    def test_documentation_explains_runtime_and_lockfile_contracts(self):
        text = (ROOT / "docs/DEPENDENCY_POLICY.md").read_text()
        self.assertIn("minimum Python version", text)
        self.assertIn("`>=3.14`", text)
        self.assertIn("Node 24", text)
        self.assertIn("npm 11", text)
        self.assertIn("`npm ci --ignore-scripts --no-audit --no-fund`", text)
        self.assertIn("never regenerates `package-lock.json`", text)

    def test_workflow_uses_pinned_actions_and_read_only_permissions(self):
        text = (ROOT / ".github/workflows/_dependency-policy.yml").read_text()
        self.assertIn("contents: read", text)
        self.assertIn("fromJSON(inputs.runner_json)", text)
        self.assertRegex(text, r"actions/checkout@[0-9a-f]{40}")
        self.assertRegex(text, r"actions/upload-artifact@[0-9a-f]{40}")


if __name__ == "__main__":
    unittest.main()
