from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class NodeProjectContractTests(unittest.TestCase):
    def test_reusable_validates_matrix_and_uses_pinned_actions(self):
        text = (ROOT / ".github/workflows/_node-project-test.yml").read_text()
        self.assertIn("fromJSON(needs.prepare.outputs.matrix)", text)
        self.assertIn("MAX_PROJECTS = 10", text)
        self.assertIn("actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd", text)
        self.assertIn("actions/setup-node@48b55a011bda9f5d6aeb4c2d9c7362e8dae4041e", text)
        self.assertIn("pnpm/action-setup@0ebf47130e4866e96fce0953f49152a61190b271", text)
        self.assertIn("actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a", text)

    def test_pnpm_bootstrap_uses_installed_node_without_standalone_bundle(self):
        text = (ROOT / ".github/workflows/_node-project-test.yml").read_text()
        node_setup = text.index("Install Node.js before pnpm bootstrap")
        pnpm_setup = text.index("- name: Install pnpm")
        cache_setup = text.index("- name: Initialize pnpm cache", pnpm_setup)

        self.assertLess(node_setup, pnpm_setup)
        self.assertNotIn("standalone: true", text[pnpm_setup:cache_setup])

    def test_pnpm_uses_controlled_node_before_bootstrap(self):
        text = (ROOT / ".github/workflows/_node-project-test.yml").read_text()
        setup_node = text.index("actions/setup-node@")
        pnpm_setup = text.index("pnpm/action-setup@")
        self.assertLess(setup_node, pnpm_setup)
        self.assertLess(pnpm_setup, text.index("cache: pnpm"))
        self.assertIn("cache-dependency-path:", text)

    def test_contract_is_read_only_and_has_no_arbitrary_command_input(self):
        text = (ROOT / ".github/workflows/_node-project-test.yml").read_text()
        action = (ROOT / ".github/actions/node-project-test/action.yml").read_text()
        self.assertIn("permissions:\n  contents: read", text)
        self.assertNotIn("secrets: inherit", text)
        self.assertNotIn("command:", text)
        self.assertNotIn("extra_steps", text)
        self.assertNotIn("bash -c", action)
        self.assertNotIn("eval ", action)
        self.assertIn("scripts/node_project/runner.py", action)


if __name__ == "__main__":
    unittest.main()
