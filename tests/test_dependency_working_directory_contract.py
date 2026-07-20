from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class DependencyWorkingDirectoryContractTests(unittest.TestCase):
    def test_workflow_and_action_expose_confined_working_directory(self):
        workflow = (ROOT / ".github/workflows/_dependency-policy.yml").read_text()
        action = (ROOT / ".github/actions/dependency-policy/action.yml").read_text()
        self.assertIn("working_directory:", workflow)
        self.assertIn("working_directory: ${{ inputs.working_directory }}", workflow)
        self.assertIn("working_directory:", action)
        self.assertIn("realpath -e", action)
        self.assertIn("resolves outside the repository", action)
        self.assertIn("non-symlink directory", action)
        self.assertIn('cd "$DEPENDENCY_ROOT"', action)
        self.assertIn('--root "$DEPENDENCY_ROOT"', action)
        self.assertIn('"$DEPENDENCY_ROOT"', action)

    def test_working_directory_is_not_executed_as_shell(self):
        action = (ROOT / ".github/actions/dependency-policy/action.yml").read_text()
        self.assertNotIn("eval ", action)
        self.assertNotIn("bash -c", action)
        self.assertNotIn("source $WORKING_DIRECTORY", action)


if __name__ == "__main__":
    unittest.main()
