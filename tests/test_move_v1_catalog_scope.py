from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "move-v1.yml"


class MoveV1CatalogScopeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.workflow = WORKFLOW.read_text(encoding="utf-8")

    def test_catalog_changes_trigger_push_and_pr_validation(self) -> None:
        self.assertIn('  pull_request:\n    branches: [main]\n', self.workflow)
        self.assertGreaterEqual(self.workflow.count('      - "catalog/**"'), 2)

    def test_recovery_path_recognizes_catalog_changes(self) -> None:
        self.assertIn(
            r'templates/|presets/|scripts/|catalog/)',
            self.workflow,
        )

    def test_pull_request_validation_never_moves_v1(self) -> None:
        expected = "if: needs.scope.outputs.publish == 'true' && github.event_name != 'pull_request'"
        self.assertIn(expected, self.workflow)

    def test_catalog_check_runs_before_general_contract_tests(self) -> None:
        catalog_check = "python3 -m scripts.capability_catalog.generate --check"
        unittest_run = "python3 -m unittest discover -v"
        self.assertIn(catalog_check, self.workflow)
        self.assertLess(self.workflow.index(catalog_check), self.workflow.index(unittest_run))


if __name__ == "__main__":
    unittest.main()
