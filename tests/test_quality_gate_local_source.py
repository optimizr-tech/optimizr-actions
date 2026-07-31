import json
from pathlib import Path
import tempfile
import unittest

from scripts.quality_gate.compare import compare
from scripts.quality_gate.metrics import CoverageMetric
from scripts.quality_gate.parse_pip_audit import parse as parse_pip_audit
from scripts.quality_gate.parse_pytest_cov import parse as parse_pytest_cov
from scripts.quality_gate.run import collect_metrics

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = (
    "_quality-gate-baseline.yml",
    "_quality-gate-pr.yml",
    "_quality-gate.yml",
)
REQUIRED_MODULES = (
    "__init__.py",
    "collect_ci_run.py",
    "compare.py",
    "legacy_metrics.py",
    "metrics.py",
    "parse_bandit.py",
    "parse_jscpd.py",
    "parse_next_bundle.py",
    "parse_pip_audit.py",
    "parse_pnpm_audit.py",
    "parse_pytest_cov.py",
    "parse_vitest_cov.py",
    "post_comment.py",
    "render_comment.py",
    "run.py",
)


class QualityGateLocalSourceTests(unittest.TestCase):
    def test_quality_gate_package_is_owned_by_actions(self) -> None:
        package = ROOT / "scripts" / "quality_gate"
        for module in REQUIRED_MODULES:
            with self.subTest(module=module):
                self.assertTrue((package / module).is_file())

    def test_workflows_use_exact_reusable_source(self) -> None:
        for name in WORKFLOWS:
            text = (ROOT / ".github" / "workflows" / name).read_text()
            with self.subTest(workflow=name):
                self.assertNotIn("optimizr-infra-ops", text)
                self.assertNotIn("/_qg", text)
                self.assertIn("repository: ${{ job.workflow_repository }}", text)
                self.assertIn("ref: ${{ job.workflow_sha }}", text)
                self.assertIn(".optimizr-actions-source", text)

    def test_repository_boundary_allowlist_is_empty(self) -> None:
        text = (ROOT / "tests" / "test_repository_boundary.py").read_text()
        self.assertIn("LEGACY_INFRA_OPS_REFERENCES", text)
        self.assertIn("= Counter()", text)
        self.assertNotIn("quality-gate-scripts@v1", text)

    def test_parsers_and_comparator_preserve_existing_contract(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            coverage = root / "pytest-coverage.json"
            coverage.write_text(
                json.dumps(
                    {
                        "totals": {
                            "percent_covered": 89.0,
                            "covered_lines": 89,
                            "num_statements": 100,
                            "percent_branches_covered": 75.0,
                            "covered_branches": 15,
                            "num_branches": 20,
                        }
                    }
                ),
                encoding="utf-8",
            )
            audit = root / "pip-audit.json"
            audit.write_text(
                json.dumps(
                    {
                        "dependencies": [
                            {"name": "safe", "vulns": []},
                            {"name": "affected", "vulns": [{"id": "TEST-1"}]},
                        ]
                    }
                ),
                encoding="utf-8",
            )

            parsed_coverage = parse_pytest_cov(coverage)
            parsed_audit = parse_pip_audit(audit, "backend")
            self.assertEqual(89.0, parsed_coverage.line_pct)
            self.assertEqual(1, parsed_audit.high)
            self.assertEqual(2, len(collect_metrics(root)))

            baseline = CoverageMetric(
                tool="pytest",
                scope="backend",
                line_pct=91.0,
                line_covered=91,
                line_total=100,
                branch_pct=75.0,
                branch_covered=15,
                branch_total=20,
            )
            report = compare([parsed_coverage], [baseline])
            self.assertEqual("red", report.overall)

    def test_compatibility_composite_no_longer_fetches_infra_ops(self) -> None:
        text = (
            ROOT / ".github" / "actions" / "quality-gate-scripts" / "action.yml"
        ).read_text()
        self.assertNotIn("repository: optimizr-tech/optimizr-infra-ops", text)
        self.assertIn("github.action_path", text)
        self.assertIn("scripts/quality_gate", text)


if __name__ == "__main__":
    unittest.main()
