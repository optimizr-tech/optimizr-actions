from pathlib import Path
import unittest

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
        self.assertIn("LEGACY_INFRA_OPS_REFERENCES = Counter()", text)
        self.assertNotIn("quality-gate-scripts@v1", text)


if __name__ == "__main__":
    unittest.main()
