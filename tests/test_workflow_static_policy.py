"""Regression checks for executable workflow policy."""

from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


class WorkflowStaticPolicyTests(unittest.TestCase):
    def test_local_validation_adapter_delegates_to_the_canonical_runner(self) -> None:
        content = read(".github/actions/local-validation/action.yml")
        self.assertIn("scripts/local_validation/run.py", content)
        self.assertIn("command-json", content)

    def test_quality_gate_uses_argument_arrays_for_optional_flags(self) -> None:
        content = read(".github/workflows/_quality-gate-pr.yml")
        self.assertIn("baseline_args=()", content)
        self.assertIn("post_args=()", content)
        self.assertIn('"${baseline_args[@]}"', content)
        self.assertIn('"${post_args[@]}"', content)

    def test_release_gate_pins_validation_images_by_digest(self) -> None:
        content = read(".github/workflows/move-v1.yml")
        self.assertIn(
            "rhysd/actionlint@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667",
            content,
        )
        self.assertIn(
            "mikefarah/yq@sha256:76def1f56f456ecc1c3173ea275218ee17139bc2018c5a07887b15afd88ec03e",
            content,
        )

    def test_deploy_workflows_do_not_use_unquoted_numeric_or_unused_loop_variables(self) -> None:
        self_hosted = read(".github/workflows/_vps-self-hosted-deploy.yml")
        monorepo = read(".github/workflows/_vps-monorepo-deploy.yml")
        self.assertIn('if [ "$counter" -ge "$HEALTH_TIMEOUT" ]; then', self_hosted)
        self.assertNotIn("for attempt in 1 2 3; do", monorepo)


if __name__ == "__main__":
    unittest.main()
