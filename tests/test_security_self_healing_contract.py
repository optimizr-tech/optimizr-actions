from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


class SecuritySelfHealingContractTests(unittest.TestCase):
    def _assert_retry_contract(self, path: str, rollout_name: str) -> None:
        content = read(path)

        self.assertIn("security_rebuild_retry_enabled:", content)
        self.assertIn("security_rebuild_retry_no_cache:", content)
        self.assertEqual(
            1,
            content.count(
                "optimizr-tech/optimizr-actions/.github/actions/security-rebuild@v1"
            ),
        )
        self.assertIn(
            "steps.security-images-initial-gate.outputs.classification == "
            "'actionable_vulnerability'",
            content,
        )
        self.assertIn("continue-on-error: true", content)
        self.assertIn("Discover remediated Compose images", content)
        self.assertIn("Enforce final image security result", content)
        self.assertIn("security_initial_result:", content)
        self.assertIn("security_rebuild_attempted:", content)
        self.assertIn("security_rebuild_result:", content)
        self.assertIn("security_final_result:", content)
        self.assertNotIn(
            'docker compose -f "$COMPOSE_FILE" images --quiet', content
        )

        initial = content.index("Security gate (images, initial)")
        rebuild = content.index("Rebuild actionable image vulnerabilities")
        rediscover = content.index("Discover remediated Compose images")
        final = content.index("Security gate (images, remediated)")
        enforce = content.index("Enforce final image security result")
        rollout = content.index(rollout_name)
        self.assertLess(initial, rebuild)
        self.assertLess(rebuild, rediscover)
        self.assertLess(rediscover, final)
        self.assertLess(final, enforce)
        self.assertLess(enforce, rollout)

    def test_single_service_retry_is_bounded_before_rollout(self) -> None:
        self._assert_retry_contract(
            ".github/workflows/_vps-self-hosted-deploy.yml",
            "Roll out and verify primary container",
        )

    def test_monorepo_retry_is_bounded_before_rollout(self) -> None:
        self._assert_retry_contract(
            ".github/workflows/_vps-monorepo-deploy.yml",
            "Roll out services",
        )


if __name__ == "__main__":
    unittest.main()
