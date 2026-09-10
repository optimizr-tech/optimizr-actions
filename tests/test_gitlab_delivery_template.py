from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class GitLabDeliveryTemplateTests(unittest.TestCase):
    def read_template(self) -> str:
        return (ROOT / "templates/gitlab/optimizr-delivery.yml").read_text(
            encoding="utf-8"
        )

    def test_template_is_manual_protected_and_service_serialized(self) -> None:
        content = self.read_template()

        self.assertIn(".optimizr-delivery:", content)
        self.assertIn("stage: deploy", content)
        self.assertIn('resource_group: "optimizr-delivery-${OPTIMIZR_DELIVERY_SERVICE}"', content)
        self.assertIn('if: \'$CI_COMMIT_REF_PROTECTED == "true" && $CI_COMMIT_TAG =~ /^deploy-/\'', content)
        self.assertIn("when: manual", content)
        self.assertIn("when: never", content)
        self.assertIn('OPTIMIZR_DELIVERY_PROVIDER: gitlab-ci', content)
        self.assertIn('OPTIMIZR_DELIVERY_PROTECTED_REF: "true"', content)
        self.assertIn('"$OPTIMIZR_DELIVERY_RUNNER_TAG"', content)

    def test_template_requires_protected_runner_signal_and_confined_entrypoint(self) -> None:
        content = self.read_template()

        self.assertIn(
            'test "${OPTIMIZR_DELIVERY_PROTECTED_RUNNER:-}" = "true"',
            content,
        )
        self.assertIn('entrypoint="${OPTIMIZR_DELIVERY_ENTRYPOINT:-}"', content)
        self.assertIn('"$CI_PROJECT_DIR"/*)', content)
        self.assertIn('test -f "$entrypoint"', content)
        self.assertIn('python "$entrypoint"', content)
        self.assertNotIn("eval ", content)
        self.assertNotIn("sh -c", content)
        self.assertNotIn("curl ", content)

    def test_template_does_not_define_the_protected_runner_attestation(self) -> None:
        content = self.read_template()
        self.assertNotIn("    OPTIMIZR_DELIVERY_PROTECTED_RUNNER:", content)


if __name__ == "__main__":
    unittest.main()
