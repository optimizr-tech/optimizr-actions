import unittest

from scripts.security_evidence import summarize_security_suite


class SecuritySuiteSkipBehaviorTests(unittest.TestCase):
    def summarize(self, **overrides: str) -> dict[str, object]:
        jobs = {
            "profile": "success",
            "static_lint": "success",
            "filesystem_security": "success",
            "dependency_policy": "success",
            "sast": "success",
            "supply_chain": "skipped",
        }
        jobs.update(overrides)
        return summarize_security_suite(profile="python", image_refs="", jobs=jobs)

    def test_required_python_job_cannot_be_skipped(self):
        summary = self.summarize(dependency_policy="skipped")
        self.assertEqual(summary["result"], "failed")
        self.assertEqual(summary["unexpectedly_skipped"], ["dependency_policy"])

    def test_optional_supply_chain_skip_is_allowed_without_images(self):
        summary = summarize_security_suite(
            profile="infra",
            image_refs="",
            jobs={
                "profile": "success",
                "static_lint": "success",
                "filesystem_security": "success",
                "dependency_policy": "skipped",
                "sast": "skipped",
                "supply_chain": "skipped",
            },
        )
        self.assertEqual(summary["result"], "passed")
        self.assertEqual(
            summary["expected_skipped"],
            ["dependency_policy", "sast", "supply_chain"],
        )

    def test_supply_chain_becomes_required_when_images_are_declared(self):
        summary = summarize_security_suite(
            profile="infra",
            image_refs="app:local",
            jobs={
                "profile": "success",
                "static_lint": "success",
                "filesystem_security": "success",
                "dependency_policy": "skipped",
                "sast": "skipped",
                "supply_chain": "skipped",
            },
        )
        self.assertEqual(summary["result"], "failed")
        self.assertEqual(summary["unexpectedly_skipped"], ["supply_chain"])


if __name__ == "__main__":
    unittest.main()
