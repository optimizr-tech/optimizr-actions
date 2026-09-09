import json
import unittest

from scripts.testsprite.validate_target import ContractError, validate_contract


class TestSpriteTargetContractTests(unittest.TestCase):
    def valid_kwargs(self) -> dict[str, str]:
        return {
            "base_url": "https://service-testsprite.example.com/preview",
            "expected_base_url": "https://service-testsprite.example.com/preview",
            "environment_name": "staging-testsprite",
            "runner_json": json.dumps(["self-hosted", "Linux", "service"]),
            "forbidden_hosts_json": json.dumps(["service.example.com"]),
            "event_name": "workflow_dispatch",
            "ref": "refs/heads/main",
            "suite_path": "testsprite_tests",
        }

    def test_accepts_trusted_non_production_contract(self) -> None:
        validate_contract(**self.valid_kwargs())

    def test_rejects_pull_request_execution(self) -> None:
        values = self.valid_kwargs()
        values["event_name"] = "pull_request"
        with self.assertRaisesRegex(ContractError, "trusted main"):
            validate_contract(**values)

    def test_rejects_production_environment(self) -> None:
        values = self.valid_kwargs()
        values["environment_name"] = "production-testsprite"
        with self.assertRaisesRegex(ContractError, "production"):
            validate_contract(**values)

    def test_rejects_non_https_or_unexpected_target(self) -> None:
        values = self.valid_kwargs()
        values["base_url"] = "http://service-testsprite.example.com/preview"
        with self.assertRaisesRegex(ContractError, "HTTPS"):
            validate_contract(**values)

        values = self.valid_kwargs()
        values["expected_base_url"] = "https://another.example.com/preview"
        with self.assertRaisesRegex(ContractError, "exactly"):
            validate_contract(**values)

    def test_rejects_local_or_forbidden_targets(self) -> None:
        values = self.valid_kwargs()
        values["base_url"] = values["expected_base_url"] = "https://localhost/preview"
        with self.assertRaisesRegex(ContractError, "local"):
            validate_contract(**values)

        values = self.valid_kwargs()
        values["base_url"] = values["expected_base_url"] = "https://service.example.com"
        with self.assertRaisesRegex(ContractError, "forbidden"):
            validate_contract(**values)

    def test_requires_self_hosted_linux_runner(self) -> None:
        values = self.valid_kwargs()
        values["runner_json"] = json.dumps(["ubuntu-latest"])
        with self.assertRaisesRegex(ContractError, "self-hosted and Linux"):
            validate_contract(**values)

    def test_rejects_suite_path_traversal(self) -> None:
        values = self.valid_kwargs()
        values["suite_path"] = "../testsprite_tests"
        with self.assertRaisesRegex(ContractError, "traversal"):
            validate_contract(**values)


if __name__ == "__main__":
    unittest.main()
