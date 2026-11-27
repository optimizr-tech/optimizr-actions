from datetime import date, timedelta
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts.config_lint.runner import load_policy, run_compose


class ConfigLintPolicyTests(unittest.TestCase):
    def write_policy(self, directory, policy):
        path = Path(directory) / "policy.json"
        path.write_text(json.dumps(policy), encoding="utf-8")
        return path

    def base_policy(self):
        return {
            "version": 1,
            "fail_on": ["error", "warning"],
            "exceptions": [],
            "compose": {},
        }

    def test_accepts_scoped_hadolint_exception_with_future_expiry(self):
        policy = self.base_policy()
        policy["exceptions"] = [{
            "rule": "hadolint:DL3008", "path": "Dockerfile",
            "reason": "legacy base image", "expires": (date.today() + timedelta(days=1)).isoformat(),
        }]
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(policy, load_policy(self.write_policy(directory, policy)))

    def test_rejects_expired_or_unjustified_exceptions(self):
        expired = self.base_policy()
        expired["exceptions"] = [{
            "rule": "privileged", "reason": "temporary", "expires": "2000-01-01",
        }]
        malformed = self.base_policy()
        malformed["exceptions"] = [{"rule": "privileged", "expires": "2099-01-01"}]
        for policy in (expired, malformed):
            with self.subTest(policy=policy), tempfile.TemporaryDirectory() as directory:
                with self.assertRaises(ValueError):
                    load_policy(self.write_policy(directory, policy))

    def test_rejects_unknown_compose_rules_and_severities(self):
        policy = self.base_policy()
        policy["compose"] = {"severities": {"unknown": "error"}}
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "compose.severities"):
                load_policy(self.write_policy(directory, policy))

    def test_compose_policy_reports_security_and_pinning_violations(self):
        policy = {
            "fail_on": ["error"],
            "exceptions": [],
            "compose": {
                "allowed_published_ports": [443],
                "require_read_only": ["api"],
                "require_cap_drop": ["api"],
            },
        }
        config = {"services": {
            "api": {
                "privileged": True,
                "network_mode": "host",
                "ports": [{"published": "8080"}],
                "image": "example/api:latest",
                "read_only": False,
                "cap_drop": [],
            }
        }}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            compose = root / "compose.yaml"
            compose.write_text("services: {}", encoding="utf-8")
            failures = []
            with patch("scripts.config_lint.runner.compose_config", return_value=config):
                run_compose(root, [compose], policy, failures)
        self.assertEqual(
            {"privileged", "host-network", "published-port", "image-digest", "read-only", "cap-drop"},
            {item["rule"] for item in failures},
        )


if __name__ == "__main__":
    unittest.main()
