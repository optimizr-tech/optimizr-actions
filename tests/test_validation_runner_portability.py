import json
import os
from pathlib import Path
import re
import unittest
from unittest.mock import patch

import yaml

ROOT = Path(__file__).resolve().parents[1]


class ValidationRunnerPortabilityTests(unittest.TestCase):
    WORKFLOWS = (
        "_docker-compose-validate.yml",
        "_trivy-scan.yml",
        "_commitlint.yml",
        "_validate-pr.yml",
        "_python-uv-test.yml",
        "_node-project-test.yml",
        "_quality-gate-collect-security.yml",
        "_quality-gate-collect-dup.yml",
        "_quality-gate-baseline.yml",
        "_quality-gate-pr.yml",
        "_security-suite.yml",
        "_static-lint.yml",
        "_security-gate.yml",
        "_dependency-policy.yml",
        "_sast-gate.yml",
        "_supply-chain-evidence.yml",
    )

    def test_reusables_accept_governed_runner_selection(self):
        for name in self.WORKFLOWS:
            text = (ROOT / ".github/workflows" / name).read_text(encoding="utf-8")
            with self.subTest(workflow=name):
                self.assertIn("runner_json:", text)
                self.assertIn("self_hosted_mode:", text)
                self.assertIn("fromJSON(inputs.runner_json)", text)
                self.assertNotIn("runs-on: ubuntu-latest", text)

    def test_reusables_never_infer_billing_policy_from_skip_tests(self):
        for name in self.WORKFLOWS:
            text = (ROOT / ".github/workflows" / name).read_text(encoding="utf-8")
            with self.subTest(workflow=name):
                self.assertNotIn("[skip-tests]", text)
                self.assertNotIn("github.event.head_commit.message", text)

    def test_candidate_checkouts_are_explicitly_clean_and_verified(self):
        for name in (
            "_dependency-policy.yml",
            "_docker-compose-validate.yml",
            "_node-project-test.yml",
            "_quality-gate-collect-dup.yml",
            "_quality-gate-collect-security.yml",
            "_sast-gate.yml",
            "_security-gate.yml",
            "_static-lint.yml",
            "_supply-chain-evidence.yml",
        ):
            text = (ROOT / ".github/workflows" / name).read_text(encoding="utf-8")
            with self.subTest(workflow=name):
                self.assertIn("clean: true", text)
                self.assertIn("checkout-integrity@v1", text)

    def test_evidence_helper_checkout_happens_after_integrity_verification(self):
        validation_steps = {
            "_dependency-policy.yml": "Enforce dependency policy",
            "_sast-gate.yml": "Run local SAST profiles",
            "_security-gate.yml": "Run portable security gate",
            "_static-lint.yml": "Run portable static lint",
            "_supply-chain-evidence.yml": "Generate image evidence",
        }
        for name, validation_step in validation_steps.items():
            text = (ROOT / ".github/workflows" / name).read_text(encoding="utf-8")
            with self.subTest(workflow=name):
                verification = text.index("Verify checkout integrity")
                validation = text.index(validation_step)
                helper = text.index("Checkout reusable evidence helper")
                bundle = text.index("Write SHA-bound evidence bundle")
                self.assertLess(verification, validation)
                self.assertLess(validation, helper)
                self.assertLess(helper, bundle)

                helper_end = text.find("\n      - name:", helper)
                helper_block = text[helper:helper_end]
                self.assertRegex(
                    helper_block,
                    r"(?m)^\s+if:\s+always\(\)\s*$",
                )

    def test_matrix_reusables_require_materialized_paths_before_consuming_workspace(self):
        security = (
            ROOT / ".github/workflows/_quality-gate-collect-security.yml"
        ).read_text(encoding="utf-8")
        duplication = (
            ROOT / ".github/workflows/_quality-gate-collect-dup.yml"
        ).read_text(encoding="utf-8")

        self.assertIn("required_paths_json:", security)
        self.assertIn("required_paths_json: ${{ matrix.required_paths_json }}", security)
        self.assertIn("pyproject.toml", security)
        self.assertIn("required_paths_json:", duplication)
        self.assertIn("required_paths_json: ${{ matrix.required_paths_json }}", duplication)
        self.assertIn("matrix.paths", duplication)

    def test_pr_capable_workflows_require_ephemeral_self_hosted_runners(self):
        for name in (
            "_commitlint.yml",
            "_validate-pr.yml",
            "_node-project-test.yml",
            "_python-uv-test.yml",
            "_quality-gate-collect-security.yml",
            "_quality-gate-collect-dup.yml",
            "_quality-gate-pr.yml",
            "_security-suite.yml",
            "_static-lint.yml",
            "_security-gate.yml",
            "_dependency-policy.yml",
            "_sast-gate.yml",
            "_supply-chain-evidence.yml",
        ):
            text = (ROOT / ".github/workflows" / name).read_text(encoding="utf-8")
            with self.subTest(workflow=name):
                self.assertIn('"ephemeral" not in labels', text)
                self.assertIn('os.environ["EVENT_NAME"] != "pull_request"', text)

    def test_candidate_reusables_reject_persistent_trusted_pr_mode(self):
        workflows = (
            "_python-uv-test.yml",
            "_node-project-test.yml",
            "_security-suite.yml",
            "_static-lint.yml",
            "_security-gate.yml",
            "_dependency-policy.yml",
            "_sast-gate.yml",
            "_supply-chain-evidence.yml",
        )
        cases = (
            ("trusted-main", "push", "refs/heads/main", ["self-hosted", "Linux"], True),
            (
                "trusted-main",
                "workflow_dispatch",
                "refs/heads/main",
                ["self-hosted", "Linux"],
                True,
            ),
            (
                "trusted-main",
                "pull_request",
                "refs/pull/1/merge",
                ["self-hosted", "Linux"],
                False,
            ),
            (
                "trusted-pr",
                "pull_request",
                "refs/pull/1/merge",
                ["self-hosted", "Linux", "local-docker"],
                False,
            ),
            (
                "ephemeral-pr",
                "pull_request",
                "refs/pull/1/merge",
                ["self-hosted", "Linux", "ephemeral"],
                True,
            ),
            (
                "ephemeral-pr",
                "pull_request",
                "refs/pull/1/merge",
                ["self-hosted", "Linux", "local-docker"],
                False,
            ),
            (
                "ephemeral-pr",
                "push",
                "refs/heads/main",
                ["self-hosted", "Linux", "ephemeral"],
                False,
            ),
        )

        for name in workflows:
            path = ROOT / ".github/workflows" / name
            text = path.read_text(encoding="utf-8")
            with self.subTest(workflow=name):
                self.assertNotIn('mode == "trusted-pr"', text)
                self.assertNotIn("trusted-pr requires pull_request", text)

                workflow = yaml.safe_load(text)
                guards = []
                for job in workflow["jobs"].values():
                    if not isinstance(job, dict):
                        continue
                    for step in job.get("steps", []):
                        if step.get("name") != "Validate runner trust contract":
                            continue
                        match = re.fullmatch(
                            r"python3 - <<'PY'\n(?P<body>.*?)\nPY",
                            step["run"].strip(),
                            flags=re.DOTALL,
                        )
                        self.assertIsNotNone(match, name)
                        guards.append(match.group("body"))

                self.assertTrue(guards, f"{name} has no runner trust guard")
                for guard in guards:
                    for mode, event, ref, labels, expected in cases:
                        environment = {
                            "RUNNER_JSON": json.dumps(labels),
                            "SELF_HOSTED_MODE": mode,
                            "EVENT_NAME": event,
                            "EVENT_REF": ref,
                        }
                        with self.subTest(
                            workflow=name,
                            mode=mode,
                            event=event,
                            labels=labels,
                        ), patch.dict(os.environ, environment):
                            try:
                                exec(compile(guard, name, "exec"), {})
                            except SystemExit as exc:
                                accepted = exc.code in (None, 0)
                            else:
                                accepted = True
                            self.assertEqual(accepted, expected)

    def test_explicit_optional_skip_remains_caller_controlled(self):
        for name in (
            "_docker-compose-validate.yml",
            "_trivy-scan.yml",
            "_python-uv-test.yml",
        ):
            text = (ROOT / ".github/workflows" / name).read_text(encoding="utf-8")
            with self.subTest(workflow=name):
                self.assertIn("!inputs.skip", text)

    def test_python_uv_uses_actions_owned_composite(self):
        text = (ROOT / ".github/workflows/_python-uv-test.yml").read_text(encoding="utf-8")
        self.assertNotIn(
            "optimizr-infra-ops/.github/actions/python-uv-test-steps",
            text,
        )
        self.assertEqual(
            text.count(
                "optimizr-tech/optimizr-actions/.github/actions/"
                "python-uv-test-steps@v1"
            ),
            4,
        )

    def test_rabbitmq_service_avoids_deprecated_memory_environment(self):
        text = (ROOT / ".github/workflows/_python-uv-test.yml").read_text(encoding="utf-8")
        self.assertIn("--memory 1g", text)
        self.assertNotIn("RABBITMQ_VM_MEMORY_HIGH_WATERMARK", text)

    def test_serve_integration_services_match_runtime_pins(self):
        text = (ROOT / ".github/workflows/_python-uv-test.yml").read_text(encoding="utf-8")
        for image in (
            "postgres:16.14-alpine@sha256:e013e867e712fec275706a6c51c966f0bb0c93cfa8f51000f85a15f9865a28cb",
            "redis:7.4.9-alpine@sha256:b1addbe72465a718643cff9e60a58e6df1841e29d6d7d60c9a85d8d72f08d1a7",
            "rabbitmq:4.2.9-management-alpine@sha256:a51ed990cb4392ce136380fb01fdb8aab1203565953f5ea9711bf839b1b709db",
        ):
            with self.subTest(image=image):
                self.assertIn(image, text)


if __name__ == "__main__":
    unittest.main()
