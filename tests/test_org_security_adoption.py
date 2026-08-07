from __future__ import annotations

from pathlib import Path
import subprocess
import sys
import unittest

from scripts.org_audit.combined import audit_functional_duplication
from scripts.org_audit.combined import audit_security_adoption


ROOT = Path(__file__).resolve().parents[1]


class OrgSecurityAdoptionTests(unittest.TestCase):
    def test_reports_missing_dependabot_and_canonical_deploy_adoption(self) -> None:
        workflows = {
            ".github/workflows/deploy.yml": """
on:
  push:
jobs:
  deploy:
    runs-on: self-hosted
    steps:
      - run: docker compose up -d
"""
        }

        findings = audit_security_adoption(
            "optimizr-tech/example", "private", workflows, dependabot_config=None
        )
        rules = {finding.rule_id for finding in findings}

        self.assertEqual(
            {
                "MISSING_DEPENDABOT_CONFIG",
                "MISSING_DEPENDABOT_AUTOMERGE",
                "MISSING_CANONICAL_DEPLOY",
            },
            rules,
        )

    def test_accepts_governed_dependabot_and_deploy_callers(self) -> None:
        workflows = {
            ".github/workflows/deploy.yml": """
jobs:
  deploy:
    uses: optimizr-tech/optimizr-actions/.github/workflows/_vps-self-hosted-deploy.yml@v1
""",
            ".github/workflows/dependabot-security-automerge.yml": """
jobs:
  automerge:
    uses: optimizr-tech/optimizr-actions/.github/workflows/_dependabot-security-automerge.yml@v1
""",
        }
        dependabot = "version: 2\nupdates: []\n"

        findings = audit_security_adoption(
            "optimizr-tech/example", "private", workflows, dependabot
        )

        self.assertEqual([], findings)

    def test_combined_audit_entrypoint_imports_from_repository_root(self) -> None:
        completed = subprocess.run(
            [sys.executable, "scripts/org_audit/combined.py", "--help"],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )

        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertIn("--repositories-env", completed.stdout)


class OrgFunctionalDuplicationTests(unittest.TestCase):
    def test_reports_local_reimplementation_when_canonical_reusable_is_absent(self) -> None:
        workflows = {
            ".github/workflows/ci.yml": """
on:
  push:
jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - run: docker compose config
      - run: trivy fs --exit-code 1 .
      - run: shellcheck scripts/*.sh
      - run: uv run pytest --cov
"""
        }

        findings = audit_functional_duplication(
            "optimizr-tech/example", "private", workflows, catalog=None
        )
        rules = {finding.rule_id for finding in findings}

        self.assertEqual(
            {
                "LOCAL_COMPOSE_VALIDATION",
                "DUPLICATED_SECURITY_SCAN",
                "DUPLICATED_STATIC_LINT",
                "DUPLICATED_PYTHON_TEST_RUNNER",
            },
            rules,
        )

    def test_accepts_local_tools_when_canonical_reusable_is_called(self) -> None:
        workflows = {
            ".github/workflows/ci.yml": """
on:
  push:
jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - run: docker compose config
      - run: trivy fs --exit-code 1 .
      - run: shellcheck scripts/*.sh
      - run: uv run pytest --cov
""",
            ".github/workflows/reusable.yml": """
jobs:
  gate:
    uses: optimizr-tech/optimizr-actions/.github/workflows/_docker-compose-validate.yml@v1
    with:
      workspace: .
  security:
    uses: optimizr-tech/optimizr-actions/.github/workflows/_security-gate.yml@v1
  lint:
    uses: optimizr-tech/optimizr-actions/.github/workflows/_static-lint.yml@v1
  python:
    uses: optimizr-tech/optimizr-actions/.github/workflows/_python-uv-test.yml@v1
""",
        }

        findings = audit_functional_duplication(
            "optimizr-tech/example", "private", workflows, catalog=None
        )

        self.assertEqual([], findings)

    def test_reports_skip_tests_without_equivalent_validation(self) -> None:
        workflows = {
            ".github/workflows/ci.yml": """
on:
  pull_request:
jobs:
  validate:
    runs-on: ubuntu-latest
    if: "! contains(github.event.pull_request.title, '[skip-tests]')"
    steps:
      - run: echo validating
"""
        }

        findings = audit_functional_duplication(
            "optimizr-tech/example", "private", workflows, catalog=None
        )
        rules = {finding.rule_id for finding in findings}

        self.assertIn("SKIP_TESTS_WITHOUT_EQUIVALENT", rules)

    def test_accepts_skip_tests_when_self_hosted_equivalent_is_called(self) -> None:
        workflows = {
            ".github/workflows/ci.yml": """
on:
  pull_request:
jobs:
  validate:
    runs-on: ubuntu-latest
    if: "! contains(github.event.pull_request.title, '[skip-tests]')"
    uses: optimizr-tech/optimizr-actions/.github/workflows/_repository-validation.yml@v1
  emergency:
    runs-on: self-hosted
    uses: optimizr-tech/optimizr-actions/.github/workflows/_validation-gate.yml@v1
"""
        }

        findings = audit_functional_duplication(
            "optimizr-tech/example", "private", workflows, catalog=None
        )

        self.assertEqual([], findings)

    def test_reports_permanent_skip_on_mandatory_validation(self) -> None:
        workflows = {
            ".github/workflows/validate.yml": """
jobs:
  gate:
    uses: optimizr-tech/optimizr-actions/.github/workflows/_repository-validation.yml@v1
    with:
      skip: "true"
"""
        }

        findings = audit_functional_duplication(
            "optimizr-tech/example", "private", workflows, catalog=None
        )
        rules = {finding.rule_id for finding in findings}

        self.assertIn("PERMANENT_SKIP_IN_MANDATORY_VALIDATION", rules)

    def test_reports_hosted_only_call_of_self_hosted_capable_reusable(self) -> None:
        catalog = {
            "artifacts": [
                {
                    "path": ".github/workflows/_repository-validation.yml",
                    "runner": [
                        "hosted",
                        "self-hosted-persistent",
                        "self-hosted-ephemeral",
                    ],
                }
            ]
        }
        workflows = {
            ".github/workflows/ci.yml": """
jobs:
  gate:
    runs-on: ubuntu-latest
    uses: optimizr-tech/optimizr-actions/.github/workflows/_repository-validation.yml@v1
  deploy:
    runs-on: self-hosted
    steps:
      - run: echo deploying
"""
        }

        findings = audit_functional_duplication(
            "optimizr-tech/example", "private", workflows, catalog
        )
        rules = {finding.rule_id for finding in findings}

        self.assertIn("HOSTED_ONLY_REUSABLE", rules)

    def test_reports_clone_script_execution_instead_of_reusable(self) -> None:
        workflows = {
            ".github/workflows/ci.yml": """
jobs:
  validate:
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd
      - name: Checkout actions
        uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd
        with:
          repository: optimizr-tech/optimizr-actions
          path: optimizr-actions
      - run: python3 optimizr-actions/scripts/security_gate/aggregate.py
"""
        }

        findings = audit_functional_duplication(
            "optimizr-tech/example", "private", workflows, catalog=None
        )
        rules = {finding.rule_id for finding in findings}

        self.assertIn("ACTIONS_CLONE_SCRIPT_EXECUTION", rules)


if __name__ == "__main__":
    unittest.main()
