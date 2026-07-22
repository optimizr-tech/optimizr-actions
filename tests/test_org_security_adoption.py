from __future__ import annotations

import unittest

from scripts.org_audit.combined import audit_security_adoption


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


if __name__ == "__main__":
    unittest.main()
