import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from org_audit.audit import Finding, audit_workflows, public_alias, render_markdown, render_json, update_marked_section


class OrgAuditTests(unittest.TestCase):
    def test_detects_legacy_refs_temp_sha_unpinned_actions_permissions_paths_and_self_hosted_pr(self):
        workflows = {
            ".github/workflows/ci.yml": """
name: CI
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
permissions:
  contents: write
  actions: write
jobs:
  test:
    runs-on: [self-hosted, Linux, prod]
    steps:
      - uses: actions/checkout@main
      - uses: optimizr-tech/optimizr-infra-ops/.github/workflows/_trivy-scan.yml@v1
      - uses: optimizr-tech/optimizr-actions/.github/workflows/_semantic-release.yml@7925034d32f769326a45f6af155c95dac6aefc55
""",
            ".github/workflows/update-badges.yml": """
on: [workflow_dispatch]
jobs:
  badge:
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd
      - uses: optimizr-tech/optimizr-actions/.github/actions/update-release-badge@v1
""",
        }
        findings = audit_workflows("optimizr-tech/private-repo", "private", workflows)
        rules = {finding.rule_id for finding in findings}
        self.assertTrue({
            "LEGACY_INFRA_OPS_REUSABLE",
            "TEMPORARY_ACTIONS_SHA",
            "INTERNAL_REF_NOT_V1",
            "UNPINNED_THIRD_PARTY_ACTION",
            "BROAD_WORKFLOW_PERMISSION",
            "MISSING_PATH_FILTER",
            "SELF_HOSTED_PULL_REQUEST",
            "DUPLICATED_BADGE_WORKFLOW",
        }.issubset(rules))

    def test_public_report_hashes_private_names_and_never_contains_workflow_content(self):
        secret_name = "optimizr-tech/very-private-service"
        alias = public_alias(secret_name, "private")
        self.assertTrue(alias.startswith("private-"))
        finding = Finding(secret_name, "private", ".github/workflows/ci.yml", "RULE", "sanitized message")
        payload = render_json([finding], public=True)
        serialized = json.dumps(payload)
        self.assertNotIn(secret_name, serialized)
        self.assertIn(alias, serialized)
        self.assertNotIn("password", serialized.lower())
        markdown = render_markdown([finding], public=True)
        self.assertNotIn(secret_name, markdown)
        self.assertIn(alias, markdown)

    def test_marked_issue_section_is_idempotent(self):
        body = "Before\n<!-- optimizr-actions-audit:start -->\nold\n<!-- optimizr-actions-audit:end -->\nAfter\n"
        updated = update_marked_section(body, "new report")
        self.assertIn("new report", updated)
        self.assertNotIn("old", updated)
        self.assertEqual(update_marked_section(updated, "new report"), updated)


if __name__ == "__main__":
    unittest.main()
