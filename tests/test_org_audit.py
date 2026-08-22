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
  validate:
    runs-on: [self-hosted, Linux, prod]
    uses: optimizr-tech/optimizr-actions/.github/workflows/_repository-validation.yml@v1
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
            "SELF_HOSTED_PR_WITHOUT_GOVERNED_MODE",
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

    def test_reports_prohibited_caller_level_skip_guard(self):
        guard = """
    if: >-
      github.event_name != 'pull_request' ||
      !contains(github.event.pull_request.title, '[skip-tests]')
"""
        workflows = {
            ".github/workflows/commitlint.yml": f"""
on:
  pull_request:
jobs:
  commitlint:
{guard}
    uses: optimizr-tech/optimizr-actions/.github/workflows/_commitlint.yml@v1
""",
            ".github/workflows/validate-pr.yml": f"""
on:
  pull_request:
jobs:
  validate-pr:
{guard}
    uses: optimizr-tech/optimizr-actions/.github/workflows/_validate-pr.yml@v1
""",
        }

        findings = audit_workflows(
            "optimizr-tech/example", "private", workflows
        )

        self.assertEqual(
            2,
            sum(
                finding.rule_id == "PR_BILLING_SKIP_GUARD"
                for finding in findings
            ),
        )

    def test_reports_hosted_pr_code_validation_when_repo_has_self_hosted(self):
        workflows = {
            ".github/workflows/test.yml": """
on:
  pull_request:
jobs:
  root:
    if: >-
      !contains(github.event.pull_request.title, '[skip-tests]')
    uses: optimizr-tech/optimizr-actions/.github/workflows/_docker-compose-validate.yml@v1
  dependent:
    needs: root
    runs-on: ubuntu-latest
    steps:
      - run: echo validate
""",
            ".github/workflows/deploy.yml": """
on:
  push:
    branches: [main]
jobs:
  deploy:
    runs-on: [self-hosted, Linux, prod]
    uses: optimizr-tech/optimizr-actions/.github/workflows/_vps-self-hosted-deploy.yml@v1
""",
        }

        findings = audit_workflows(
            "optimizr-tech/example", "private", workflows
        )

        self.assertEqual(
            ["root", "dependent"],
            [
                finding.message.split("job `", 1)[1].split("`", 1)[0]
                for finding in findings
                if finding.rule_id == "HOSTED_PR_CODE_VALIDATION"
            ],
        )
        self.assertIn(
            "PR_BILLING_SKIP_GUARD",
            {finding.rule_id for finding in findings},
        )

    def test_accepts_own_jobs_and_hosted_switch_on_governed_runners(self):
        workflows = {
            ".github/workflows/observability-contracts.yml": """
on:
  pull_request:
jobs:
  contracts:
    runs-on: [self-hosted, Linux, corp-docs]
    steps:
      - run: echo contract check
""",
            ".github/workflows/node-validation.yml": """
on:
  pull_request:
jobs:
  node:
    uses: optimizr-tech/optimizr-actions/.github/workflows/_python-uv-test.yml@v1
    with:
      runner_json: ${{ github.event_name == 'pull_request' && '["ubuntu-latest"]' || '["self-hosted","Linux","corp-docs"]' }}
      self_hosted_mode: ${{ github.event_name == 'pull_request' && 'none' || 'trusted-main' }}
""",
        }

        findings = audit_workflows(
            "optimizr-tech/corp-docs", "private", workflows
        )
        rules = {finding.rule_id for finding in findings}

        self.assertNotIn("SELF_HOSTED_PR_WITHOUT_GOVERNED_MODE", rules)

    def test_accepts_hosted_reusable_pr_checks_when_repo_has_no_self_hosted(self):
        workflows = {
            ".github/workflows/commitlint.yml": """
on:
  pull_request:
jobs:
  commitlint:
    uses: optimizr-tech/optimizr-actions/.github/workflows/_commitlint.yml@v1
""",
            ".github/workflows/validate-pr.yml": """
on:
  pull_request:
jobs:
  validate-pr:
    uses: optimizr-tech/optimizr-actions/.github/workflows/_validate-pr.yml@v1
""",
        }

        findings = audit_workflows(
            "optimizr-tech/example", "private", workflows
        )

        self.assertNotIn(
            "HOSTED_PR_CODE_VALIDATION",
            {finding.rule_id for finding in findings},
        )
        self.assertNotIn(
            "PR_BILLING_SKIP_GUARD",
            {finding.rule_id for finding in findings},
        )

    def test_accepts_governed_persistent_pr_reusable_callers(self):
        workflows = {
            ".github/workflows/commitlint.yml": """
on:
  pull_request:
jobs:
  commitlint:
    uses: optimizr-tech/optimizr-actions/.github/workflows/_commitlint.yml@v1
    with:
      runner_json: '["self-hosted", "Linux", "monitoring"]'
      self_hosted_mode: trusted-pr
""",
            ".github/workflows/validate-pr.yml": """
on:
  pull_request:
jobs:
  validate-pr:
    uses: optimizr-tech/optimizr-actions/.github/workflows/_validate-pr.yml@v1
    with:
      runner_json: '["self-hosted", "Linux", "monitoring"]'
      self_hosted_mode: trusted-pr
""",
        }

        findings = audit_workflows(
            "optimizr-tech/monitoring", "private", workflows
        )
        rules = {finding.rule_id for finding in findings}

        self.assertNotIn("HOSTED_PR_CODE_VALIDATION", rules)
        self.assertNotIn("SELF_HOSTED_PR_WITHOUT_GOVERNED_MODE", rules)

    def test_accepts_metadata_reusable_callers_as_canonical_pr_checks(self):
        workflows = {
            ".github/workflows/commitlint.yml": """
on:
  pull_request:
jobs:
  commitlint:
    uses: optimizr-tech/optimizr-actions/.github/workflows/_pr-metadata.yml@v1
    with:
      runner_json: '["self-hosted", "Linux", "monitoring"]'
      self_hosted_mode: metadata-pr
""",
            ".github/workflows/validate-pr.yml": """
on:
  pull_request:
jobs:
  validate-pr:
    uses: optimizr-tech/optimizr-actions/.github/workflows/_pr-metadata.yml@v1
    with:
      runner_json: '["self-hosted", "Linux", "monitoring"]'
      self_hosted_mode: metadata-pr
""",
        }

        findings = audit_workflows(
            "optimizr-tech/monitoring", "private", workflows
        )
        rules = {finding.rule_id for finding in findings}

        self.assertNotIn("DUPLICATED_COMMITLINT_WORKFLOW", rules)
        self.assertNotIn("DUPLICATED_PR_VALIDATION", rules)
        self.assertNotIn("HOSTED_PR_CODE_VALIDATION", rules)
        self.assertNotIn("SELF_HOSTED_PR_WITHOUT_GOVERNED_MODE", rules)

    def test_accepts_dynamic_governed_mode_expressions(self):
        workflows = {
            ".github/workflows/node-validation.yml": """
on:
  pull_request:
jobs:
  node:
    uses: optimizr-tech/optimizr-actions/.github/workflows/_node-project-test.yml@v1
    with:
      runner_json: ${{ github.event_name == 'pull_request' && '["self-hosted","Linux","monitoring","ephemeral"]' || '["self-hosted","Linux","monitoring"]' }}
      self_hosted_mode: ${{ github.event_name == 'pull_request' && 'ephemeral-pr' || 'trusted-main' }}
""",
            ".github/workflows/deploy.yml": """
on:
  push:
    branches: [main]
jobs:
  deploy:
    runs-on: [self-hosted, Linux, monitoring]
    uses: optimizr-tech/optimizr-actions/.github/workflows/_vps-self-hosted-deploy.yml@v1
""",
        }

        findings = audit_workflows(
            "optimizr-tech/monitoring", "private", workflows
        )
        self.assertNotIn(
            "SELF_HOSTED_PR_WITHOUT_GOVERNED_MODE",
            {finding.rule_id for finding in findings},
        )

    def test_accepts_dependabot_metadata_caller_on_self_hosted_repo(self):
        workflows = {
            ".github/workflows/dependabot-automerge.yml": """
on:
  pull_request:
jobs:
  automerge:
    uses: optimizr-tech/optimizr-actions/.github/workflows/_dependabot-security-automerge.yml@v1
""",
            ".github/workflows/deploy.yml": """
on:
  push:
    branches: [main]
jobs:
  deploy:
    runs-on: [self-hosted, Linux, monitoring]
    uses: optimizr-tech/optimizr-actions/.github/workflows/_vps-self-hosted-deploy.yml@v1
""",
        }

        findings = audit_workflows(
            "optimizr-tech/monitoring", "private", workflows
        )
        self.assertNotIn(
            "HOSTED_PR_CODE_VALIDATION",
            {finding.rule_id for finding in findings},
        )

    def test_allows_metadata_only_pr_workflow_without_path_filter(self):
        workflows = {
            ".github/workflows/ci.yml": """
on:
  pull_request:
jobs:
  metadata:
    uses: optimizr-tech/optimizr-actions/.github/workflows/_pr-metadata.yml@v1
    with:
      runner_json: '["self-hosted", "Linux", "cdn"]'
      self_hosted_mode: metadata-pr
""",
        }

        findings = audit_workflows(
            "optimizr-tech/cdn", "private", workflows
        )
        self.assertNotIn(
            "MISSING_PATH_FILTER",
            {finding.rule_id for finding in findings},
        )


if __name__ == "__main__":
    unittest.main()
