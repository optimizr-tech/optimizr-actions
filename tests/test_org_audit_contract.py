from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class OrgAuditContractTests(unittest.TestCase):
    def test_private_issue_update_requires_reports_and_uploaded_public_artifact(self):
        text = (ROOT / ".github/workflows/org-adoption-audit.yml").read_text()
        public_job = text.split("  public-report:\n", 1)[1].split(
            "\n  private-issue-report:", 1
        )[0]
        issue_job = text.split("  private-issue-report:\n", 1)[1]
        public_config = public_job.split(
            "- name: Validate public audit configuration\n", 1
        )[1].split("- name: Audit selected repositories", 1)[0]
        report_validation = public_job.split(
            "- name: Validate generated public audit reports\n", 1
        )[1].split("- name: Upload redacted public report\n", 1)[0]
        upload = public_job.split("- name: Upload redacted public report\n", 1)[1].split(
            "- name: Verify public audit artifact upload\n", 1
        )[0]
        artifact_validation = public_job.split(
            "- name: Verify public audit artifact upload\n", 1
        )[1]
        private_config = issue_job.split(
            "- name: Validate private audit configuration\n", 1
        )[1].split("- name: Update private issue\n", 1)[0]

        self.assertIn("ORG_AUDIT_REPOSITORIES//[[:space:],]/", public_config)
        self.assertIn("ORG_AUDIT_TOKEN//[[:space:]]/", public_config)
        self.assertLess(
            public_job.index("Validate public audit configuration"),
            public_job.index("Audit selected repositories"),
        )
        self.assertIn("id: audit", public_job)
        self.assertIn("if: success()", report_validation)
        self.assertIn("test -s public-report/report.json", report_validation)
        self.assertIn("test -s public-report/report.md", report_validation)
        self.assertIn("id: upload_public_report", upload)
        self.assertIn("if: always()", upload)
        self.assertIn("if-no-files-found: error", upload)
        self.assertIn("public-report/report.json", upload)
        self.assertIn("public-report/report.md", upload)
        self.assertIn("actions/upload-artifact@", upload)
        self.assertIn("if: always()", artifact_validation)
        self.assertIn(
            "ARTIFACT_ID: ${{ steps.upload_public_report.outputs.artifact-id }}",
            artifact_validation,
        )
        self.assertIn(
            "ARTIFACT_DIGEST: ${{ steps.upload_public_report.outputs.artifact-digest }}",
            artifact_validation,
        )
        self.assertIn("test -n \"$ARTIFACT_ID\"", artifact_validation)
        self.assertIn("test -n \"$ARTIFACT_DIGEST\"", artifact_validation)
        self.assertNotIn("continue-on-error: true", public_job)
        self.assertLess(
            public_job.index("Validate generated public audit reports"),
            public_job.index("Upload redacted public report"),
        )
        self.assertLess(
            public_job.index("Upload redacted public report"),
            public_job.index("Verify public audit artifact upload"),
        )
        self.assertIn("needs: [public-report]", issue_job)
        self.assertIn("if: needs.public-report.result == 'success'", issue_job)
        self.assertIn("ORG_AUDIT_REPOSITORIES//[[:space:],]/", private_config)
        self.assertIn("ORG_AUDIT_TOKEN//[[:space:]]/", private_config)
        self.assertIn("ORG_AUDIT_ISSUE_REF//[[:space:]]/", private_config)
        self.assertIn("ORG_AUDIT_ISSUE_TOKEN//[[:space:]]/", private_config)
        self.assertIn("--issue-ref-env ORG_AUDIT_ISSUE_REF", issue_job)
        self.assertIn("--issue-token-env ORG_AUDIT_ISSUE_TOKEN", issue_job)

    def test_public_job_is_read_only_hosted_and_uploads_only_public_report(self):
        text = (ROOT / ".github/workflows/org-adoption-audit.yml").read_text()
        self.assertIn("schedule:", text)
        self.assertIn("workflow_dispatch:", text)
        self.assertIn("runs-on: ubuntu-latest", text)
        self.assertIn("permissions:\n  contents: read", text)
        self.assertIn("ORG_AUDIT_REPOSITORIES", text)
        self.assertIn("ORG_AUDIT_TOKEN", text)
        self.assertIn("--public", text)
        self.assertIn("public-report", text)
        self.assertRegex(
            text,
            r"private-issue-report:\n    name: .*\n"
            r"    needs: \[public-report\]\n"
            r"    if: needs\.public-report\.result == 'success'",
        )
        self.assertIn("ORG_AUDIT_RUN_URL", text)
        self.assertIn("--run-url-env ORG_AUDIT_RUN_URL", text)
        self.assertIn("Validate public audit configuration", text)
        self.assertIn("Validate private audit configuration", text)
        self.assertIn('ORG_AUDIT_ISSUE_REF is not configured', text)
        self.assertIn('ORG_AUDIT_ISSUE_TOKEN is not configured', text)
        self.assertNotIn("Update private issue when configured", text)
        self.assertNotIn("if: env.ORG_AUDIT_ISSUE_REF != ''", text)
        self.assertIn("actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1", text)
        self.assertIn("actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a", text)
        self.assertNotIn("git clone", text)


if __name__ == "__main__":
    unittest.main()
