from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
ACTION = ROOT / ".github/actions/validation-authorization/action.yml"
DOC = ROOT / "docs/VALIDATION_AUTHORIZATION.md"


class ValidationAuthorizationContractTests(unittest.TestCase):
    def test_action_declares_canonical_inputs_and_outputs(self):
        text = ACTION.read_text(encoding="utf-8")
        for name in (
            "gate_job_result",
            "gate_result",
            "validated_sha",
            "candidate_sha",
            "evidence_digest",
            "actions_workflow_sha",
            "validation_path",
            "candidate_ref",
            "required_ref",
            "allowed_paths_json",
        ):
            self.assertIn(f"  {name}:\n", text)
        self.assertIn("default: refs/heads/main", text)
        self.assertIn('default: \'["hosted","self-hosted","reviewed-emergency"]\'', text)
        for output in (
            "result",
            "validated_sha",
            "evidence_digest",
            "actions_workflow_sha",
            "validation_path",
        ):
            self.assertIn(f"  {output}:\n", text)

    def test_action_invokes_local_authorization_script_without_trust_expansion(self):
        text = ACTION.read_text(encoding="utf-8")
        self.assertIn("scripts/validation_authorization/authorize.py", text)
        self.assertIn('--github-output "$GITHUB_OUTPUT"', text)
        self.assertNotIn("actions/checkout", text)
        self.assertNotIn("curl ", text)
        self.assertNotIn("gh api", text)
        self.assertNotIn("skip-tests", text)
        self.assertNotIn("secrets.", text)

    def test_documentation_defines_digest_failure_and_consumer_migration(self):
        text = DOC.read_text(encoding="utf-8")
        self.assertIn("`sha256:<64 lowercase hex>`", text)
        self.assertIn("Monitoring PR #73", text)
        self.assertIn("needs.validation-gate.result", text)
        self.assertIn("does not interpret `[skip-tests]`", text)
        self.assertIn("Rollback", text)


if __name__ == "__main__":
    unittest.main()
