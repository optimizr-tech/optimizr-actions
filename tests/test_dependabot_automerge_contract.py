from __future__ import annotations

from pathlib import Path
import json
import os
import subprocess
import sys
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
REUSABLE = ROOT / ".github" / "workflows" / "_dependabot-security-automerge.yml"
TEMPLATE = ROOT / "templates" / "workflows" / "dependabot-security-automerge.yml"


class DependabotAutomergeContractTests(unittest.TestCase):
    def test_reusable_enables_only_native_patch_or_opted_in_minor_automerge(self) -> None:
        content = REUSABLE.read_text(encoding="utf-8")

        self.assertIn("github.event.pull_request.user.login == 'dependabot[bot]'", content)
        self.assertIn(
            "dependabot/fetch-metadata@25dd0e34f4fe68f24cc83900b1fe3fe149efef98",
            content,
        )
        self.assertIn("version-update:semver-patch", content)
        self.assertIn("version-update:semver-minor", content)
        self.assertIn("inputs.allow_minor", content)
        self.assertIn('gh pr merge --auto --squash "$PR_URL"', content)
        self.assertNotIn("gh pr review --approve", content)
        self.assertNotIn("actions/checkout", content)
        self.assertNotIn("secrets: inherit", content)
        self.assertIn("runs-on: ${{ fromJSON(inputs.runner_json) }}", content)

    def test_consumer_template_uses_base_context_without_pr_code(self) -> None:
        content = TEMPLATE.read_text(encoding="utf-8")

        self.assertIn("pull_request_target:", content)
        self.assertIn("types: [opened, synchronize, reopened]", content)
        self.assertIn(
            "optimizr-tech/optimizr-actions/.github/workflows/"
            "_dependabot-security-automerge.yml@v1",
            content,
        )
        self.assertNotIn("actions/checkout", content)
        self.assertNotIn("secrets: inherit", content)


class DependabotRunnerTrustTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = yaml.safe_load(REUSABLE.read_text(encoding="utf-8"))
        cls.steps = cls.workflow["jobs"]["enable-automerge"]["steps"]
        cls.guard = cls.steps[0]["run"].split("python3 - <<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]

    def run_guard(self, selector: object, mode: str = "metadata-pr", event: str = "pull_request_target") -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, "-c", self.guard],
            env={**os.environ, "RUNNER_JSON": json.dumps(selector),
                 "SELF_HOSTED_MODE": mode, "EVENT_NAME": event},
            capture_output=True, text=True, check=False,
        )

    def test_existing_callers_keep_defaults_and_permissions(self) -> None:
        inputs = self.workflow[True]["workflow_call"]["inputs"]
        self.assertEqual('["ubuntu-latest"]', inputs["runner_json"]["default"])
        self.assertEqual("none", inputs["self_hosted_mode"]["default"])
        self.assertFalse(inputs["allow_minor"]["default"])
        self.assertEqual({"contents": "write", "pull-requests": "write"}, self.workflow["permissions"])
        self.assertEqual(0, self.run_guard(["ubuntu-latest"], "none").returncode)

    def test_group_scoped_metadata_is_accepted_before_pinned_action(self) -> None:
        selector = {"group": "authorized-metadata", "labels": ["self-hosted", "Linux", "metadata"]}
        result = self.run_guard(selector)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("Validate auto-merge runner trust contract", self.steps[0]["name"])
        self.assertIn("dependabot/fetch-metadata@", self.steps[1]["uses"])

    def test_invalid_selectors_modes_and_events_fail_closed(self) -> None:
        valid = {"group": "authorized-metadata", "labels": ["self-hosted", "Linux"]}
        invalid_selectors = [
            None, "ubuntu-latest", [], ["self-hosted", "Linux"], ["windows-latest"],
            {}, {**valid, "extra": True}, {**valid, "group": ""},
            {**valid, "group": " metadata "}, {**valid, "group": 1},
            {**valid, "labels": "self-hosted"}, {**valid, "labels": []},
            {**valid, "labels": ["Linux"]}, {**valid, "labels": ["self-hosted"]},
            {**valid, "labels": ["self-hosted", "Linux", 1]},
            {**valid, "labels": ["self-hosted", "Linux", " "]},
        ]
        for selector in invalid_selectors:
            with self.subTest(selector=selector):
                self.assertNotEqual(0, self.run_guard(selector).returncode)
        for mode in ["none", "trusted-main", "trusted-pr", "ephemeral-pr", ""]:
            with self.subTest(mode=mode):
                self.assertNotEqual(0, self.run_guard(valid, mode).returncode)
        for event in ["pull_request", "push", "workflow_dispatch", "workflow_run"]:
            with self.subTest(event=event):
                self.assertNotEqual(0, self.run_guard(valid, event=event).returncode)
        self.assertNotEqual(0, self.run_guard(["ubuntu-latest"]).returncode)


if __name__ == "__main__":
    unittest.main()
