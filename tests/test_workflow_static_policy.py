"""Regression checks for executable workflow policy."""

from __future__ import annotations

import json
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


class WorkflowStaticPolicyTests(unittest.TestCase):
    def test_canonical_release_commit_uses_org_allowlisted_gitmoji(self) -> None:
        config = json.loads(read("templates/.releaserc.json"))
        git_plugin = next(
            options
            for plugin, options in config["plugins"]
            if plugin == "@semantic-release/git"
        )
        message = git_plugin["message"]
        subject, notes_template = message.split("\n\n", 1)

        self.assertEqual(
            subject,
            ":bookmark_tabs: chore(release): ${nextRelease.version} [skip ci]",
        )
        self.assertEqual(notes_template, "${nextRelease.notes}")
        self.assertNotIn("\\n", message)
        self.assertLessEqual(len(subject.replace("${nextRelease.version}", "1.2.3")), 72)

    def test_v1_pr_workflows_preserve_legacy_caller_contract(self) -> None:
        commitlint = read(".github/workflows/_commitlint.yml")
        validate_pr = read(".github/workflows/_validate-pr.yml")

        for workflow in (commitlint, validate_pr):
            self.assertIn("INPUT_BASE_SHA: ${{ inputs.base_sha }}", workflow)
            self.assertIn(
                "EVENT_BASE_SHA: ${{ github.event.pull_request.base.sha }}",
                workflow,
            )
            self.assertIn('BASE_SHA="${INPUT_BASE_SHA:-$EVENT_BASE_SHA}"', workflow)
            self.assertIn("INPUT_HEAD_SHA: ${{ inputs.head_sha }}", workflow)
            self.assertIn(
                "EVENT_HEAD_SHA: ${{ github.event.pull_request.head.sha }}",
                workflow,
            )
            self.assertIn('HEAD_SHA="${INPUT_HEAD_SHA:-$EVENT_HEAD_SHA}"', workflow)

        self.assertIn("EVENT_PR_TITLE: ${{ github.event.pull_request.title }}", validate_pr)
        self.assertIn('PR_TITLE="${INPUT_PR_TITLE:-$EVENT_PR_TITLE}"', validate_pr)

    def test_v1_pr_workflow_compatibility_inputs_are_optional(self) -> None:
        commitlint = read(".github/workflows/_commitlint.yml")
        validate_pr = read(".github/workflows/_validate-pr.yml")

        for workflow in (commitlint, validate_pr):
            for input_name in ("base_sha", "head_sha"):
                match = re.search(
                    rf"^      {input_name}:\n(?P<body>(?:        .*\n)+)",
                    workflow,
                    re.MULTILINE,
                )
                self.assertIsNotNone(match)
                input_block = match.group("body")
                self.assertIn("required: false", input_block)
                self.assertIn('default: ""', input_block)

        title_match = re.search(
            r"^      pr_title:\n(?P<body>(?:        .*\n)+)",
            validate_pr,
            re.MULTILINE,
        )
        self.assertIsNotNone(title_match)
        title_block = title_match.group("body")
        self.assertIn("required: false", title_block)
        self.assertIn('default: ""', title_block)

    def test_quality_gate_uses_argument_arrays_for_optional_flags(self) -> None:
        content = read(".github/workflows/_quality-gate-pr.yml")
        self.assertIn("baseline_args=()", content)
        self.assertIn("post_args=()", content)
        self.assertIn('"${baseline_args[@]}"', content)
        self.assertIn('"${post_args[@]}"', content)

    def test_release_gate_pins_validation_images_by_digest(self) -> None:
        content = read(".github/workflows/move-v1.yml")
        self.assertIn(
            "rhysd/actionlint@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667",
            content,
        )
        self.assertIn(
            "mikefarah/yq@sha256:76def1f56f456ecc1c3173ea275218ee17139bc2018c5a07887b15afd88ec03e",
            content,
        )

    def test_v1_moves_when_canonical_release_template_changes(self) -> None:
        content = read(".github/workflows/move-v1.yml")
        self.assertIn('- "templates/**"', content)

    def test_failed_compose_diagnostics_include_stopped_services(self) -> None:
        content = read(".github/workflows/_vps-self-hosted-deploy.yml")
        self.assertIn(
            'docker compose -f "$COMPOSE_FILE" ps -a --status exited --services',
            content,
        )
        self.assertIn(
            'docker compose -f "$COMPOSE_FILE" ps -a -q "$service"',
            content,
        )

    def test_deploy_workflows_do_not_use_unquoted_numeric_or_unused_loop_variables(self) -> None:
        self_hosted = read(".github/workflows/_vps-self-hosted-deploy.yml")
        monorepo = read(".github/workflows/_vps-monorepo-deploy.yml")
        self.assertIn('if [ "$counter" -ge "$HEALTH_TIMEOUT" ]; then', self_hosted)
        self.assertNotIn("for attempt in 1 2 3; do", monorepo)


if __name__ == "__main__":
    unittest.main()
