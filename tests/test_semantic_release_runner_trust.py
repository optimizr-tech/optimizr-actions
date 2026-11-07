from __future__ import annotations

import os
from pathlib import Path
import re
import unittest
from unittest.mock import patch

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "_semantic-release.yml"
DOC = ROOT / "docs" / "SEMANTIC_RELEASE.md"
TRUST_DOC = ROOT / "docs" / "RUNNER_AND_TRUST_BOUNDARIES.md"


def load_jobs() -> dict[str, dict[str, object]]:
    payload = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    return payload["jobs"]


def guard_source(step: dict[str, object]) -> str:
    run = step["run"]
    assert isinstance(run, str)
    match = re.search(r"python3 - <<'PY'\n(?P<script>.*?)\nPY\s*$", run, re.DOTALL)
    if not match:
        raise AssertionError("runner trust step must execute an inline Python guard")
    return match.group("script")


class SemanticReleaseRunnerTrustTests(unittest.TestCase):
    def setUp(self) -> None:
        self.jobs = load_jobs()

    def test_both_jobs_start_with_same_guard_before_checkout(self) -> None:
        sources = []
        for job_name in ("release", "update-release-badge"):
            with self.subTest(job=job_name):
                steps = self.jobs[job_name]["steps"]
                self.assertIsInstance(steps, list)
                first = steps[0]
                self.assertEqual("Validate runner trust contract", first["name"])
                self.assertIn("run", first)
                self.assertNotIn("uses", first)
                self.assertEqual("bash", first["shell"])
                sources.append(guard_source(first))
                checkout_name = "Checkout" if job_name == "release" else "Checkout released branch"
                step_names = [step.get("name") for step in steps]
                self.assertIn(checkout_name, step_names)
                self.assertGreater(step_names.index(checkout_name), 0)
        self.assertEqual(sources[0], sources[1])

    def assert_guard(self, labels: str, event: str, ref: str, succeeds: bool) -> None:
        script = guard_source(self.jobs["release"]["steps"][0])
        env = {
            "RUNS_ON_JSON": labels,
            "EVENT_NAME": event,
            "EVENT_REF": ref,
        }
        with patch.dict(os.environ, env, clear=False):
            try:
                exec(compile(script, "semantic-release-runner-guard", "exec"), {})
                guard_succeeded = True
            except SystemExit as error:
                guard_succeeded = error.code in (None, 0)
            self.assertEqual(succeeds, guard_succeeded)

    def test_hosted_runner_remains_allowed_for_pull_request(self) -> None:
        self.assert_guard('["ubuntu-latest"]', "pull_request", "refs/pull/7/merge", True)

    def test_ephemeral_linux_runner_remains_allowed_for_pull_request(self) -> None:
        self.assert_guard(
            '["self-hosted","Linux","ephemeral","local-docker"]',
            "pull_request",
            "refs/pull/7/merge",
            True,
        )

    def test_persistent_linux_runner_allows_only_trusted_main_events(self) -> None:
        labels = '["self-hosted","Linux","local-docker"]'
        for event in ("push", "workflow_dispatch"):
            with self.subTest(event=event):
                self.assert_guard(labels, event, "refs/heads/main", True)

    def test_persistent_runner_rejects_pr_and_non_main_refs(self) -> None:
        labels = '["self-hosted","Linux","local-docker"]'
        for event, ref in (
            ("pull_request", "refs/pull/7/merge"),
            ("push", "refs/heads/develop"),
            ("workflow_dispatch", "refs/heads/release"),
        ):
            with self.subTest(event=event, ref=ref):
                self.assert_guard(labels, event, ref, False)

    def test_unknown_and_malformed_runner_configs_fail_closed(self) -> None:
        for labels in (
            '["ubuntu-24.04"]',
            '["self-hosted","Windows"]',
            '["self-hosted","ephemeral"]',
            "{}",
            "not-json",
        ):
            with self.subTest(labels=labels):
                self.assert_guard(labels, "push", "refs/heads/main", False)

    def test_docs_describe_persistent_release_boundary(self) -> None:
        semantic_doc = DOC.read_text(encoding="utf-8")
        trust_doc = TRUST_DOC.read_text(encoding="utf-8")
        self.assertIn("Persistent Linux self-hosted runners", semantic_doc)
        self.assertIn("refs/heads/main", semantic_doc)
        self.assertIn("_semantic-release.yml`", trust_doc)
        self.assertIn("self-hosted-persistent", trust_doc)
        self.assertIn("trusted-push", trust_doc)


if __name__ == "__main__":
    unittest.main()
