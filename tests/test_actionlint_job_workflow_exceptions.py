"""Every workflow that reads job.workflow_* needs a path-scoped actionlint exception.

actionlint v1.7.12 does not model the GitHub-supported ``job.workflow_*``
identity properties (https://github.com/rhysd/actionlint/pull/661). Reusable
workflows that check out their own source with them must be listed in
``.github/actionlint.yaml``; a missing entry only fails later, on ``main``.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
CONFIG = ROOT / ".github" / "actionlint.yaml"
JOB_WORKFLOW_PROPERTY = re.compile(r"\bjob\.workflow_(repository|ref|sha|file_path)\b")


class ActionlintJobWorkflowExceptionsTest(unittest.TestCase):
    def test_every_job_workflow_user_has_a_scoped_exception(self) -> None:
        paths = (yaml.safe_load(CONFIG.read_text(encoding="utf-8")) or {}).get("paths", {})
        for workflow in sorted(WORKFLOWS.glob("*.yml")):
            used = set(JOB_WORKFLOW_PROPERTY.findall(workflow.read_text(encoding="utf-8")))
            if not used:
                continue
            key = f".github/workflows/{workflow.name}"
            with self.subTest(workflow=key):
                self.assertIn(key, paths, f"{key} uses job.workflow_* but has no actionlint exception")
                patterns = paths[key].get("ignore", [])
                for prop in used:
                    message = f'property "workflow_{prop}" is not defined in object type {{...}}'
                    self.assertTrue(
                        any(re.search(pattern, message) for pattern in patterns),
                        f"{key}: no ignore pattern covers job.workflow_{prop}",
                    )

    def test_exceptions_stay_scoped_to_job_workflow_properties(self) -> None:
        paths = (yaml.safe_load(CONFIG.read_text(encoding="utf-8")) or {}).get("paths", {})
        for key, entry in paths.items():
            for pattern in entry.get("ignore", []):
                with self.subTest(path=key, pattern=pattern):
                    self.assertTrue(
                        pattern.startswith('property "workflow_('),
                        "actionlint exceptions must stay limited to job.workflow_* properties",
                    )


if __name__ == "__main__":
    unittest.main()
