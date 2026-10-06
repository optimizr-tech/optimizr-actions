"""Contract tests for the documented owner-pipeline runner prerequisites."""

from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs" / "DEVELOPMENT_WORKFLOW.md"


class OwnerPipelineDocsTests(unittest.TestCase):
    def test_documents_owner_runner_prerequisites(self) -> None:
        # 2026-10-06: the owner pipeline failed on missing runner tools
        # (`gh: command not found`, container permission error). The
        # prerequisites must stay documented for the restricted pool.
        text = DOC.read_text(encoding="utf-8")
        self.assertIn("## Owner runner prerequisites", text)
        self.assertIn("local-docker-owner", text)
        self.assertIn("runner_gh_version", text)
        self.assertIn('--user "$(id -u):$(id -g)"', text)
        self.assertIn("fails closed", text)

    def test_documents_the_restricted_metadata_and_publication_boundary(self) -> None:
        text = DOC.read_text(encoding="utf-8")
        self.assertIn("_pr-metadata.yml@refs/tags/v1", text)
        self.assertIn("restricted owner self-hosted runner", text)
        self.assertIn("local-docker", text)


if __name__ == "__main__":
    unittest.main()
