from pathlib import Path
import json
import unittest

from scripts.capability_catalog.catalog import build_catalog, render_catalog
from scripts.capability_catalog.metadata import (
    CATEGORIES,
    RUNNER_KINDS,
    TRUST_BOUNDARIES,
)


ROOT = Path(__file__).resolve().parents[1]
CATALOG_PATH = ROOT / "catalog" / "capabilities.json"
METADATA_PATH = ROOT / "catalog" / "artifact_metadata.json"

ENTRY_KEYS = {
    "path",
    "kind",
    "source_sha256",
    "maturity",
    "category",
    "runner",
    "trust_boundary",
    "inputs",
    "outputs",
    "permissions",
    "evidence",
    "examples",
    "known_limitations",
    "metadata_status",
}


class CapabilityCatalogTests(unittest.TestCase):
    maxDiff = None

    def test_catalog_discovers_and_sorts_public_artifacts(self) -> None:
        catalog = build_catalog(ROOT)

        self.assertEqual(2, catalog["schema_version"])
        artifacts = catalog["artifacts"]
        self.assertTrue(artifacts)
        self.assertEqual(
            artifacts,
            sorted(artifacts, key=lambda item: item["path"]),
        )
        self.assertTrue(
            {item["kind"] for item in artifacts}
            <= {"workflow", "action", "template"}
        )

    def test_entries_have_complete_enriched_schema(self) -> None:
        for entry in build_catalog(ROOT)["artifacts"]:
            with self.subTest(path=entry["path"]):
                self.assertEqual(ENTRY_KEYS, set(entry))
                self.assertRegex(entry["source_sha256"], r"^[0-9a-f]{64}$")
                expected_maturity = (
                    "canonical-template"
                    if entry["kind"] == "template"
                    else "stable-v1"
                )
                self.assertEqual(expected_maturity, entry["maturity"])

    def test_every_artifact_reports_runner_and_trust_boundary(self) -> None:
        for entry in build_catalog(ROOT)["artifacts"]:
            with self.subTest(path=entry["path"]):
                self.assertIn(entry["category"], CATEGORIES)
                self.assertGreater(len(entry["runner"]), 0, "runner must be declared")
                self.assertTrue(
                    set(entry["runner"]) <= set(RUNNER_KINDS),
                    "runner kinds must be canonical",
                )
                self.assertEqual(len(entry["runner"]), len(set(entry["runner"])))
                self.assertIn(entry["trust_boundary"], TRUST_BOUNDARIES)
                self.assertIn(
                    entry["metadata_status"],
                    ("classified", "partial", "unclassified"),
                )
                self.assertEqual("classified", entry["metadata_status"])

    def test_committed_catalog_matches_live_repository_surface(self) -> None:
        committed = CATALOG_PATH.read_text(encoding="utf-8")
        expected = render_catalog(ROOT)
        self.assertEqual(
            expected,
            committed,
            "Capability catalog drifted. Run "
            "`python -m scripts.capability_catalog.generate`.",
        )
        self.assertEqual(json.loads(committed), build_catalog(ROOT))

    def test_render_is_deterministic_and_newline_terminated(self) -> None:
        first = render_catalog(ROOT)
        second = render_catalog(ROOT)
        self.assertEqual(first, second)
        self.assertTrue(first.endswith("\n"))


class CuratedMetadataTests(unittest.TestCase):
    def test_curated_metadata_only_references_discovered_artifacts(self) -> None:
        curated = json.loads(METADATA_PATH.read_text(encoding="utf-8"))
        discovered = {item["path"] for item in build_catalog(ROOT)["artifacts"]}
        for path in curated["entries"]:
            with self.subTest(path=path):
                self.assertIn(path, discovered)

    def test_curated_metadata_fields_are_bounded(self) -> None:
        curated = json.loads(METADATA_PATH.read_text(encoding="utf-8"))
        allowed = {
            "category",
            "runner",
            "trust_boundary",
            "evidence",
            "examples",
            "known_limitations",
        }
        for path, entry in curated["entries"].items():
            with self.subTest(path=path):
                self.assertLessEqual(set(entry), allowed)


if __name__ == "__main__":
    unittest.main()
