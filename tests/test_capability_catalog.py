from pathlib import Path
import json
import unittest

from scripts.capability_catalog.catalog import build_catalog, render_catalog


ROOT = Path(__file__).resolve().parents[1]
CATALOG_PATH = ROOT / "catalog" / "capabilities.json"


class CapabilityCatalogTests(unittest.TestCase):
    def test_catalog_discovers_and_sorts_public_artifacts(self) -> None:
        catalog = build_catalog(ROOT)

        self.assertEqual(1, catalog["schema_version"])
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

    def test_entries_have_bounded_first_slice_schema(self) -> None:
        for entry in build_catalog(ROOT)["artifacts"]:
            with self.subTest(path=entry["path"]):
                self.assertEqual(
                    {
                        "path",
                        "kind",
                        "source_sha256",
                        "maturity",
                        "metadata_status",
                    },
                    set(entry),
                )
                self.assertRegex(entry["source_sha256"], r"^[0-9a-f]{64}$")
                expected_maturity = (
                    "canonical-template"
                    if entry["kind"] == "template"
                    else "stable-v1"
                )
                self.assertEqual(expected_maturity, entry["maturity"])
                self.assertEqual("unclassified", entry["metadata_status"])

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


if __name__ == "__main__":
    unittest.main()
