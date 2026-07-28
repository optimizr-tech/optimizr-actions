import hashlib
import json
import unittest


from scripts.postgres_major_migration.diagnostics import (
    build_component_manifest,
    build_comparison_manifest,
)


class PostgresMigrationDiagnosticsTests(unittest.TestCase):
    def test_json_verification_output_is_reduced_to_component_hashes(self) -> None:
        manifest = build_component_manifest(
            '{"charges": 7, "schema": {"tables": 2}}',
            side="source",
            overall_sha256="a" * 64,
        )

        self.assertEqual(manifest["side"], "source")
        self.assertEqual(manifest["sha256"], "a" * 64)
        self.assertEqual(
            [component["name"] for component in manifest["components"]],
            ["charges", "schema"],
        )
        self.assertEqual(
            manifest["components"][0]["sha256"],
            hashlib.sha256(b"7").hexdigest(),
        )
        self.assertNotIn("secret-value", json.dumps(manifest, sort_keys=True))

    def test_tabular_verification_output_preserves_safe_component_names(self) -> None:
        manifest = build_component_manifest(
            "schema\t2\ncharges\t42\n",
            side="target",
            overall_sha256="b" * 64,
        )

        self.assertEqual(
            [component["name"] for component in manifest["components"]],
            ["charges", "schema"],
        )
        self.assertEqual(
            manifest["components"][1]["sha256"],
            hashlib.sha256(b"2").hexdigest(),
        )

    def test_unsafe_component_names_are_replaced_without_value_leakage(self) -> None:
        manifest = build_component_manifest(
            "customer password\tsecret-value",
            side="source",
            overall_sha256="c" * 64,
        )

        self.assertEqual(manifest["components"][0]["name"], "component_1")
        serialized = json.dumps(manifest, sort_keys=True)
        self.assertNotIn("customer password", serialized)
        self.assertNotIn("secret-value", serialized)

    def test_comparison_manifest_keeps_source_and_target_hashes(self) -> None:
        source = build_component_manifest("schema\t1", "source", "a" * 64)
        target = build_component_manifest("schema\t2", "target", "b" * 64)

        manifest = build_comparison_manifest(source, target)

        self.assertEqual(manifest["status"], "mismatch")
        self.assertEqual(manifest["source"], source)
        self.assertEqual(manifest["target"], target)


if __name__ == "__main__":
    unittest.main()
