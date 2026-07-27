from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "_postgres-major-logical-migration.yml"


class PostgresMajorLogicalMigrationContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = WORKFLOW.read_text(encoding="utf-8")

    def test_is_reusable_and_production_protected(self) -> None:
        self.assertIn("workflow_call:", self.text)
        self.assertIn("environment:\n      name: production", self.text)
        self.assertIn("cancel-in-progress: false", self.text)

    def test_requires_immutable_target_and_distinct_volumes(self) -> None:
        self.assertIn("target_image must be pinned by sha256 digest", self.text)
        self.assertIn("source_volume and target_volume must differ", self.text)
        self.assertIn("target volume is not empty; choose a fresh volume", self.text)

    def test_uses_logical_backup_restore_globals_and_fingerprints(self) -> None:
        for token in (
            "pg_dump",
            "pg_dumpall",
            "--globals-only",
            "globals.restore.sql",
            "pg_restore",
            "sha256sum",
            "verification_sql",
            "source and target verification fingerprints differ",
            ".optimizr-postgres-major-migration.json",
        ):
            self.assertIn(token, self.text)

    def test_resolves_compose_sources_without_hardcoded_container_names(self) -> None:
        for token in (
            "source_compose_directory",
            "source_compose_file",
            "source_service",
            'docker compose -f "$SOURCE_COMPOSE_FILE" ps -q "$SOURCE_SERVICE"',
            "unable to resolve source volume from declared mount",
        ):
            self.assertIn(token, self.text)

    def test_does_not_cut_over_or_delete_docker_volumes(self) -> None:
        for token in (
            "docker volume rm",
            "docker volume prune",
            "docker compose down -v",
            "docker compose up -d",
        ):
            self.assertNotIn(token, self.text)

    def test_quiesced_applications_are_restarted(self) -> None:
        self.assertIn("Quiesce applications and create verified backup", self.text)
        self.assertIn("trap restart_apps EXIT", self.text)
        self.assertIn('docker start "$container"', self.text)

    def test_sensitive_global_dump_is_not_uploaded(self) -> None:
        self.assertIn('chmod 600 "$dump_file"', self.text)
        self.assertIn("globals_file", self.text)
        self.assertIn("path: artifacts/postgres-major-migration", self.text)
        self.assertNotIn("path: ${{ steps.backup.outputs.backup_dir }}", self.text)


if __name__ == "__main__":
    unittest.main()
