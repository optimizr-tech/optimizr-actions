"""Static contracts for opt-in Compose service recreation after sync."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class RecreateServicesContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.workflow = (
            ROOT / ".github/workflows/_vps-self-hosted-deploy.yml"
        ).read_text(encoding="utf-8")

    def test_recreate_services_is_optional_and_empty_by_default(self) -> None:
        self.assertIn("recreate_services:", self.workflow)
        self.assertIn(
            "Whitespace-separated Compose services to recreate after file synchronization",
            self.workflow,
        )
        self.assertIn('default: ""', self.workflow)

    def test_recreation_is_narrow_and_does_not_touch_dependencies_or_volumes(self) -> None:
        self.assertIn(
            "RECREATE_SERVICES: ${{ inputs.recreate_services }}",
            self.workflow,
        )
        self.assertIn(
            "compose_cmd config --services",
            self.workflow,
        )
        self.assertIn(
            "compose_cmd up -d --no-deps --force-recreate --no-build",
            self.workflow,
        )
        self.assertNotIn("docker compose -f \"$COMPOSE_FILE\" down -v", self.workflow)

    def test_recreation_rejects_unknown_or_unsafe_service_names(self) -> None:
        self.assertIn("Service name contains unsupported characters", self.workflow)
        self.assertIn("Requested Compose service is not declared", self.workflow)


if __name__ == "__main__":
    unittest.main()
