from __future__ import annotations

import importlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = {
    "vps": ROOT / ".github/workflows/_vps-self-hosted-deploy.yml",
    "monorepo": ROOT / ".github/workflows/_vps-monorepo-deploy.yml",
}
CONTRACT = importlib.import_module("scripts.deploy.volume_probe_contract")


def load_workflow(path: Path) -> dict:
    return yaml.load(path.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)


def workflow_steps(workflow: dict) -> list[dict]:
    return workflow["jobs"]["deploy"]["steps"]


def step_named(workflow: dict, name: str) -> dict:
    return next(step for step in workflow_steps(workflow) if step.get("name") == name)


def valid_probe(**overrides: object) -> dict:
    probe = {
        "container": "alloy",
        "volume": "alloy_data",
        "mount_path": "/var/lib/alloy",
        "uid": 65532,
    }
    probe.update(overrides)
    return probe


def volume_inputs(**overrides: str) -> dict[str, str]:
    values = {
        "ENSURE_NETWORKS": "",
        "ENSURE_VOLUMES": "",
        "CREATE_MISSING_VOLUMES": "false",
        "CREATE_MISSING_VOLUMES_ALLOWLIST": "",
        "VOLUME_WRITE_PROBES_JSON": "[]",
    }
    values.update(overrides)
    return values


class VolumeProbeWorkflowContractTests(unittest.TestCase):
    def test_both_deploy_workflows_expose_optional_backward_compatible_inputs(self) -> None:
        for name, path in WORKFLOWS.items():
            with self.subTest(workflow=name):
                workflow = load_workflow(path)
                inputs = workflow["on"]["workflow_call"]["inputs"]
                self.assertEqual(inputs["create_missing_volumes"]["default"], "false")
                self.assertEqual(inputs["create_missing_volumes_allowlist"]["default"], "")
                self.assertEqual(inputs["volume_write_probes_json"]["default"], "[]")
                self.assertEqual(inputs["create_missing_volumes_allowlist"]["type"], "string")
                self.assertEqual(inputs["volume_write_probes_json"]["type"], "string")

    def test_helper_checkout_uses_the_exact_reusable_workflow_revision_without_credentials(self) -> None:
        for name, path in WORKFLOWS.items():
            with self.subTest(workflow=name):
                workflow = load_workflow(path)
                checkout = step_named(workflow, "Checkout volume contract helper")
                self.assertEqual(checkout["with"]["repository"], "${{ job.workflow_repository }}")
                self.assertEqual(checkout["with"]["ref"], "${{ job.workflow_sha }}")
                self.assertEqual(checkout["with"]["persist-credentials"], "false")
                self.assertIn("scripts/deploy/volume_probe_contract.py", checkout["with"]["sparse-checkout"])

    def test_validation_precedes_volume_mutations_and_probe_precedes_health_gate(self) -> None:
        for name, path in WORKFLOWS.items():
            with self.subTest(workflow=name):
                workflow = load_workflow(path)
                steps = workflow_steps(workflow)
                names = [step.get("name", "") for step in steps]
                self.assertLess(
                    names.index("Validate owner-scoped volume inputs"),
                    names.index("Ensure networks and verify volumes"),
                )
                self.assertIn("manifest_path", step_named(workflow, "Validate owner-scoped volume inputs")["run"])

                if name == "vps":
                    rollout = step_named(workflow, "Roll out and verify primary container")["run"]
                    self.assertLess(rollout.index("compose_cmd up -d"), rollout.index("volume_contract.py probe"))
                    self.assertLess(rollout.index("volume_contract.py probe"), rollout.index("elapsed=0"))
                else:
                    self.assertLess(
                        names.index("Roll out services"),
                        names.index("Probe configured volume writes"),
                    )
                    self.assertLess(
                        names.index("Probe configured volume writes"),
                        names.index("Wait for healthcheck"),
                    )


class VolumeInputValidationTests(unittest.TestCase):
    def test_empty_new_inputs_preserve_legacy_defaults(self) -> None:
        manifest = CONTRACT.validate_inputs(volume_inputs(ENSURE_VOLUMES="data cache"))
        self.assertEqual(manifest["ensure_volumes"], ["data", "cache"])
        self.assertEqual(manifest["create_missing_volumes_allowlist"], [])
        self.assertEqual(manifest["volume_write_probes"], [])
        self.assertFalse(CONTRACT.may_create_missing_volume(manifest, "data"))

    def test_allowlist_creates_only_exactly_authorized_required_volumes(self) -> None:
        manifest = CONTRACT.validate_inputs(
            volume_inputs(
                ENSURE_VOLUMES="alloy_data metrics_data",
                CREATE_MISSING_VOLUMES_ALLOWLIST="alloy_data",
            )
        )
        self.assertTrue(CONTRACT.may_create_missing_volume(manifest, "alloy_data"))
        self.assertFalse(CONTRACT.may_create_missing_volume(manifest, "metrics_data"))

    def test_legacy_boolean_still_authorizes_all_required_missing_volumes_without_allowlist(self) -> None:
        manifest = CONTRACT.validate_inputs(
            volume_inputs(ENSURE_VOLUMES="data cache", CREATE_MISSING_VOLUMES="true")
        )
        self.assertTrue(CONTRACT.may_create_missing_volume(manifest, "data"))
        self.assertTrue(CONTRACT.may_create_missing_volume(manifest, "cache"))

    def test_legacy_boolean_and_new_allowlist_are_mutually_exclusive(self) -> None:
        with self.assertRaises(CONTRACT.ContractError):
            CONTRACT.validate_inputs(
                volume_inputs(
                    ENSURE_VOLUMES="alloy_data",
                    CREATE_MISSING_VOLUMES="true",
                    CREATE_MISSING_VOLUMES_ALLOWLIST="alloy_data",
                )
            )

    def test_allowlisted_and_probed_volumes_must_be_required(self) -> None:
        with self.assertRaises(CONTRACT.ContractError):
            CONTRACT.validate_inputs(
                volume_inputs(
                    ENSURE_VOLUMES="required_data",
                    CREATE_MISSING_VOLUMES_ALLOWLIST="other_data",
                )
            )
        with self.assertRaises(CONTRACT.ContractError):
            CONTRACT.validate_inputs(
                volume_inputs(
                    ENSURE_VOLUMES="required_data",
                    VOLUME_WRITE_PROBES_JSON=json.dumps([valid_probe(volume="other_data")]),
                )
            )

    def test_volume_and_network_names_reject_shell_and_option_metacharacters(self) -> None:
        for name in (";touch-pwned", "--help", "bad/name", "name*", "two words"):
            with self.subTest(name=name), self.assertRaises(CONTRACT.ContractError):
                CONTRACT.validate_inputs(volume_inputs(ENSURE_VOLUMES=name))
            with self.subTest(network=name), self.assertRaises(CONTRACT.ContractError):
                CONTRACT.validate_inputs(volume_inputs(ENSURE_NETWORKS=name))

    def test_probe_json_rejects_malformed_schema_unknown_fields_and_duplicate_keys(self) -> None:
        invalid = (
            "{",
            json.dumps({"not_a_probe": True}),
            json.dumps([valid_probe(command="touch /tmp/untrusted")]),
            '[{"container":"one","container":"two","volume":"data",'
            '"mount_path":"/data","uid":1}]',
        )
        for raw in invalid:
            with self.subTest(raw=raw), self.assertRaises(CONTRACT.ContractError):
                CONTRACT.validate_inputs(
                    volume_inputs(ENSURE_VOLUMES="alloy_data", VOLUME_WRITE_PROBES_JSON=raw)
                )

    def test_probe_rejects_invalid_names_paths_and_non_integer_uids(self) -> None:
        bad_probes = (
            valid_probe(container="../other"),
            valid_probe(volume="--help"),
            valid_probe(mount_path="/var/lib/../etc"),
            valid_probe(mount_path="relative/path"),
            valid_probe(mount_path="/var//lib"),
            valid_probe(uid=True),
            valid_probe(uid=1.5),
            valid_probe(uid=-1),
        )
        for probe in bad_probes:
            with self.subTest(probe=probe), self.assertRaises(CONTRACT.ContractError):
                CONTRACT.validate_inputs(
                    volume_inputs(
                        ENSURE_VOLUMES="alloy_data",
                        VOLUME_WRITE_PROBES_JSON=json.dumps([probe]),
                    )
                )

    def test_probe_count_and_json_size_are_bounded(self) -> None:
        probes = [valid_probe() for _ in range(CONTRACT.MAX_PROBES + 1)]
        with self.assertRaises(CONTRACT.ContractError):
            CONTRACT.validate_inputs(
                volume_inputs(
                    ENSURE_VOLUMES="alloy_data",
                    VOLUME_WRITE_PROBES_JSON=json.dumps(probes),
                )
            )
        with self.assertRaises(CONTRACT.ContractError):
            CONTRACT.validate_inputs(
                volume_inputs(
                    ENSURE_VOLUMES="alloy_data",
                    VOLUME_WRITE_PROBES_JSON=" " * (CONTRACT.MAX_PROBE_JSON_BYTES + 1),
                )
            )


class VolumeMutationTests(unittest.TestCase):
    def test_authorized_volume_is_created_but_other_missing_volume_fails_before_any_creation(self) -> None:
        manifest = CONTRACT.validate_inputs(
            volume_inputs(
                ENSURE_VOLUMES="alloy_data metrics_data",
                CREATE_MISSING_VOLUMES_ALLOWLIST="alloy_data",
            )
        )
        calls: list[list[str]] = []

        def docker(args: list[str]) -> subprocess.CompletedProcess[str]:
            calls.append(args)
            if args[:2] == ["volume", "inspect"]:
                return subprocess.CompletedProcess(args, 1, "", "missing")
            if args[:2] == ["volume", "ls"]:
                return subprocess.CompletedProcess(args, 0, "", "")
            return subprocess.CompletedProcess(args, 0, "", "")

        with self.assertRaises(CONTRACT.ContractError):
            CONTRACT.ensure_volumes(manifest, docker_call=docker)
        self.assertFalse(any(args[:2] == ["volume", "create"] for args in calls))

    def test_missing_allowlisted_volume_is_created_and_reinspected(self) -> None:
        manifest = CONTRACT.validate_inputs(
            volume_inputs(
                ENSURE_VOLUMES="alloy_data",
                CREATE_MISSING_VOLUMES_ALLOWLIST="alloy_data",
            )
        )
        calls: list[list[str]] = []

        def docker(args: list[str]) -> subprocess.CompletedProcess[str]:
            calls.append(args)
            if args == ["volume", "inspect", "alloy_data"]:
                count = sum(call == args for call in calls)
                return subprocess.CompletedProcess(args, 1 if count == 1 else 0, "alloy_data", "")
            if args[:2] == ["volume", "ls"]:
                return subprocess.CompletedProcess(args, 0, "", "")
            if args == ["volume", "create", "alloy_data"]:
                return subprocess.CompletedProcess(args, 0, "alloy_data\n", "")
            self.fail(f"unexpected Docker call: {args}")

        CONTRACT.ensure_volumes(manifest, docker_call=docker)
        self.assertIn(["volume", "create", "alloy_data"], calls)
        self.assertEqual(calls.count(["volume", "inspect", "alloy_data"]), 2)

    def test_legacy_boolean_keeps_broad_creation_behavior(self) -> None:
        manifest = CONTRACT.validate_inputs(
            volume_inputs(ENSURE_VOLUMES="data", CREATE_MISSING_VOLUMES="true")
        )
        calls: list[list[str]] = []

        def docker(args: list[str]) -> subprocess.CompletedProcess[str]:
            calls.append(args)
            if args[:2] == ["volume", "inspect"]:
                return subprocess.CompletedProcess(args, 1, "", "missing")
            if args[:2] == ["volume", "ls"]:
                return subprocess.CompletedProcess(args, 0, "", "")
            return subprocess.CompletedProcess(args, 0, "data\n", "")

        CONTRACT.ensure_volumes(manifest, docker_call=docker)
        self.assertIn(["volume", "create", "data"], calls)


class VolumeWriteProbeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest = CONTRACT.validate_inputs(
            volume_inputs(
                ENSURE_VOLUMES="alloy_data",
                VOLUME_WRITE_PROBES_JSON=json.dumps([valid_probe()]),
            )
        )
        self.container = {
            "Id": "container-123",
            "Name": "/alloy",
            "State": {"Running": True},
            "Image": "sha256:image-123",
            "Config": {
                "Image": "ghcr.io/optimizr/alloy:sha-abc",
                "Labels": {"com.docker.compose.service": "alloy"},
            },
            "Mounts": [
                {
                    "Type": "volume",
                    "Name": "alloy_data",
                    "Destination": "/var/lib/alloy",
                    "RW": True,
                }
            ],
        }

    def fake_commands(self, container: dict | None = None, image_id: str = "sha256:image-123"):
        selected = self.container if container is None else container

        def docker(args: list[str]) -> subprocess.CompletedProcess[str]:
            if args == ["inspect", "--type", "container", "alloy"]:
                return subprocess.CompletedProcess(args, 0, json.dumps([selected]), "")
            if args == ["image", "inspect", "--format", "{{.Id}}", "ghcr.io/optimizr/alloy:sha-abc"]:
                return subprocess.CompletedProcess(args, 0, image_id + "\n", "")
            if args[:2] == ["exec", "--user"]:
                return subprocess.CompletedProcess(args, 0, "", "")
            self.fail(f"unexpected Docker call: {args}")

        def compose(args: list[str]) -> subprocess.CompletedProcess[str]:
            if args == ["ps", "--all", "--quiet"]:
                return subprocess.CompletedProcess(args, 0, "container-123\n", "")
            if args == ["config", "--format", "json"]:
                config = {"services": {"alloy": {"image": "ghcr.io/optimizr/alloy:sha-abc"}}}
                return subprocess.CompletedProcess(args, 0, json.dumps(config), "")
            self.fail(f"unexpected Compose call: {args}")

        return docker, compose

    def test_probe_runs_in_current_compose_container_as_requested_uid(self) -> None:
        calls: list[list[str]] = []
        docker, compose = self.fake_commands()

        def record_docker(args: list[str]) -> subprocess.CompletedProcess[str]:
            calls.append(args)
            return docker(args)

        CONTRACT.run_write_probes(self.manifest, docker_call=record_docker, compose_call=compose)
        exec_call = next(args for args in calls if args[:2] == ["exec", "--user"])
        self.assertEqual(exec_call[2:4], ["65532", "alloy"])
        self.assertIn(CONTRACT.WRITE_PROBE_SCRIPT, exec_call)
        self.assertEqual(exec_call[3], "alloy")

    def test_probe_script_writes_and_cleans_a_unique_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            subprocess.run(
                ["sh", "-eu", "-c", CONTRACT.WRITE_PROBE_SCRIPT, "sh", directory],
                check=True,
                capture_output=True,
                text=True,
            )
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_probe_fails_closed_when_mount_does_not_match(self) -> None:
        container = {**self.container, "Mounts": []}
        docker, compose = self.fake_commands(container=container)
        with self.assertRaises(CONTRACT.ContractError):
            CONTRACT.run_write_probes(self.manifest, docker_call=docker, compose_call=compose)

    def test_probe_fails_closed_when_container_is_not_from_this_compose_project(self) -> None:
        docker, _compose = self.fake_commands()

        def compose(args: list[str]) -> subprocess.CompletedProcess[str]:
            if args == ["ps", "--all", "--quiet"]:
                return subprocess.CompletedProcess(args, 0, "some-other-container\n", "")
            return _compose(args)

        with self.assertRaises(CONTRACT.ContractError):
            CONTRACT.run_write_probes(self.manifest, docker_call=docker, compose_call=compose)

    def test_probe_fails_closed_when_running_container_image_differs_from_configured_image(self) -> None:
        docker, compose = self.fake_commands(image_id="sha256:other-image")
        with self.assertRaises(CONTRACT.ContractError):
            CONTRACT.run_write_probes(self.manifest, docker_call=docker, compose_call=compose)

    def test_probe_execution_failure_fails_the_deployment(self) -> None:
        docker, compose = self.fake_commands()

        def failing_docker(args: list[str]) -> subprocess.CompletedProcess[str]:
            if args[:2] == ["exec", "--user"]:
                return subprocess.CompletedProcess(args, 1, "", "write denied")
            return docker(args)

        with self.assertRaises(CONTRACT.ContractError):
            CONTRACT.run_write_probes(self.manifest, docker_call=failing_docker, compose_call=compose)


if __name__ == "__main__":
    unittest.main()
