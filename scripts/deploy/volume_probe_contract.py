"""Validate and apply owner-scoped Docker volume creation and write probes."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Callable, Mapping, Sequence


MAX_NAME_LENGTH = 255
MAX_NAME_LIST_BYTES = 64 * 1024
MAX_NETWORKS = 128
MAX_VOLUMES = 256
MAX_PROBES = 32
MAX_PROBE_JSON_BYTES = 32 * 1024
MAX_MANIFEST_BYTES = 512 * 1024
DOCKER_COMMAND_TIMEOUT_SECONDS = 60

_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
_PATH_SEGMENT_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
_CONTAINER_ID_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_IMAGE_ID_RE = re.compile(r"^sha256:[0-9a-fA-F]{64}$")
_PROBE_FIELDS = {"container", "volume", "mount_path", "uid"}

WRITE_PROBE_SCRIPT = """set -eu
umask 077
target="$1"
probe_file="$(mktemp "$target/.optimizr-write-probe.XXXXXX")"
cleanup() {
  rm -f -- "$probe_file"
}
trap cleanup EXIT
printf 'optimizr-volume-write-probe\\n' > "$probe_file"
test -s "$probe_file"
rm -f -- "$probe_file"
trap - EXIT
"""


class ContractError(RuntimeError):
    """Raised when a caller input or runtime verification fails closed."""


DockerCall = Callable[[list[str]], subprocess.CompletedProcess[str]]


def _required_text(inputs: Mapping[str, str], key: str, default: str = "") -> str:
    value = inputs.get(key, default)
    if not isinstance(value, str):
        raise ContractError(f"{key} must be a string")
    return value


def _split_names(raw: str, field: str, maximum: int) -> list[str]:
    try:
        encoded_size = len(raw.encode("utf-8"))
    except UnicodeEncodeError:
        raise ContractError(f"{field} contains invalid text") from None
    if encoded_size > MAX_NAME_LIST_BYTES:
        raise ContractError(f"{field} exceeds the maximum size")
    values = raw.split()
    if len(values) > maximum:
        raise ContractError(f"{field} contains too many names")
    if len(values) != len(set(values)):
        raise ContractError(f"{field} must not contain duplicate names")
    for value in values:
        if len(value) > MAX_NAME_LENGTH or not _NAME_RE.fullmatch(value):
            raise ContractError(f"{field} contains an invalid Docker name")
    return values


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ContractError("volume_write_probes_json contains a duplicate object key")
        result[key] = value
    return result


def _reject_json_constant(_value: str) -> None:
    raise ContractError("volume_write_probes_json contains a non-standard JSON number")


def _validate_mount_path(value: object) -> str:
    if not isinstance(value, str) or len(value) > 4096:
        raise ContractError("probe mount_path must be a bounded absolute path")
    if not value.startswith("/") or value == "/" or "\\" in value or "\x00" in value:
        raise ContractError("probe mount_path must be a non-root POSIX absolute path")
    segments = value[1:].split("/")
    if any(
        not segment
        or segment in {".", ".."}
        or not _PATH_SEGMENT_RE.fullmatch(segment)
        for segment in segments
    ):
        raise ContractError("probe mount_path contains an invalid or traversing segment")
    return value


def _validate_probe(raw: object, ensure_volumes: set[str]) -> dict[str, object]:
    if not isinstance(raw, dict) or set(raw) != _PROBE_FIELDS:
        raise ContractError("each volume probe must contain only container, volume, mount_path, and uid")

    container = raw["container"]
    volume = raw["volume"]
    if not isinstance(container, str) or len(container) > MAX_NAME_LENGTH or not _NAME_RE.fullmatch(container):
        raise ContractError("probe container contains an invalid Docker name")
    if not isinstance(volume, str) or len(volume) > MAX_NAME_LENGTH or not _NAME_RE.fullmatch(volume):
        raise ContractError("probe volume contains an invalid Docker name")
    if volume not in ensure_volumes:
        raise ContractError("every probed volume must also appear in ensure_volumes")

    uid = raw["uid"]
    if type(uid) is not int or uid < 0 or uid > 2_147_483_647:
        raise ContractError("probe uid must be an integer between 0 and 2147483647")

    return {
        "container": container,
        "volume": volume,
        "mount_path": _validate_mount_path(raw["mount_path"]),
        "uid": uid,
    }


def validate_inputs(inputs: Mapping[str, str]) -> dict[str, object]:
    """Validate the full new volume contract before any Docker resource mutation."""
    ensure_networks = _split_names(
        _required_text(inputs, "ENSURE_NETWORKS", ""), "ensure_networks", MAX_NETWORKS
    )
    ensure_volumes_list = _split_names(
        _required_text(inputs, "ENSURE_VOLUMES", ""), "ensure_volumes", MAX_VOLUMES
    )
    allowlist = _split_names(
        _required_text(inputs, "CREATE_MISSING_VOLUMES_ALLOWLIST", ""),
        "create_missing_volumes_allowlist",
        MAX_VOLUMES,
    )
    ensure_volumes = set(ensure_volumes_list)
    if not set(allowlist).issubset(ensure_volumes):
        raise ContractError("every allowlisted volume must also appear in ensure_volumes")

    legacy_raw = _required_text(inputs, "CREATE_MISSING_VOLUMES", "false").lower()
    if legacy_raw not in {"true", "false"}:
        raise ContractError("create_missing_volumes must be true or false")
    legacy_create = legacy_raw == "true"
    if legacy_create and allowlist:
        raise ContractError("create_missing_volumes and create_missing_volumes_allowlist are mutually exclusive")

    probes_raw = _required_text(inputs, "VOLUME_WRITE_PROBES_JSON", "[]")
    try:
        encoded_probe_size = len(probes_raw.encode("utf-8"))
    except UnicodeEncodeError:
        raise ContractError("volume_write_probes_json contains invalid text") from None
    if encoded_probe_size > MAX_PROBE_JSON_BYTES:
        raise ContractError("volume_write_probes_json exceeds the maximum size")
    try:
        probes_value = json.loads(
            probes_raw,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except (ValueError, ContractError, UnicodeError, RecursionError) as exc:
        raise ContractError("volume_write_probes_json must be valid strict JSON") from exc
    if not isinstance(probes_value, list):
        raise ContractError("volume_write_probes_json must be a JSON array")
    if len(probes_value) > MAX_PROBES:
        raise ContractError("volume_write_probes_json contains too many probes")

    probes: list[dict[str, object]] = []
    seen: set[tuple[object, ...]] = set()
    for raw_probe in probes_value:
        probe = _validate_probe(raw_probe, ensure_volumes)
        identity = (
            probe["container"],
            probe["volume"],
            probe["mount_path"],
            probe["uid"],
        )
        if identity in seen:
            raise ContractError("volume_write_probes_json contains a duplicate probe")
        seen.add(identity)
        probes.append(probe)

    rollout_services: list[str] | None = None
    if probes and "ROLLOUT_SERVICES" in inputs:
        rollout_services = _split_names(
            _required_text(inputs, "ROLLOUT_SERVICES"), "services_up", MAX_VOLUMES
        )
        if not rollout_services:
            raise ContractError("monorepo volume probes require services_up to roll out first")

    return {
        "ensure_networks": ensure_networks,
        "ensure_volumes": ensure_volumes_list,
        "create_missing_volumes": legacy_create,
        "create_missing_volumes_allowlist": allowlist,
        "volume_write_probes": probes,
        "rollout_services": rollout_services,
    }


def may_create_missing_volume(manifest: Mapping[str, object], volume: str) -> bool:
    """Return whether this exact required volume is authorized for creation."""
    return bool(manifest["create_missing_volumes"]) or volume in set(
        manifest["create_missing_volumes_allowlist"]  # type: ignore[arg-type]
    )


def _require_success(
    result: subprocess.CompletedProcess[str], description: str
) -> subprocess.CompletedProcess[str]:
    if result.returncode != 0:
        raise ContractError(f"{description} failed with exit status {result.returncode}")
    return result


def _inspect_volume_name(result: subprocess.CompletedProcess[str], expected: str) -> bool:
    try:
        value = json.loads(result.stdout)
    except (TypeError, json.JSONDecodeError):
        raise ContractError("Docker returned an invalid volume inspection") from None
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
        raise ContractError("Docker returned an invalid volume inspection")
    return value[0].get("Name") == expected


def ensure_volumes(
    manifest: Mapping[str, object], docker_call: DockerCall | None = None
) -> None:
    """Preflight all required volumes, then create only explicitly authorized misses."""
    call = docker_call or run_docker
    missing: list[str] = []
    for volume in manifest["ensure_volumes"]:  # type: ignore[union-attr]
        inspect = call(["volume", "inspect", volume])
        if inspect.returncode == 0:
            if not _inspect_volume_name(inspect, volume):
                raise ContractError("Docker inspection did not match the requested volume")
            continue

        listed = call(
            ["volume", "ls", "--format", "{{.Name}}", "--filter", f"name={volume}"]
        )
        _require_success(listed, "Docker volume inventory")
        matches = listed.stdout.splitlines()
        if volume in matches:
            raise ContractError("Docker listed a volume that it could not inspect")
        missing.append(volume)

    unauthorized = [
        volume for volume in missing if not may_create_missing_volume(manifest, volume)
    ]
    if unauthorized:
        names = ", ".join(unauthorized)
        raise ContractError(
            f"required volume(s) are missing and not authorized for creation: {names}"
        )

    for volume in missing:
        created = call(["volume", "create", volume])
        _require_success(created, "Docker volume creation")
        if created.stdout.strip() != volume:
            raise ContractError("Docker did not confirm creation of the exact requested volume")
        inspected = call(["volume", "inspect", volume])
        _require_success(inspected, "Docker volume verification")
        if not _inspect_volume_name(inspected, volume):
            raise ContractError("Docker created a volume with an unexpected name")


def _docker_prefix(environment: Mapping[str, str]) -> tuple[list[str], dict[str, str]]:
    mode = environment.get("DOCKER_MODE", "sudo")
    child_environment = dict(environment)
    if mode == "direct":
        config = environment.get("DOCKER_CONFIG", "")
        if config:
            child_environment["DOCKER_CONFIG"] = config
        return ["docker"], child_environment
    if mode in {"sudo", "auto"}:
        prefix = ["sudo", "docker"]
        config = environment.get("DOCKER_CONFIG", "")
        if config:
            prefix.extend(["--config", config])
        return prefix, child_environment
    raise ContractError("unsupported docker_mode")


def run_docker(
    args: Sequence[str], environment: Mapping[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    env = environment if environment is not None else os.environ
    prefix, child_environment = _docker_prefix(env)
    try:
        return subprocess.run(
            [*prefix, *args],
            capture_output=True,
            check=False,
            env=child_environment,
            timeout=DOCKER_COMMAND_TIMEOUT_SECONDS,
            text=True,
        )
    except subprocess.TimeoutExpired:
        raise ContractError("Docker command exceeded its execution time limit") from None
    except OSError:
        raise ContractError("Docker command could not be started") from None


def _compose_args(args: Sequence[str], environment: Mapping[str, str]) -> list[str]:
    compose_file = environment.get("COMPOSE_FILE", "")
    if not compose_file:
        raise ContractError("COMPOSE_FILE is required for volume write probes")
    result = ["compose", "-f", compose_file]
    if environment.get("DEPLOYMENT_MODE", "build") == "prebuilt-images":
        prebuilt_file = environment.get("PREBUILT_COMPOSE_FILE", "")
        if not prebuilt_file:
            raise ContractError("PREBUILT_COMPOSE_FILE is required in prebuilt-images mode")
        result.extend(["-f", prebuilt_file])
    result.extend(args)
    return result


def _parse_inspected_container(raw: str) -> dict[str, object]:
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        raise ContractError("Docker returned invalid container inspection data") from None
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
        raise ContractError("Docker did not return exactly one inspected container")
    return value[0]


def _verify_probe_target(
    probe: Mapping[str, object],
    docker_call: DockerCall,
    compose_call: DockerCall,
    expected_services: set[str] | None = None,
) -> str:
    container_name = str(probe["container"])
    volume = str(probe["volume"])
    mount_path = str(probe["mount_path"])

    compose_ids_result = _require_success(
        compose_call(["ps", "--all", "--quiet", "--no-trunc"]),
        "Compose container inventory",
    )
    compose_ids = set(compose_ids_result.stdout.splitlines())

    inspected_result = _require_success(
        docker_call(["inspect", "--type", "container", container_name]),
        "Docker container inspection",
    )
    container = _parse_inspected_container(inspected_result.stdout)
    container_id = container.get("Id")
    if (
        not isinstance(container_id, str)
        or not _CONTAINER_ID_RE.fullmatch(container_id)
        or container_id not in compose_ids
    ):
        raise ContractError("probe container is not part of the current Compose deployment")
    actual_name = container.get("Name")
    if not isinstance(actual_name, str) or actual_name != f"/{container_name}":
        raise ContractError("Docker inspected a different container than requested")
    if not isinstance(container.get("State"), dict) or container["State"].get("Running") is not True:
        raise ContractError("probe container is not running")

    config = container.get("Config")
    if not isinstance(config, dict):
        raise ContractError("probe container has no inspectable image configuration")
    config_image = config.get("Image")
    if (
        not isinstance(config_image, str)
        or not config_image
        or len(config_image) > 512
        or config_image.startswith("-")
        or any(ord(character) < 0x21 or ord(character) > 0x7E for character in config_image)
    ):
        raise ContractError("probe container has no configured image")
    labels = config.get("Labels")
    if not isinstance(labels, dict):
        raise ContractError("probe container has no Compose service label")
    service_name = labels.get("com.docker.compose.service")
    if not isinstance(service_name, str) or not _NAME_RE.fullmatch(service_name):
        raise ContractError("probe container has an invalid Compose service label")
    if expected_services is not None and service_name not in expected_services:
        raise ContractError("probe container service was not requested in this rollout")
    oneoff = labels.get("com.docker.compose.oneoff")
    if isinstance(oneoff, str) and oneoff.lower() == "true":
        raise ContractError("probe target must be a deployed Compose service, not a one-off container")

    compose_config_result = _require_success(
        compose_call(["config", "--format", "json"]), "Compose configuration inspection"
    )
    try:
        compose_config = json.loads(compose_config_result.stdout)
    except json.JSONDecodeError:
        raise ContractError("Compose returned invalid configuration data") from None
    services = compose_config.get("services") if isinstance(compose_config, dict) else None
    service = services.get(service_name) if isinstance(services, dict) else None
    if not isinstance(service, dict):
        raise ContractError("probe container is not declared by the current Compose configuration")
    configured_image = service.get("image")
    if configured_image is not None and configured_image != config_image:
        raise ContractError("probe container image does not match the current Compose configuration")

    image_id = container.get("Image")
    if not isinstance(image_id, str) or not _IMAGE_ID_RE.fullmatch(image_id):
        raise ContractError("probe container has no immutable image identifier")
    image_result = _require_success(
        docker_call(["image", "inspect", "--format", "{{.Id}}", config_image]),
        "Docker deployed image inspection",
    )
    if image_result.stdout.strip() != image_id:
        raise ContractError("probe container image reference no longer resolves to its deployed image")

    mounts = container.get("Mounts")
    if not isinstance(mounts, list):
        raise ContractError("probe container has no inspectable mounts")
    matching_mounts = [
        mount
        for mount in mounts
        if isinstance(mount, dict)
        and mount.get("Type") == "volume"
        and mount.get("Name") == volume
        and mount.get("Destination") == mount_path
    ]
    if len(matching_mounts) != 1 or matching_mounts[0].get("RW") is not True:
        raise ContractError("probe does not match one writable named-volume mount")
    return container_id


def run_write_probes(
    manifest: Mapping[str, object],
    docker_call: DockerCall | None = None,
    compose_call: DockerCall | None = None,
) -> None:
    """Verify the live Compose container and run only the fixed write/cleanup probe."""
    environment = os.environ
    docker = docker_call or (lambda args: run_docker(args, environment))
    compose = compose_call or (
        lambda args: run_docker(_compose_args(args, environment), environment)
    )

    raw_expected_services = manifest.get("rollout_services")
    if raw_expected_services is None:
        expected_services = None
    elif isinstance(raw_expected_services, list) and all(
        isinstance(service, str) for service in raw_expected_services
    ):
        expected_services = set(raw_expected_services)
    else:
        raise ContractError("validated rollout service list has an invalid structure")

    for probe in manifest["volume_write_probes"]:  # type: ignore[union-attr]
        container_id = _verify_probe_target(probe, docker, compose, expected_services)
        _require_success(
            docker(
                [
                    "exec",
                    "--user",
                    str(probe["uid"]),
                    container_id,
                    "sh",
                    "-eu",
                    "-c",
                    WRITE_PROBE_SCRIPT,
                    "sh",
                    str(probe["mount_path"]),
                ]
            ),
            "Docker volume write probe",
        )


def ensure_resources(
    manifest: Mapping[str, object], docker_call: DockerCall | None = None
) -> None:
    call = docker_call or run_docker
    for network in manifest["ensure_networks"]:  # type: ignore[union-attr]
        inspected = call(["network", "inspect", network])
        if inspected.returncode != 0:
            created = call(["network", "create", network])
            _require_success(created, "Docker network creation")
    ensure_volumes(manifest, docker_call=call)


def _write_manifest(manifest: Mapping[str, object]) -> str:
    runner_temp = os.environ.get("RUNNER_TEMP", "")
    github_output = os.environ.get("GITHUB_OUTPUT", "")
    if not runner_temp or not github_output:
        raise ContractError("runner temporary directory and GITHUB_OUTPUT are required")
    runner_temp_path = Path(runner_temp)
    if not runner_temp_path.is_absolute() or not runner_temp_path.is_dir():
        raise ContractError("RUNNER_TEMP must be an existing absolute directory")

    path = ""
    try:
        descriptor, path = tempfile.mkstemp(
            prefix="optimizr-volume-contract-", suffix=".json", dir=runner_temp
        )
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(manifest, output, separators=(",", ":"))
            output.write("\n")
        with open(github_output, "a", encoding="utf-8") as output:
            output.write(f"manifest_path={path}\n")
    except (OSError, TypeError, ValueError):
        if path:
            try:
                Path(path).unlink(missing_ok=True)
            except OSError:
                pass
        raise ContractError("validated volume manifest could not be written") from None
    return path


def _load_manifest() -> dict[str, object]:
    runner_temp_value = os.environ.get("RUNNER_TEMP", "")
    raw_path = os.environ.get("VOLUME_MANIFEST", "")
    if not runner_temp_value or not raw_path:
        raise ContractError("validated volume manifest is unavailable")
    try:
        runner_temp = Path(runner_temp_value).resolve(strict=True)
    except OSError:
        raise ContractError("RUNNER_TEMP is unavailable") from None
    if not runner_temp.is_dir():
        raise ContractError("RUNNER_TEMP is unavailable")
    path = Path(raw_path)
    try:
        if not path.is_absolute() or path.is_symlink():
            raise ContractError("volume manifest must be an absolute regular file, not a symbolic link")
        resolved = path.resolve(strict=True)
        if runner_temp not in resolved.parents or not resolved.is_file():
            raise ContractError("volume manifest must remain inside RUNNER_TEMP")
        if resolved.stat().st_size > MAX_MANIFEST_BYTES:
            raise ContractError("volume manifest exceeds the maximum size")
        value = json.loads(resolved.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeError, RecursionError):
        raise ContractError("validated volume manifest could not be read") from None
    if not isinstance(value, dict):
        raise ContractError("validated volume manifest has an invalid structure")
    return value


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    try:
        if args == ["validate"]:
            manifest = validate_inputs(os.environ)
            _write_manifest(manifest)
            print(
                "Validated volume contract: "
                f"{len(manifest['ensure_volumes'])} required volume(s), "
                f"{len(manifest['volume_write_probes'])} write probe(s)."
            )
        elif args == ["apply"]:
            ensure_resources(_load_manifest())
        elif args == ["probe"]:
            run_write_probes(_load_manifest())
        else:
            raise ContractError("expected one command: validate, apply, or probe")
    except ContractError as exc:
        print(f"::error::{exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
