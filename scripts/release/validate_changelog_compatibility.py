#!/usr/bin/env python3
"""Validate the caller's changelog preset against the release runtime."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys
from typing import Any

PRESET_PACKAGE = "conventional-changelog-conventionalcommits"
WRITER_PACKAGE = "conventional-changelog-writer"
SUPPORTED_WRITER_MAJOR = {"9": "8", "10": "9"}
PRESET_PLUGINS = {
    "@semantic-release/commit-analyzer",
    "@semantic-release/release-notes-generator",
}


class CompatibilityError(ValueError):
    """Raised when the release configuration or dependency pair is unsafe."""


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CompatibilityError(f"could not read valid JSON from {path.name}: {exc}") from exc
    if not isinstance(value, dict):
        raise CompatibilityError(f"{path.name} must contain a JSON object")
    return value


def _plugin_name(plugin: object) -> str | None:
    if isinstance(plugin, str):
        return plugin
    if isinstance(plugin, list) and plugin and isinstance(plugin[0], str):
        return plugin[0]
    return None


def _preset_plugins(config: dict[str, Any]) -> list[str]:
    plugins = config.get("plugins")
    if not isinstance(plugins, list):
        return []
    selected: list[str] = []
    for plugin in plugins:
        name = _plugin_name(plugin)
        options = plugin[1] if isinstance(plugin, list) and len(plugin) > 1 else None
        if (
            name in PRESET_PLUGINS
            and isinstance(options, dict)
            and options.get("preset") == "conventionalcommits"
        ):
            selected.append(name)
    return selected


def _configured_plugin_names(config: dict[str, Any]) -> set[str]:
    plugins = config.get("plugins")
    if not isinstance(plugins, list):
        return set()
    return {name for plugin in plugins if (name := _plugin_name(plugin)) is not None}


def _major(version_spec: object) -> str | None:
    if not isinstance(version_spec, str):
        return None
    match = re.search(r"(?:^|[^0-9])(\d+)", version_spec)
    return match.group(1) if match else None


def _check_pair(
    preset_major: str | None,
    writer_major: str | None,
    *,
    declared_preset_major: str | None = None,
    declared_writer_major: str | None = None,
    check_declarations: bool = False,
) -> None:
    required_writer_major = SUPPORTED_WRITER_MAJOR.get(preset_major or "")
    if check_declarations and declared_preset_major != preset_major:
        required_writer_major = None
    writer_declaration_matches = not check_declarations or (
        declared_writer_major == required_writer_major
        or (preset_major == "9" and declared_writer_major is None)
    )
    if (
        required_writer_major is None
        or writer_major != required_writer_major
        or not writer_declaration_matches
    ):
        raise CompatibilityError(
            "unsupported conventionalcommits compatibility pair. Supported pairs are "
            "preset 9.x + writer 8.x, or preset 10.x + writer 9.x. "
            f"Found preset={preset_major or 'missing'}, writer={writer_major or 'missing'}"
            + (
                f", manifest preset={declared_preset_major or 'missing'}, "
                f"manifest writer={declared_writer_major or 'missing'}"
                if declared_preset_major is not None or declared_writer_major is not None
                else ""
            )
            + "."
        )


def _validate_node_project(workspace: Path) -> str:
    package_json = _read_json(workspace / "package.json")
    package_lock = _read_json(workspace / "package-lock.json")
    dependencies: dict[str, Any] = {}
    for section in ("dependencies", "devDependencies"):
        section_value = package_json.get(section)
        if isinstance(section_value, dict):
            dependencies.update(section_value)
    lock_packages = package_lock.get("packages")
    if not isinstance(lock_packages, dict):
        raise CompatibilityError("package-lock.json has no packages map")

    preset_spec = dependencies.get(PRESET_PACKAGE)
    writer_spec = dependencies.get(WRITER_PACKAGE)
    locked_preset = lock_packages.get(f"node_modules/{PRESET_PACKAGE}", {})
    locked_writer = lock_packages.get(f"node_modules/{WRITER_PACKAGE}", {})
    if not isinstance(locked_preset, dict) or not isinstance(locked_writer, dict):
        raise CompatibilityError("package-lock.json is missing a required changelog package")

    declared_preset_major = _major(preset_spec)
    declared_writer_major = _major(writer_spec)
    locked_preset_major = _major(locked_preset.get("version"))
    locked_writer_major = _major(locked_writer.get("version"))
    _check_pair(
        locked_preset_major,
        locked_writer_major,
        declared_preset_major=declared_preset_major,
        declared_writer_major=declared_writer_major,
        check_declarations=True,
    )
    return (
        "Compatible conventionalcommits preset "
        f"{locked_preset.get('version')} + writer {locked_writer.get('version')} selected."
    )


def _resolve_package_dir(package_name: str, start: Path, workspace: Path) -> Path:
    parts = package_name.split("/")
    current = start
    while True:
        candidate = current / "node_modules" / Path(*parts)
        if candidate.is_dir():
            return candidate
        if current == workspace:
            break
        parent = current.parent
        if workspace not in parent.parents and parent != workspace:
            break
        current = parent
    raise CompatibilityError(
        f"installed release runtime is missing {package_name} inside the caller workspace"
    )


def _runtime_version(package_dir: Path, package_name: str) -> str:
    manifest = _read_json(package_dir / "package.json")
    if manifest.get("name") != package_name or not isinstance(manifest.get("version"), str):
        raise CompatibilityError(f"installed {package_name} package metadata is invalid")
    return manifest["version"]


def _validate_package_less_runtime(
    workspace: Path,
    preset_plugins: list[str],
    configured_plugins: set[str],
) -> str:
    notes_name = "@semantic-release/release-notes-generator"
    if notes_name not in configured_plugins:
        raise CompatibilityError(
            "package-less conventionalcommits validation requires an explicit "
            "@semantic-release/release-notes-generator plugin"
        )

    notes_dir = _resolve_package_dir(notes_name, workspace, workspace)
    writer_dir = _resolve_package_dir(WRITER_PACKAGE, notes_dir, workspace)
    writer_version = _runtime_version(writer_dir, WRITER_PACKAGE)
    compatible_pairs: list[str] = []
    for plugin_name in preset_plugins:
        plugin_dir = _resolve_package_dir(plugin_name, workspace, workspace)
        preset_dir = _resolve_package_dir(PRESET_PACKAGE, plugin_dir, workspace)
        preset_version = _runtime_version(preset_dir, PRESET_PACKAGE)
        _check_pair(_major(preset_version), _major(writer_version))
        compatible_pairs.append(preset_version)
    return (
        "Compatible installed runtime preset(s) "
        + ", ".join(sorted(set(compatible_pairs)))
        + f" + writer {writer_version} selected."
    )


def validate(workspace: Path, package_mode: str) -> str:
    workspace = workspace.resolve()
    config = _read_json(workspace / ".releaserc.json")
    plugins = config.get("plugins")
    if package_mode == "package-less" and (not isinstance(plugins, list) or not plugins):
        raise CompatibilityError(
            "package-less mode requires an explicit non-empty plugins array; implicit semantic-release "
            "defaults may include the npm publisher"
        )

    preset_plugins = _preset_plugins(config)
    if not preset_plugins:
        return "No conventionalcommits preset selected; compatibility check is not required."
    if package_mode == "package-less":
        return _validate_package_less_runtime(
            workspace,
            preset_plugins,
            _configured_plugin_names(config),
        )
    return _validate_node_project(workspace)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package-mode", choices=("node", "package-less"), default="node")
    parser.add_argument("--workspace", type=Path, default=Path.cwd())
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        message = validate(args.workspace, args.package_mode)
    except CompatibilityError as exc:
        print(f"changelog-compatibility: {exc}", file=sys.stderr)
        return 2
    print(message)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
