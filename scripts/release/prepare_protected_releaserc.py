#!/usr/bin/env python3
"""Prepare a semantic-release config that cannot push generated commits to main."""

from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
import sys

DIRECT_BRANCH_MUTATION_PLUGINS = {
    "@semantic-release/changelog",
    "@semantic-release/git",
}
REQUIRED_RELEASE_PLUGIN = "@semantic-release/github"


class ProtectedReleaseError(RuntimeError):
    """Raised when the runtime release configuration is unsafe or malformed."""


def plugin_name(plugin: object) -> str:
    if isinstance(plugin, str) and plugin:
        return plugin
    if (
        isinstance(plugin, list)
        and plugin
        and isinstance(plugin[0], str)
        and plugin[0]
    ):
        return plugin[0]
    raise ProtectedReleaseError("semantic-release plugin entry is malformed")


def prepare_protected_config(config: object) -> tuple[dict[str, object], list[str]]:
    if not isinstance(config, dict):
        raise ProtectedReleaseError("semantic-release config must be a JSON object")
    plugins = config.get("plugins")
    if not isinstance(plugins, list) or not plugins:
        raise ProtectedReleaseError("semantic-release config must contain plugins")

    protected = copy.deepcopy(config)
    filtered: list[object] = []
    removed: list[str] = []
    for plugin in plugins:
        name = plugin_name(plugin)
        if name in DIRECT_BRANCH_MUTATION_PLUGINS:
            removed.append(name)
            continue
        filtered.append(copy.deepcopy(plugin))

    remaining_names = [plugin_name(plugin) for plugin in filtered]
    if REQUIRED_RELEASE_PLUGIN not in remaining_names:
        raise ProtectedReleaseError("protected mode requires the github release plugin")
    unexpected = sorted(DIRECT_BRANCH_MUTATION_PLUGINS.intersection(remaining_names))
    if unexpected:
        raise ProtectedReleaseError(
            f"protected config still contains branch-mutating plugin: {unexpected[0]}"
        )

    protected["plugins"] = filtered
    return protected, removed


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("config", type=Path, nargs="?", default=Path(".releaserc.json"))
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        config = json.loads(args.config.read_text(encoding="utf-8"))
        protected, removed = prepare_protected_config(config)
        args.config.write_text(
            json.dumps(protected, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
    except (OSError, json.JSONDecodeError, ProtectedReleaseError) as exc:
        print(f"protected-release-config: {exc}", file=sys.stderr)
        return 2

    print("protected-main release config prepared; removed=" + ",".join(removed))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
