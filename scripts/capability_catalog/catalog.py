"""Discover and render the public Optimizr Actions capability surface."""

from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
from typing import Final


SCHEMA_VERSION: Final = 1
ENTRY_KEYS: Final = (
    "kind",
    "maturity",
    "metadata_status",
    "path",
    "source_sha256",
)


def _is_public_template(path: Path, templates_root: Path) -> bool:
    relative_parts = path.relative_to(templates_root).parts
    return path.is_file() and all(
        part != "__pycache__" and not part.startswith(".")
        for part in relative_parts
    )


def discover_public_artifacts(root: Path) -> list[tuple[str, str]]:
    """Return sorted ``(path, kind)`` pairs for the public repository surface."""

    candidates: list[tuple[Path, str]] = []

    workflows_root = root / ".github" / "workflows"
    if workflows_root.exists():
        candidates.extend((path, "workflow") for path in workflows_root.glob("_*.yml"))

    actions_root = root / ".github" / "actions"
    if actions_root.exists():
        candidates.extend((path, "action") for path in actions_root.glob("*/action.yml"))

    templates_root = root / "templates"
    if templates_root.exists():
        candidates.extend(
            (path, "template")
            for path in templates_root.rglob("*")
            if _is_public_template(path, templates_root)
        )

    discovered = {
        (path.relative_to(root).as_posix(), kind)
        for path, kind in candidates
        if path.is_file()
    }
    return sorted(discovered, key=lambda item: item[0])


def build_catalog(root: Path) -> dict[str, object]:
    """Build the canonical catalog document for ``root``."""

    artifacts: list[dict[str, str]] = []
    for relative_path, kind in discover_public_artifacts(root):
        source = (root / relative_path).read_bytes()
        artifacts.append(
            {
                "path": relative_path,
                "kind": kind,
                "source_sha256": sha256(source).hexdigest(),
                "maturity": (
                    "canonical-template" if kind == "template" else "stable-v1"
                ),
                "metadata_status": "unclassified",
            }
        )

    return {
        "schema_version": SCHEMA_VERSION,
        "artifacts": artifacts,
    }


def render_catalog(root: Path) -> str:
    """Serialize the canonical catalog deterministically."""

    return json.dumps(
        build_catalog(root),
        indent=2,
        sort_keys=True,
    ) + "\n"
