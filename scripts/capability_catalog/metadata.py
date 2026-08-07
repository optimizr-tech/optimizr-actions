"""Curated artifact metadata that enriches the machine-derived capability catalog."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Final, Mapping

CATEGORIES: Final = (
    "test",
    "build",
    "security",
    "release",
    "deploy",
    "governance",
    "operations-adapter",
)
TRUST_BOUNDARIES: Final = ("trusted-push", "trusted-pr", "untrusted-pr")
RUNNER_KINDS: Final = ("hosted", "self-hosted-persistent", "self-hosted-ephemeral")
METADATA_SCHEMA_VERSION: Final = 1
CURATED_KEYS: Final = frozenset(
    {
        "category",
        "runner",
        "trust_boundary",
        "evidence",
        "examples",
        "known_limitations",
    }
)


class MetadataError(ValueError):
    """Raised when curated metadata violates the catalog contract."""


def load_curated_metadata(path: Path) -> dict[str, Mapping[str, object]]:
    """Load and validate the curated artifact metadata document."""
    if not path.exists():
        return {}
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, Mapping):
        raise MetadataError("curated metadata document must be a JSON object")
    if document.get("schema_version") != METADATA_SCHEMA_VERSION:
        raise MetadataError(
            f"curated metadata schema_version must be {METADATA_SCHEMA_VERSION}"
        )
    entries = document.get("entries")
    if not isinstance(entries, Mapping):
        raise MetadataError("curated metadata must define an `entries` object")
    for artifact, entry in entries.items():
        if not isinstance(artifact, str) or not artifact:
            raise MetadataError("curated metadata keys must be non-empty artifact paths")
        if not isinstance(entry, Mapping):
            raise MetadataError(f"curated metadata for `{artifact}` must be an object")
        unknown = set(entry) - CURATED_KEYS
        if unknown:
            raise MetadataError(
                f"curated metadata for `{artifact}` has unknown keys: "
                + ", ".join(sorted(unknown))
            )
        category = entry.get("category")
        if category is not None and category not in CATEGORIES:
            raise MetadataError(
                f"curated metadata for `{artifact}` has invalid category `{category}`"
            )
        runner = entry.get("runner")
        if runner is not None:
            if not isinstance(runner, list) or not runner:
                raise MetadataError(
                    f"curated metadata for `{artifact}` requires a non-empty runner list"
                )
            invalid = [kind for kind in runner if kind not in RUNNER_KINDS]
            if invalid:
                raise MetadataError(
                    f"curated metadata for `{artifact}` has invalid runner kinds: "
                    + ", ".join(invalid)
                )
            if len(set(runner)) != len(runner):
                raise MetadataError(
                    f"curated metadata for `{artifact}` repeats runner kinds"
                )
        trust_boundary = entry.get("trust_boundary")
        if trust_boundary is not None and trust_boundary not in TRUST_BOUNDARIES:
            raise MetadataError(
                f"curated metadata for `{artifact}` has invalid trust_boundary "
                f"`{trust_boundary}`"
            )
        for key in ("evidence", "known_limitations"):
            value = entry.get(key)
            if value is not None and not isinstance(value, str):
                raise MetadataError(
                    f"curated metadata for `{artifact}` field `{key}` must be a string"
                )
        examples = entry.get("examples")
        if examples is not None and (
            not isinstance(examples, list) or not all(isinstance(item, str) for item in examples)
        ):
            raise MetadataError(
                f"curated metadata for `{artifact}` field `examples` must be a string list"
            )
    return dict(entries)


def classify_entry(curated: Mapping[str, object]) -> str:
    """Derive the metadata status for one artifact from its curated entry."""
    trust_boundary = curated.get("trust_boundary")
    evidence = curated.get("evidence")
    if trust_boundary and evidence:
        return "classified"
    if trust_boundary or evidence:
        return "partial"
    return "unclassified"


def incomplete_artifacts(artifacts: list[Mapping[str, object]]) -> list[str]:
    """Return artifact paths whose metadata is not fully classified."""
    return sorted(
        entry["path"]
        for entry in artifacts
        if entry.get("metadata_status") != "classified"
    )


def orphaned_metadata(
    curated: Mapping[str, Mapping[str, object]],
    artifacts: list[Mapping[str, object]],
) -> list[str]:
    """Return curated paths that do not match any discovered public artifact."""
    discovered = {str(entry["path"]) for entry in artifacts}
    return sorted(path for path in curated if path not in discovered)
