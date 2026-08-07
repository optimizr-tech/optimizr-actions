"""Discover, enrich, and render the public Optimizr Actions capability surface."""

from __future__ import annotations

from hashlib import sha256
import json
import re
from pathlib import Path
from typing import Final, Mapping

from .metadata import (
    RUNNER_KINDS,
    classify_entry,
    load_curated_metadata,
)


SCHEMA_VERSION: Final = 2
METADATA_FILE: Final = "catalog/artifact_metadata.json"
ENTRY_KEYS: Final = (
    "path",
    "kind",
    "source_sha256",
    "maturity",
    "category",
    "runner",
    "trust_boundary",
    "inputs",
    "outputs",
    "permissions",
    "evidence",
    "examples",
    "known_limitations",
    "metadata_status",
)

HOSTED_RUNNER_RE = re.compile(r"(?:ubuntu|windows|macos)-")
KEY_LINE_RE = re.compile(r"^(\s*)([A-Za-z0-9_-]+):\s*(.*)$")
RUNS_ON_RE = re.compile(r"(?m)^\s+runs-on\s*:\s*(.+)$")


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


def _block_children(content: str, block_start: int, base_indent: int) -> dict[str, str]:
    """Parse direct ``key: value`` children of an indented YAML block.

    Only lines indented exactly ``base_indent + 2`` are treated as direct
    children; deeper nested metadata lines are ignored.
    """
    children: dict[str, str] = {}
    lines = content.splitlines()
    target_indent = base_indent + 2
    for line in lines[block_start + 1:]:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip())
        if indent <= base_indent:
            break
        if indent != target_indent:
            continue
        match = KEY_LINE_RE.match(line)
        if match:
            children[match.group(2)] = match.group(3).strip()
    return children


def _top_level_block(content: str, name: str) -> dict[str, str]:
    """Return direct children of a top-level ``name:`` block."""
    match = re.search(rf"(?m)^{re.escape(name)}\s*:\s*$", content)
    if match is None:
        return {}
    return _block_children(content, _line_index(content, match.start()), 0)


def _line_index(content: str, char_offset: int) -> int:
    """Convert a character offset into a 0-based line index."""
    return content.count("\n", 0, char_offset)


def _block_form_keys(children: Mapping[str, str]) -> dict[str, str]:
    """Keep only block-form entries (nested metadata), dropping ``key: value`` rows."""
    return {key: value for key, value in children.items() if not value}


def _workflow_call_io(content: str, name: str) -> dict[str, str]:
    """Extract ``inputs``/``outputs`` declared under ``on.workflow_call``."""
    call = re.search(r"(?m)^\s{2,}workflow_call\s*:\s*$", content)
    if call is None:
        return {}
    lines = content.splitlines()
    call_line = _line_index(content, call.start())
    call_indent = len(lines[call_line]) - len(lines[call_line].lstrip())
    block_index = None
    for index, line in enumerate(lines[call_line + 1:], start=call_line + 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip())
        if indent <= call_indent:
            break
        if line.strip() == f"{name}:":
            block_index = index
            break
    if block_index is None:
        return {}
    children = _block_children(content, block_index, len(lines[block_index]) - len(lines[block_index].lstrip()))
    return _block_form_keys(children)


def _extract_io(content: str, kind: str, name: str) -> dict[str, str]:
    """Extract declared ``inputs`` or ``outputs`` for an artifact.

    Only block-form entries (empty inline value, nested metadata) are kept;
    entry metadata keys such as ``description``/``required``/``type`` are
    nested one level deeper and are discarded here.
    """
    if kind == "workflow":
        return _workflow_call_io(content, name)
    if kind == "action":
        return _top_level_block(content, name)
    return {}


def _extract_runs_on(content: str) -> list[str]:
    """Derive supported runner kinds from ``runs-on`` declarations."""
    kinds: set[str] = set()
    for raw in RUNS_ON_RE.findall(content):
        if "self-hosted" in raw:
            kinds.add("self-hosted-persistent")
        if "ephemeral" in raw:
            kinds.add("self-hosted-ephemeral")
        if HOSTED_RUNNER_RE.search(raw):
            kinds.add("hosted")
    return [kind for kind in RUNNER_KINDS if kind in kinds]


def _caller_selectable_runner(inputs: Mapping[str, str]) -> bool:
    """A ``runner_json`` input means the caller selects hosted or self-hosted."""
    return "runner_json" in inputs


def _category_for(relative_path: str) -> str:
    """Best-effort category derivation; curated metadata may override it."""
    name = relative_path.lower()
    if any(token in name for token in ("security", "sast", "trivy", "dependency-policy", "supply-chain")):
        return "security"
    if any(token in name for token in ("release", "badge")):
        return "release"
    if any(token in name for token in ("deploy", "snapshot", "prune", "healthcheck", "network", "migration", "probe", "verification", "manifest", "env-file")):
        return "deploy"
    if any(token in name for token in ("validation-gate", "repository-validation", "attestation", "authorization", "automerge")):
        return "governance"
    if any(token in name for token in ("lint", "test", "commitlint", "validate-pr", "pr-metadata", "quality-gate", "compose")):
        return "test"
    return "test"


def _normalized_bytes(source: bytes) -> bytes:
    """Normalize line endings so hashes match the canonical repository content.

    Git stores text files with LF regardless of checkout ``core.autocrlf``;
    hashing must be independent of the platform that generated the catalog.
    """
    return source.replace(b"\r\n", b"\n").replace(b"\r", b"\n")


def build_catalog(root: Path) -> dict[str, object]:
    """Build the canonical enriched catalog document for ``root``."""

    curated = load_curated_metadata(root / METADATA_FILE)
    artifacts: list[dict[str, object]] = []
    for relative_path, kind in discover_public_artifacts(root):
        source = (root / relative_path).read_bytes()
        canonical_source = _normalized_bytes(source)
        content = canonical_source.decode("utf-8")
        entry_curated = curated.get(relative_path, {})
        inputs = _extract_io(content, kind, "inputs")
        runner = list(entry_curated.get("runner") or _extract_runs_on(content))
        if not runner and kind == "action":
            runner = list(RUNNER_KINDS)
        if not runner and kind == "workflow" and _caller_selectable_runner(inputs):
            runner = list(RUNNER_KINDS)
        artifacts.append(
            {
                "path": relative_path,
                "kind": kind,
                "source_sha256": sha256(canonical_source).hexdigest(),
                "maturity": (
                    "canonical-template" if kind == "template" else "stable-v1"
                ),
                "category": entry_curated.get("category") or _category_for(relative_path),
                "runner": runner,
                "trust_boundary": entry_curated.get("trust_boundary") or "",
                "inputs": inputs,
                "outputs": _extract_io(content, kind, "outputs"),
                "permissions": _top_level_block(content, "permissions"),
                "evidence": entry_curated.get("evidence") or "",
                "examples": entry_curated.get("examples") or [],
                "known_limitations": entry_curated.get("known_limitations") or "",
                "metadata_status": classify_entry(entry_curated),
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
