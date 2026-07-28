"""Create component-level, value-free PostgreSQL migration diagnostics."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
from typing import Any


_SAFE_COMPONENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _safe_component_name(raw_name: str, index: int, used: set[str]) -> str:
    candidate = raw_name.strip()
    if not _SAFE_COMPONENT.fullmatch(candidate):
        candidate = f"component_{index}"
    if candidate not in used:
        used.add(candidate)
        return candidate

    suffix = 2
    while f"{candidate}_{suffix}" in used:
        suffix += 1
    unique = f"{candidate}_{suffix}"
    used.add(unique)
    return unique


def _json_value(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def _verification_pairs(raw_output: str) -> list[tuple[str, str]]:
    text = raw_output.strip()
    if not text:
        return []

    try:
        decoded = json.loads(text)
    except json.JSONDecodeError:
        decoded = None

    if isinstance(decoded, dict):
        return [(str(name), _json_value(value)) for name, value in sorted(decoded.items())]

    if isinstance(decoded, list) and all(
        isinstance(item, dict) and "name" in item and "value" in item for item in decoded
    ):
        return [(str(item["name"]), _json_value(item["value"])) for item in decoded]

    lines = text.splitlines()
    if len(lines) == 1 and "\t" not in lines[0]:
        return [("verification", lines[0])]

    pairs: list[tuple[str, str]] = []
    for index, line in enumerate(lines, start=1):
        if "\t" in line:
            name, value = line.split("\t", 1)
            pairs.append((name, value))
        else:
            pairs.append((f"verification_{index}", line))
    return pairs


def build_component_manifest(raw_output: str, side: str, overall_sha256: str) -> dict[str, Any]:
    """Hash verification values while retaining only safe component names."""

    if side not in {"source", "target"}:
        raise ValueError("side must be source or target")
    if not _SHA256.fullmatch(overall_sha256):
        raise ValueError("overall_sha256 must be a lowercase SHA-256 digest")

    used: set[str] = set()
    components = []
    for index, (raw_name, value) in enumerate(_verification_pairs(raw_output), start=1):
        name = _safe_component_name(raw_name, index, used)
        components.append(
            {
                "name": name,
                "sha256": hashlib.sha256(value.encode("utf-8")).hexdigest(),
            }
        )

    components.sort(key=lambda component: component["name"])
    return {"side": side, "sha256": overall_sha256, "components": components}


def build_comparison_manifest(source: dict[str, Any], target: dict[str, Any]) -> dict[str, Any]:
    """Return a sanitized comparison containing no verification values."""

    if source.get("side") != "source" or target.get("side") != "target":
        raise ValueError("comparison requires source and target manifests")
    return {
        "schema_version": 1,
        "status": "match" if source["sha256"] == target["sha256"] else "mismatch",
        "source": source,
        "target": target,
    }


def _write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=True, sort_keys=True) + "\n", encoding="utf-8")


def _write_component(args: argparse.Namespace) -> None:
    raw_output = Path(args.input).read_text(encoding="utf-8")
    _write_json(
        Path(args.output),
        build_component_manifest(raw_output, args.side, args.overall_sha256),
    )


def _write_comparison(args: argparse.Namespace) -> None:
    source = json.loads(Path(args.source).read_text(encoding="utf-8"))
    target = json.loads(Path(args.target).read_text(encoding="utf-8"))
    _write_json(Path(args.output), build_comparison_manifest(source, target))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    component = subparsers.add_parser("component")
    component.add_argument("--input", required=True)
    component.add_argument("--side", choices=("source", "target"), required=True)
    component.add_argument("--overall-sha256", required=True)
    component.add_argument("--output", required=True)
    component.set_defaults(handler=_write_component)

    comparison = subparsers.add_parser("comparison")
    comparison.add_argument("--source", required=True)
    comparison.add_argument("--target", required=True)
    comparison.add_argument("--output", required=True)
    comparison.set_defaults(handler=_write_comparison)

    args = parser.parse_args()
    args.handler(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
