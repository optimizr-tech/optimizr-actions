"""Parse Next.js build manifests into a normalized bundle metric."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Literal

from scripts.quality_gate.metrics import BundleMetric, metric_to_dict

App = Literal["storefront", "admin"]


def _chunks(manifest: dict[str, Any]) -> tuple[set[str], int]:
    all_chunks: list[str] = []
    pages = manifest.get("pages") or {}
    if isinstance(pages, dict):
        for chunks in pages.values():
            if isinstance(chunks, list):
                all_chunks.extend(value for value in chunks if isinstance(value, str))
    for key in ("polyfillFiles", "lowPriorityFiles", "rootMainFiles", "devFiles"):
        chunks = manifest.get(key)
        if isinstance(chunks, list):
            all_chunks.extend(value for value in chunks if isinstance(value, str))
    return set(all_chunks), len(all_chunks)


def _page_chunk_count(manifest: dict[str, Any]) -> int:
    pages = manifest.get("pages") or {}
    if not isinstance(pages, dict):
        return 0
    return sum(
        sum(isinstance(chunk, str) for chunk in chunks)
        for chunks in pages.values()
        if isinstance(chunks, list)
    )


def parse(build_manifest_path: Path, app_paths_path: Path, app: App) -> BundleMetric:
    build = json.loads(build_manifest_path.read_text(encoding="utf-8"))
    app_paths = json.loads(app_paths_path.read_text(encoding="utf-8"))
    if not isinstance(build, dict) or not isinstance(app_paths, dict):
        raise ValueError("Next.js manifests must be JSON objects")
    unique, _ = _chunks(build)
    return BundleMetric(
        tool="next",
        scope=f"frontend-{app}",  # type: ignore[arg-type]
        unique_chunks=len(unique),
        routes=len(app_paths),
        pages_chunks_sum=_page_chunk_count(build),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--build-manifest", type=Path, required=True)
    parser.add_argument("--app-paths", type=Path, required=True)
    parser.add_argument("--app", required=True, choices=("storefront", "admin"))
    args = parser.parse_args(argv)
    metric = parse(args.build_manifest, args.app_paths, args.app)
    json.dump(metric_to_dict(metric), sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
