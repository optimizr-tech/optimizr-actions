"""Generate or verify the committed public capability catalog."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

from .catalog import build_catalog, render_catalog
from .metadata import incomplete_artifacts, load_curated_metadata, orphaned_metadata


ROOT = Path(__file__).resolve().parents[2]
CATALOG_PATH = ROOT / "catalog" / "capabilities.json"


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Fail when the committed catalog differs from live discovery.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    catalog = build_catalog(ROOT)
    rendered = render_catalog(ROOT)
    incomplete = incomplete_artifacts(catalog["artifacts"])
    if incomplete:
        print(
            "capability catalog metadata is incomplete for: "
            + ", ".join(sorted(incomplete)),
            file=sys.stderr,
        )
        return 1
    orphaned = orphaned_metadata(
        load_curated_metadata(ROOT / "catalog" / "artifact_metadata.json"),
        catalog["artifacts"],
    )
    if orphaned:
        print(
            "curated metadata references undiscovered artifacts: "
            + ", ".join(orphaned),
            file=sys.stderr,
        )
        return 1

    if args.check:
        committed = (
            CATALOG_PATH.read_text(encoding="utf-8")
            if CATALOG_PATH.exists()
            else ""
        )
        if committed == rendered:
            print("capability catalog is current")
            return 0
        print("capability catalog drift detected", file=sys.stderr)
        print(rendered, end="")
        return 1

    CATALOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    CATALOG_PATH.write_text(rendered, encoding="utf-8")
    print(f"wrote {CATALOG_PATH.relative_to(ROOT).as_posix()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
