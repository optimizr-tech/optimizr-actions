"""Parse Vitest coverage-summary JSON into a normalized metric."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Literal

from scripts.quality_gate.metrics import CoverageMetric, metric_to_dict

App = Literal["storefront", "admin"]


def parse(path: Path, app: App) -> CoverageMetric:
    data = json.loads(path.read_text(encoding="utf-8"))
    total = data.get("total")
    if not isinstance(total, dict):
        raise ValueError(f"{path}: missing 'total' object")
    lines = total.get("lines", {})
    branches = total.get("branches", {})
    return CoverageMetric(
        tool="vitest",
        scope=f"frontend-{app}",  # type: ignore[arg-type]
        line_pct=float(lines.get("pct", 0.0)),
        line_covered=int(lines.get("covered", 0)),
        line_total=int(lines.get("total", 0)),
        branch_pct=float(branches.get("pct", 0.0)),
        branch_covered=int(branches.get("covered", 0)),
        branch_total=int(branches.get("total", 0)),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("path", type=Path)
    parser.add_argument("--app", required=True, choices=("storefront", "admin"))
    args = parser.parse_args(argv)
    json.dump(metric_to_dict(parse(args.path, args.app)), sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
