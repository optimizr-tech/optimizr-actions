"""Parse pytest-cov JSON into a normalized coverage metric."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from scripts.quality_gate.metrics import CoverageMetric, Scope, metric_to_dict


def parse(path: Path, scope: Scope = "backend") -> CoverageMetric:
    data = json.loads(path.read_text(encoding="utf-8"))
    totals = data.get("totals")
    if not isinstance(totals, dict):
        raise ValueError(f"{path}: missing 'totals' object")
    return CoverageMetric(
        tool="pytest",
        scope=scope,
        line_pct=float(totals.get("percent_covered", 0.0)),
        line_covered=int(totals.get("covered_lines", 0)),
        line_total=int(totals.get("num_statements", 0)),
        branch_pct=float(totals.get("percent_branches_covered", 0.0)),
        branch_covered=int(totals.get("covered_branches", 0)),
        branch_total=int(totals.get("num_branches", 0)),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("path", type=Path)
    parser.add_argument("--scope", default="backend", choices=("backend",))
    args = parser.parse_args(argv)
    json.dump(metric_to_dict(parse(args.path, args.scope)), sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
