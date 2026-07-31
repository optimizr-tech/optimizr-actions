"""Parse jscpd JSON into a normalized duplication metric."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import get_args

from scripts.quality_gate.metrics import DuplicationMetric, Scope, metric_to_dict


def parse(path: Path, scope: Scope) -> DuplicationMetric:
    data = json.loads(path.read_text(encoding="utf-8"))
    statistics = data.get("statistics")
    total = statistics.get("total") if isinstance(statistics, dict) else None
    if not isinstance(total, dict):
        raise ValueError(f"{path}: missing 'statistics.total' object")
    return DuplicationMetric(
        tool="jscpd",
        scope=scope,
        dup_pct=float(total.get("percentage", 0.0)),
        dup_lines=int(total.get("duplicatedLines", 0)),
        total_lines=int(total.get("lines", 0)),
        clones=int(total.get("clones", 0)),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("path", type=Path)
    parser.add_argument("--scope", required=True, choices=get_args(Scope))
    args = parser.parse_args(argv)
    json.dump(metric_to_dict(parse(args.path, args.scope)), sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
