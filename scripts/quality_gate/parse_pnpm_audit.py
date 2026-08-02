"""Parse pnpm audit JSON into a normalized security metric."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import get_args

from scripts.quality_gate.metrics import Scope, SecurityMetric, metric_to_dict


def parse(path: Path, scope: Scope) -> SecurityMetric:
    data = json.loads(path.read_text(encoding="utf-8"))
    metadata = data.get("metadata")
    vulnerabilities = metadata.get("vulnerabilities") if isinstance(metadata, dict) else None
    if not isinstance(vulnerabilities, dict):
        raise ValueError(f"{path}: missing 'metadata.vulnerabilities'")
    return SecurityMetric(
        tool="pnpm-audit",
        scope=scope,
        critical=int(vulnerabilities.get("critical", 0)),
        high=int(vulnerabilities.get("high", 0)),
        medium=int(vulnerabilities.get("moderate", 0)),
        low=int(vulnerabilities.get("low", 0)),
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
