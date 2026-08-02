"""Quality-gate baseline and pull-request orchestration."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Callable

from scripts.quality_gate.compare import compare
from scripts.quality_gate.metrics import Metric, metric_from_dict, metric_to_dict
from scripts.quality_gate.parse_bandit import parse as parse_bandit
from scripts.quality_gate.parse_jscpd import parse as parse_jscpd
from scripts.quality_gate.parse_pip_audit import parse as parse_pip_audit
from scripts.quality_gate.parse_pnpm_audit import parse as parse_pnpm_audit
from scripts.quality_gate.parse_pytest_cov import parse as parse_pytest_cov
from scripts.quality_gate.parse_vitest_cov import parse as parse_vitest_cov
from scripts.quality_gate.post_comment import upsert
from scripts.quality_gate.render_comment import render


def _json_files(root: Path) -> list[Path]:
    if not root.exists():
        return []
    return sorted(
        path
        for path in root.rglob("*.json")
        if path.is_file() and not path.is_symlink()
    )


def _scope(path: Path) -> str:
    lowered = path.as_posix().lower()
    if "admin" in lowered:
        return "frontend-admin"
    if "storefront" in lowered or "frontend" in lowered:
        return "frontend-storefront"
    return "backend"


def _try(parser: Callable[..., Metric], path: Path, *args: object) -> Metric | None:
    try:
        return parser(path, *args)
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        return None


def collect_metrics(root: Path) -> list[Metric]:
    metrics: list[Metric] = []
    for path in _json_files(root):
        name = path.name.lower()
        scope = _scope(path)
        metric: Metric | None = None
        if "bandit" in name:
            metric = _try(parse_bandit, path, scope)
        elif "pip-audit" in name or "pip_audit" in name:
            metric = _try(parse_pip_audit, path, scope)
        elif "pnpm-audit" in name or "pnpm_audit" in name:
            metric = _try(parse_pnpm_audit, path, scope)
        elif "jscpd" in name or "duplication" in name:
            metric = _try(parse_jscpd, path, scope)
        elif "coverage-summary" in name or "vitest" in name:
            app = "admin" if scope == "frontend-admin" else "storefront"
            metric = _try(parse_vitest_cov, path, app)
        elif "coverage" in name or "pytest" in name:
            metric = _try(parse_pytest_cov, path, "backend")
        if metric is not None:
            metrics.append(metric)
    deduplicated: dict[tuple[str, str, str], Metric] = {}
    for metric in metrics:
        deduplicated[(metric.kind, metric.scope, metric.tool)] = metric
    return [deduplicated[key] for key in sorted(deduplicated)]


def _baseline_payload(head_sha: str, metrics: list[Metric]) -> dict[str, object]:
    return {
        "schema_version": 1,
        "head_sha": head_sha,
        "metrics": [metric_to_dict(metric) for metric in metrics],
    }


def _read_baseline(path: Path | None) -> list[Metric]:
    if path is None or not path.is_file():
        return []
    payload = json.loads(path.read_text(encoding="utf-8"))
    values = payload.get("metrics") if isinstance(payload, dict) else payload
    if not isinstance(values, list):
        raise ValueError("baseline metrics must be a list")
    return [metric_from_dict(value) for value in values if isinstance(value, dict)]


def _verdict_exit(overall: str) -> int:
    return {"green": 0, "yellow": 1, "red": 2, "unknown": 3}[overall]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifacts-dir", type=Path, required=True)
    parser.add_argument("--head-sha", required=True)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("emit-baseline")
    pr = subparsers.add_parser("pr")
    pr.add_argument("--pr", type=int, required=True)
    pr.add_argument("--baseline", type=Path)
    pr.add_argument("--post", action="store_true")
    pr.add_argument("--repo")
    args = parser.parse_args(argv)

    metrics = collect_metrics(args.artifacts_dir)
    if args.command == "emit-baseline":
        print(json.dumps(_baseline_payload(args.head_sha, metrics), indent=2, sort_keys=True))
        return 0

    report = compare(metrics, _read_baseline(args.baseline))
    body = render(report, args.head_sha)
    print(body, end="")
    Path("quality-gate-report.json").write_text(
        json.dumps(report.to_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    if args.post:
        if not args.repo:
            raise ValueError("--post requires --repo")
        token = os.environ.get("GH_TOKEN", "").strip()
        if not token:
            raise ValueError("GH_TOKEN is required to post a quality-gate comment")
        upsert(args.repo, args.pr, token, body)
    return _verdict_exit(report.overall)


if __name__ == "__main__":
    raise SystemExit(main())
