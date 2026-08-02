"""Backward-compatible metrics.json quality-gate entrypoint."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from scripts.quality_gate.compare import DEFAULT_THRESHOLDS, Threshold, Thresholds, compare
from scripts.quality_gate.metrics import Metric, metric_from_dict
from scripts.quality_gate.post_comment import upsert
from scripts.quality_gate.render_comment import render


def _load_metrics(path: Path) -> list[Metric]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(payload, dict):
        payload = payload.get("metrics", [])
    if not isinstance(payload, list):
        raise ValueError(f"{path}: metrics payload must be a list")
    return [metric_from_dict(item) for item in payload if isinstance(item, dict)]


def _metrics_file(path: Path) -> Path:
    return path / "metrics.json" if path.is_dir() else path


def _threshold(default: Threshold, payload: object) -> Threshold:
    if not isinstance(payload, dict):
        return default
    return Threshold(
        yellow=float(payload.get("yellow", default.yellow)),
        red=float(payload.get("red", default.red)),
        direction=str(payload.get("direction", default.direction)),  # type: ignore[arg-type]
        smaller_is_worse=bool(payload.get("smaller_is_worse", default.smaller_is_worse)),
    )


def _load_thresholds(path: Path) -> Thresholds:
    if not path.is_file():
        return DEFAULT_THRESHOLDS
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("threshold configuration must be a JSON object")
    defaults = DEFAULT_THRESHOLDS
    return Thresholds(
        coverage_backend=_threshold(defaults.coverage_backend, payload.get("coverage_backend")),
        coverage_backend_branches=_threshold(
            defaults.coverage_backend_branches,
            payload.get("coverage_backend_branches"),
        ),
        coverage_frontend=_threshold(defaults.coverage_frontend, payload.get("coverage_frontend")),
        bundle_unique_chunks=_threshold(
            defaults.bundle_unique_chunks,
            payload.get("bundle_unique_chunks"),
        ),
        duplication_backend=_threshold(
            defaults.duplication_backend,
            payload.get("duplication_backend"),
        ),
        duplication_frontend=_threshold(
            defaults.duplication_frontend,
            payload.get("duplication_frontend"),
        ),
        duplication=_threshold(defaults.duplication, payload.get("duplication")),
        duplication_frontend_ceiling_yellow_pct=float(
            payload.get(
                "duplication_frontend_ceiling_yellow_pct",
                defaults.duplication_frontend_ceiling_yellow_pct,
            )
        ),
        duplication_frontend_ceiling_red_pct=float(
            payload.get(
                "duplication_frontend_ceiling_red_pct",
                defaults.duplication_frontend_ceiling_red_pct,
            )
        ),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--current", type=Path, required=True)
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--thresholds", type=Path, required=True)
    parser.add_argument("--repo")
    parser.add_argument("--pr", type=int)
    parser.add_argument("--head-sha")
    parser.add_argument("--post", action="store_true")
    parser.add_argument("--output", type=Path, default=Path("quality-gate-report.json"))
    args = parser.parse_args(argv)

    current = _load_metrics(_metrics_file(args.current))
    baseline = (
        _load_metrics(_metrics_file(args.baseline))
        if args.baseline and _metrics_file(args.baseline).is_file()
        else []
    )
    report = compare(current, baseline, _load_thresholds(args.thresholds))
    args.output.write_text(
        json.dumps(report.to_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    body = render(report, args.head_sha)
    print(body, end="")

    if args.post:
        if not args.repo or not args.pr:
            raise ValueError("--post requires --repo and --pr")
        token = os.environ.get("GH_TOKEN", "").strip()
        if not token:
            raise ValueError("GH_TOKEN is required to post a quality-gate comment")
        upsert(args.repo, args.pr, token, body)
    return 1 if report.overall == "red" else 0


if __name__ == "__main__":
    raise SystemExit(main())
