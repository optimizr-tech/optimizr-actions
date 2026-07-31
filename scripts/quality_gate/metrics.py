"""Normalized quality-gate metric models and JSON helpers."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Literal

Scope = Literal["backend", "frontend-storefront", "frontend-admin"]


@dataclass(frozen=True)
class CoverageMetric:
    tool: Literal["pytest", "vitest"]
    scope: Scope
    line_pct: float
    line_covered: int
    line_total: int
    branch_pct: float
    branch_covered: int
    branch_total: int

    @property
    def kind(self) -> Literal["coverage"]:
        return "coverage"


@dataclass(frozen=True)
class SecurityMetric:
    tool: Literal["bandit", "pip-audit", "pnpm-audit"]
    scope: Scope
    critical: int
    high: int
    medium: int
    low: int

    @property
    def kind(self) -> Literal["security"]:
        return "security"

    @property
    def total(self) -> int:
        return self.critical + self.high + self.medium + self.low


@dataclass(frozen=True)
class DuplicationMetric:
    tool: Literal["jscpd"]
    scope: Scope
    dup_pct: float
    dup_lines: int
    total_lines: int
    clones: int

    @property
    def kind(self) -> Literal["duplication"]:
        return "duplication"


@dataclass(frozen=True)
class BundleMetric:
    tool: Literal["next"]
    scope: Scope
    unique_chunks: int
    routes: int
    pages_chunks_sum: int

    @property
    def kind(self) -> Literal["bundle"]:
        return "bundle"


Metric = CoverageMetric | BundleMetric | DuplicationMetric | SecurityMetric


def metric_to_dict(metric: Metric) -> dict[str, Any]:
    payload: dict[str, Any] = asdict(metric)
    payload["kind"] = metric.kind
    return payload


def metric_from_dict(payload: dict[str, Any]) -> Metric:
    kind = payload.get("kind")
    data = {key: value for key, value in payload.items() if key != "kind"}
    if kind == "coverage":
        return CoverageMetric(**data)
    if kind == "bundle":
        return BundleMetric(**data)
    if kind == "duplication":
        return DuplicationMetric(**data)
    if kind == "security":
        return SecurityMetric(**data)
    raise ValueError(f"unknown metric kind: {kind!r}")
