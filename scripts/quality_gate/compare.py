"""Compare normalized PR metrics against a reviewed main baseline."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Literal

from scripts.quality_gate.metrics import (
    BundleMetric,
    CoverageMetric,
    DuplicationMetric,
    Metric,
    Scope,
    SecurityMetric,
)

Severity = Literal["green", "yellow", "red", "unknown"]
Direction = Literal["delta_pp", "delta_pct"]


@dataclass(frozen=True)
class Threshold:
    yellow: float
    red: float
    direction: Direction
    smaller_is_worse: bool = True


@dataclass(frozen=True)
class Thresholds:
    coverage_backend: Threshold = field(
        default_factory=lambda: Threshold(-0.25, -1.0, "delta_pp")
    )
    coverage_backend_branches: Threshold = field(
        default_factory=lambda: Threshold(-1.0, -3.0, "delta_pp")
    )
    coverage_frontend: Threshold = field(
        default_factory=lambda: Threshold(-1.0, -3.0, "delta_pp")
    )
    bundle_unique_chunks: Threshold = field(
        default_factory=lambda: Threshold(5.0, 10.0, "delta_pct", False)
    )
    duplication_backend: Threshold = field(
        default_factory=lambda: Threshold(1.0, 3.0, "delta_pp", False)
    )
    duplication_frontend: Threshold = field(
        default_factory=lambda: Threshold(2.0, 4.0, "delta_pp", False)
    )
    duplication: Threshold = field(
        default_factory=lambda: Threshold(1.0, 3.0, "delta_pp", False)
    )
    duplication_frontend_ceiling_yellow_pct: float = 5.0
    duplication_frontend_ceiling_red_pct: float = 6.0


DEFAULT_THRESHOLDS = Thresholds()


@dataclass(frozen=True)
class Verdict:
    metric: str
    scope: Scope
    pr_value: float
    main_value: float
    delta: float
    delta_pct: float
    severity: Severity


@dataclass(frozen=True)
class Report:
    verdicts: tuple[Verdict, ...]
    overall: Severity

    def to_dict(self) -> dict[str, object]:
        return {
            "overall": self.overall,
            "verdicts": [asdict(verdict) for verdict in self.verdicts],
        }


def _severity_for_delta(delta: float, threshold: Threshold) -> Severity:
    if threshold.smaller_is_worse:
        if delta <= threshold.red:
            return "red"
        if delta <= threshold.yellow:
            return "yellow"
        return "green"
    if delta >= threshold.red:
        return "red"
    if delta >= threshold.yellow:
        return "yellow"
    return "green"


def _delta_pct(current: float, baseline: float) -> float:
    if baseline == 0:
        return 0.0
    return (current - baseline) / baseline * 100.0


def _max_severity(values: list[Severity]) -> Severity:
    order: tuple[Severity, ...] = ("green", "yellow", "unknown", "red")
    if not values:
        return "unknown"
    return max(values, key=order.index)


def _key(metric: Metric) -> tuple[str, Scope, str]:
    return metric.kind, metric.scope, metric.tool


def _scalar(metric: Metric) -> float:
    if isinstance(metric, CoverageMetric):
        return metric.line_pct
    if isinstance(metric, DuplicationMetric):
        return metric.dup_pct
    if isinstance(metric, SecurityMetric):
        return float(metric.total)
    return float(metric.unique_chunks)


def _coverage_verdict(
    current: CoverageMetric, baseline: CoverageMetric, thresholds: Thresholds
) -> Verdict:
    delta = current.line_pct - baseline.line_pct
    threshold = (
        thresholds.coverage_backend
        if current.scope == "backend"
        else thresholds.coverage_frontend
    )
    return Verdict(
        metric=f"coverage.lines:{current.tool}",
        scope=current.scope,
        pr_value=current.line_pct,
        main_value=baseline.line_pct,
        delta=delta,
        delta_pct=_delta_pct(current.line_pct, baseline.line_pct),
        severity=_severity_for_delta(delta, threshold),
    )


def _branch_verdict(
    current: CoverageMetric, baseline: CoverageMetric, thresholds: Thresholds
) -> Verdict | None:
    if (
        current.scope != "backend"
        or current.branch_total <= 0
        or baseline.branch_total <= 0
    ):
        return None
    delta = current.branch_pct - baseline.branch_pct
    return Verdict(
        metric=f"coverage.branches:{current.tool}",
        scope=current.scope,
        pr_value=current.branch_pct,
        main_value=baseline.branch_pct,
        delta=delta,
        delta_pct=_delta_pct(current.branch_pct, baseline.branch_pct),
        severity=_severity_for_delta(delta, thresholds.coverage_backend_branches),
    )


def _bundle_verdict(
    current: BundleMetric, baseline: BundleMetric, thresholds: Thresholds
) -> Verdict:
    delta = float(current.unique_chunks - baseline.unique_chunks)
    delta_pct = _delta_pct(current.unique_chunks, baseline.unique_chunks)
    return Verdict(
        metric="bundle.unique_chunks:next",
        scope=current.scope,
        pr_value=float(current.unique_chunks),
        main_value=float(baseline.unique_chunks),
        delta=delta,
        delta_pct=delta_pct,
        severity=_severity_for_delta(delta_pct, thresholds.bundle_unique_chunks),
    )


def _duplication_verdict(
    current: DuplicationMetric,
    baseline: DuplicationMetric,
    thresholds: Thresholds,
) -> Verdict:
    delta = current.dup_pct - baseline.dup_pct
    threshold = (
        thresholds.duplication_backend
        if current.scope == "backend"
        else thresholds.duplication_frontend
    )
    severity = _severity_for_delta(delta, threshold)
    if current.scope != "backend":
        if current.dup_pct >= thresholds.duplication_frontend_ceiling_red_pct:
            severity = "red"
        elif current.dup_pct >= thresholds.duplication_frontend_ceiling_yellow_pct:
            severity = _max_severity([severity, "yellow"])
    return Verdict(
        metric="duplication.lines:jscpd",
        scope=current.scope,
        pr_value=current.dup_pct,
        main_value=baseline.dup_pct,
        delta=delta,
        delta_pct=_delta_pct(current.dup_pct, baseline.dup_pct),
        severity=severity,
    )


def _security_verdict(current: SecurityMetric, baseline: SecurityMetric) -> Verdict:
    if current.tool != baseline.tool:
        raise ValueError("security tool mismatch")
    if current.critical > baseline.critical or current.high > baseline.high:
        severity: Severity = "red"
    elif current.medium > baseline.medium:
        severity = "yellow"
    else:
        severity = "green"
    return Verdict(
        metric=f"security.findings:{current.tool}",
        scope=current.scope,
        pr_value=float(current.total),
        main_value=float(baseline.total),
        delta=float(current.total - baseline.total),
        delta_pct=_delta_pct(current.total, baseline.total),
        severity=severity,
    )


def compare(
    pr_metrics: list[Metric],
    baseline_metrics: list[Metric],
    thresholds: Thresholds | None = None,
) -> Report:
    active = thresholds or DEFAULT_THRESHOLDS
    baseline = {_key(metric): metric for metric in baseline_metrics}
    verdicts: list[Verdict] = []
    for current in pr_metrics:
        previous = baseline.get(_key(current))
        if previous is None:
            verdicts.append(
                Verdict(
                    metric=f"{current.kind}:{current.scope}",
                    scope=current.scope,
                    pr_value=_scalar(current),
                    main_value=0.0,
                    delta=0.0,
                    delta_pct=0.0,
                    severity="unknown",
                )
            )
            continue
        if isinstance(current, CoverageMetric) and isinstance(previous, CoverageMetric):
            verdicts.append(_coverage_verdict(current, previous, active))
            branch = _branch_verdict(current, previous, active)
            if branch is not None:
                verdicts.append(branch)
        elif isinstance(current, BundleMetric) and isinstance(previous, BundleMetric):
            verdicts.append(_bundle_verdict(current, previous, active))
        elif isinstance(current, DuplicationMetric) and isinstance(previous, DuplicationMetric):
            verdicts.append(_duplication_verdict(current, previous, active))
        elif isinstance(current, SecurityMetric) and isinstance(previous, SecurityMetric):
            verdicts.append(_security_verdict(current, previous))
        else:
            raise TypeError("quality-gate metric type mismatch")
    return Report(
        verdicts=tuple(verdicts),
        overall=_max_severity([verdict.severity for verdict in verdicts]),
    )
