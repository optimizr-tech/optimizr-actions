"""Render quality-gate verdicts as one idempotent PR comment."""

from __future__ import annotations

from scripts.quality_gate.compare import Report, Severity, Verdict

MARKER_PREFIX = "<!-- quality-gate:v1"
_BADGE: dict[Severity, str] = {
    "green": ":large_green_circle: green",
    "yellow": ":large_yellow_circle: yellow",
    "red": ":red_circle: red",
    "unknown": ":white_circle: unknown",
}


def _marker(head_sha: str | None) -> str:
    return (
        f"{MARKER_PREFIX} sha={head_sha} -->"
        if head_sha
        else f"{MARKER_PREFIX} -->"
    )


def _value(verdict: Verdict, value: float) -> str:
    if verdict.metric.startswith(("coverage", "duplication")):
        return f"{value:.2f}%"
    return f"{value:.0f}"


def _delta(verdict: Verdict) -> str:
    if verdict.severity == "unknown":
        return "no baseline"
    sign = "+" if verdict.delta >= 0 else ""
    if verdict.metric.startswith(("coverage", "duplication")):
        return f"{sign}{verdict.delta:.2f}pp"
    if verdict.metric.startswith("security"):
        return f"{sign}{verdict.delta:.0f}"
    return f"{sign}{verdict.delta:.0f} ({sign}{verdict.delta_pct:.1f}%)"


def render(report: Report, head_sha: str | None = None) -> str:
    lines = [_marker(head_sha), "", f"### Quality gate — {_BADGE[report.overall]}", ""]
    if not report.verdicts:
        lines.append("_No metrics collected for this run._")
        return "\n".join(lines) + "\n"
    lines.extend(
        (
            "| Metric | Scope | PR | main | Δ | Severity |",
            "|---|---|---:|---:|---:|---|",
        )
    )
    for verdict in report.verdicts:
        lines.append(
            "| {metric} | {scope} | {current} | {baseline} | {delta} | {severity} |".format(
                metric=verdict.metric,
                scope=verdict.scope,
                current=_value(verdict, verdict.pr_value),
                baseline=_value(verdict, verdict.main_value),
                delta=_delta(verdict),
                severity=_BADGE[verdict.severity],
            )
        )
    worst = [v for v in report.verdicts if v.severity == report.overall]
    if report.overall in {"yellow", "red"} and worst:
        lines.extend(
            (
                "",
                "**Worst:** "
                + ", ".join(f"`{v.metric}` ({v.scope})" for v in worst),
            )
        )
    elif report.overall == "unknown":
        lines.extend(
            (
                "",
                "**No baseline available** — this is the first run or the retained baseline is unavailable.",
            )
        )
    return "\n".join(lines) + "\n"
