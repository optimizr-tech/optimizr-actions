"""Local quality-gate runner that renders a markdown section for a PR body.

Additive entry point: reuses ``collect_metrics``, ``compare`` and ``render`` and
never changes the behavior of ``scripts.quality_gate.run``. It does not execute
the analysis tools; the consumer's local CI produces the JSON files and this
command compares them with a baseline and reports what was not collected.
"""

from __future__ import annotations

import argparse
import json
import shlex
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Sequence

from scripts.quality_gate.compare import compare
from scripts.quality_gate.metrics import Metric
from scripts.quality_gate.render_comment import MARKER_PREFIX, render
from scripts.quality_gate.run import _read_baseline, _verdict_exit, collect_metrics

COMMAND_PREFIX = "python -m scripts.quality_gate.local"
USAGE_ERROR = 64
BASELINE_ARTIFACT = "quality-gate-baseline"
BASELINE_FILE = "quality-gate-baseline.json"
MAX_RUN_ATTEMPTS = 10

# (kind, tool) -> description, per tier. Bundle has no JSON collector in run.py.
TIER_1: dict[tuple[str, str], str] = {
    ("coverage", "pytest"): "cobertura pytest (coverage JSON)",
    ("security", "bandit"): "bandit",
    ("security", "pip-audit"): "pip-audit",
    ("security", "pnpm-audit"): "pnpm-audit",
}
TIER_2: dict[tuple[str, str], str] = {
    ("duplication", "jscpd"): "jscpd (duplicação)",
}
NOT_COLLECTABLE_LOCALLY = (
    "ruff (lint): sem coletor no quality_gate; rode no ci-local do serviço e "
    "registre o resultado à parte",
    "bundle Next (nível 2): sem coletor JSON em run.py (requer build Next); "
    "unknown / depende do CI",
)
TIER_3 = (
    "build Next completo",
    "E2E Docker",
    "Trivy de imagem",
    "suítes opt-in Postgres/mTLS reais",
)

Runner = Callable[[Sequence[str], Path | None], "subprocess.CompletedProcess[str]"]


def _run(command: Sequence[str], cwd: Path | None) -> "subprocess.CompletedProcess[str]":
    return subprocess.run(
        list(command),
        cwd=cwd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
        timeout=300,
    )


@dataclass(frozen=True)
class BaselineInfo:
    metrics: tuple[Metric, ...] = ()
    origin: str = "nenhum"
    sha: str | None = None
    date: str | None = None
    approximate: bool = False
    notes: tuple[str, ...] = field(default_factory=tuple)

    @property
    def available(self) -> bool:
        return bool(self.metrics)


def _git(args: Sequence[str], cwd: Path, runner: Runner) -> str | None:
    try:
        result = runner(["git", *args], cwd)
    except (OSError, subprocess.SubprocessError):
        return None
    out = result.stdout.strip()
    return out if result.returncode == 0 and out else None


def _file_baseline(
    path: Path, origin: str, approximate: bool, repo_root: Path, runner: Runner,
    notes: tuple[str, ...] = (),
) -> BaselineInfo:
    if not path.is_file():
        raise ValueError(f"baseline file not found: {path}")
    payload = json.loads(path.read_text(encoding="utf-8"))
    sha = payload.get("head_sha") if isinstance(payload, dict) else None
    sha = str(sha) if sha else None
    date = _git(["log", "-1", "--format=%cI", sha], repo_root, runner) if sha else None
    if date is None:
        mtime = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
        date = mtime.strftime("%Y-%m-%d") + " (mtime do arquivo; commit do SHA não resolvido)"
    return BaselineInfo(
        metrics=tuple(_read_baseline(path)),
        origin=origin,
        sha=sha,
        date=date,
        approximate=approximate,
        notes=notes,
    )


def _baseline_from_main(
    repository: str, workflow: str | None, runner: Runner
) -> tuple[BaselineInfo | None, tuple[str, ...]]:
    notes: list[str] = []
    command = [
        "gh", "run", "list", "--repo", repository, "--branch", "main",
        "--status", "success", "--limit", "30",
        "--json", "databaseId,headSha,createdAt",
    ]
    if workflow:
        command.extend(["--workflow", workflow])
    try:
        listed = runner(command, None)
    except (OSError, subprocess.SubprocessError) as exc:
        return None, (f"gh run list indisponível: {exc}",)
    if listed.returncode != 0:
        detail = (listed.stderr or listed.stdout).strip().splitlines()[:1]
        return None, (f"gh run list falhou: {detail[0] if detail else listed.returncode}",)
    try:
        runs = json.loads(listed.stdout or "[]")
    except json.JSONDecodeError:
        return None, ("gh run list retornou JSON inválido",)
    if not isinstance(runs, list) or not runs:
        return None, (f"nenhuma execução verde da main encontrada em {repository}",)
    for run in runs[:MAX_RUN_ATTEMPTS]:
        run_id = run.get("databaseId")
        with tempfile.TemporaryDirectory() as tmp:
            try:
                got = runner(
                    ["gh", "run", "download", str(run_id), "--repo", repository,
                     "-n", BASELINE_ARTIFACT, "-D", tmp],
                    None,
                )
            except (OSError, subprocess.SubprocessError) as exc:
                return None, (*notes, f"gh run download indisponível: {exc}")
            target = Path(tmp) / BASELINE_FILE
            if got.returncode != 0 or not target.is_file():
                notes.append(f"run {run_id}: artefato {BASELINE_ARTIFACT} ausente ou expirado")
                continue
            try:
                metrics = tuple(_read_baseline(target))
            except (ValueError, json.JSONDecodeError, TypeError) as exc:
                notes.append(f"run {run_id}: baseline ilegível ({exc})")
                continue
            return (
                BaselineInfo(
                    metrics=metrics,
                    origin=f"artefato {BASELINE_ARTIFACT} da última execução verde da main "
                    f"({repository}, run {run_id})",
                    sha=str(run.get("headSha") or "") or None,
                    date=str(run.get("createdAt") or "") or None,
                    notes=tuple(notes),
                ),
                tuple(notes),
            )
    return None, (*notes, "nenhuma execução verde recente com artefato de baseline utilizável")


def resolve_baseline(args: argparse.Namespace, repo_root: Path, runner: Runner) -> BaselineInfo:
    if args.baseline is not None:
        return _file_baseline(args.baseline, "arquivo informado em --baseline", False, repo_root, runner)
    if args.baseline_from_main:
        info, notes = _baseline_from_main(args.baseline_from_main, args.baseline_workflow, runner)
        if info is not None:
            return info
        if args.fallback_baseline is not None:
            return _file_baseline(
                args.fallback_baseline,
                "baseline versionado (--fallback-baseline)",
                True,
                repo_root,
                runner,
                notes,
            )
        return BaselineInfo(notes=notes)
    return BaselineInfo(notes=("nenhum baseline informado",))


def _missing(
    present: set[tuple[str, str]], tier: int
) -> list[str]:
    expected = dict(TIER_1)
    if tier >= 2:
        expected.update(TIER_2)
    return [
        f"{label}: artefato não encontrado em --artifacts-dir"
        for key, label in sorted(expected.items())
        if key not in present
    ]


def build_markdown(
    *,
    metrics: list[Metric],
    baseline: BaselineInfo,
    head_sha: str,
    tier: int,
    command: str,
) -> tuple[str, str]:
    report = compare(metrics, list(baseline.metrics))
    present = {(m.kind, m.tool) for m in metrics}
    uncollected = _missing(present, tier)
    if tier == 1:
        uncollected.extend(
            f"{label}: nível 2 não solicitado (--tier 2)" for _, label in sorted(TIER_2.items())
        )
    uncollected.extend(NOT_COLLECTABLE_LOCALLY)
    uncollected.extend(f"{item} (nível 3): unknown / depende do CI" for item in TIER_3)

    body = "\n".join(
        line for line in render(report, head_sha).splitlines() if not line.startswith(MARKER_PREFIX)
    ).strip("\n")
    partial = [u for u in uncollected if "(nível 3)" not in u]
    verdict_note = (
        f"> Veredito parcial: {len(partial)} item(ns) não coletado(s) abaixo; "
        "ausência de dado não significa green."
        if partial
        else ""
    )

    if baseline.available:
        label = "baseline aproximado" if baseline.approximate else "baseline"
        baseline_lines = [
            f"- **Baseline ({label}):** {baseline.origin}",
            f"  - SHA: `{baseline.sha or 'desconhecido'}`",
            f"  - Data: {baseline.date or 'desconhecida'}",
        ]
        if baseline.approximate:
            baseline_lines.append(
                "  - Aproximado: não é o artefato da última execução verde da main; "
                "comparação pode divergir do CI."
            )
    else:
        baseline_lines = ["- **Baseline:** indisponível (veredito unknown por métrica)"]
    baseline_lines.extend(f"  - nota: {note}" for note in baseline.notes)

    lines = [
        body,
        "",
        *([verdict_note, ""] if verdict_note else []),
        f"- **Head SHA:** `{head_sha}`",
        f"- **Nível executado:** {tier}",
        *baseline_lines,
        f"- **Comando:** `{command}`",
        "",
        "#### Não coletado (unknown / não coletado)",
        "",
        *(f"- {item}" for item in uncollected),
    ]
    return "\n".join(lines) + "\n", report.overall


def _parser() -> argparse.ArgumentParser:
    class _Parser(argparse.ArgumentParser):
        def error(self, message: str) -> "None":  # type: ignore[override]
            self.print_usage(sys.stderr)
            self.exit(USAGE_ERROR, f"{self.prog}: error: {message}\n")

    parser = _Parser(prog="python -m scripts.quality_gate.local")
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument("--tier", type=int, choices=(1, 2), default=1)
    parser.add_argument("--artifacts-dir", type=Path)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--baseline", type=Path)
    group.add_argument("--baseline-from-main", metavar="OWNER/REPO")
    parser.add_argument("--baseline-workflow", help="limit gh run list to one workflow")
    parser.add_argument("--fallback-baseline", type=Path)
    parser.add_argument("--head-sha")
    parser.add_argument("--output", type=Path)
    return parser


def main(argv: list[str] | None = None, runner: Runner = _run) -> int:
    raw = list(sys.argv[1:] if argv is None else argv)
    parser = _parser()
    args = parser.parse_args(raw)
    if args.fallback_baseline is not None and not args.baseline_from_main:
        parser.error("--fallback-baseline requires --baseline-from-main")
    repo_root = args.repo_root
    artifacts = args.artifacts_dir or repo_root / ".quality-gate" / "artifacts"
    head_sha = args.head_sha or _git(["rev-parse", "HEAD"], repo_root, runner)
    if not head_sha:
        parser.error("could not determine head SHA; pass --head-sha")
    if not artifacts.is_dir():
        parser.error(f"--artifacts-dir does not exist: {artifacts}")
    try:
        baseline = resolve_baseline(args, repo_root, runner)
    except (ValueError, json.JSONDecodeError, TypeError, OSError) as exc:
        parser.error(f"invalid baseline: {exc}")
    metrics = collect_metrics(artifacts)
    command = f"{COMMAND_PREFIX} {shlex.join(raw)}".strip()
    markdown, overall = build_markdown(
        metrics=metrics, baseline=baseline, head_sha=head_sha, tier=args.tier, command=command
    )
    sys.stdout.write(markdown)
    if args.output is not None:
        args.output.write_text(markdown, encoding="utf-8", newline="\n")
    return _verdict_exit(overall)


if __name__ == "__main__":
    raise SystemExit(main())
