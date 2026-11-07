import contextlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from scripts.quality_gate import local, run

ROOT = Path(__file__).resolve().parents[1]
SHA = "a" * 40
BASE_SHA = "b" * 40

COVERAGE = {
    "totals": {
        "percent_covered": 89.0,
        "covered_lines": 89,
        "num_statements": 100,
        "percent_branches_covered": 75.0,
        "covered_branches": 15,
        "num_branches": 20,
    }
}
BANDIT = {"metrics": {"_totals": {"SEVERITY.HIGH": 0, "SEVERITY.MEDIUM": 0, "SEVERITY.LOW": 1}}}


def _baseline(line_pct: float, sha: str = BASE_SHA) -> dict:
    return {
        "schema_version": 1,
        "head_sha": sha,
        "metrics": [
            {
                "kind": "coverage",
                "tool": "pytest",
                "scope": "backend",
                "line_pct": line_pct,
                "line_covered": 0,
                "line_total": 100,
                "branch_pct": 75.0,
                "branch_covered": 15,
                "branch_total": 20,
            },
            {
                "kind": "security",
                "tool": "bandit",
                "scope": "backend",
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 1,
            },
        ],
    }


def _done(code: int = 0, out: str = "", err: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess([], code, out, err)


def _no_tools(command, cwd):
    """Fake runner: git resolves nothing, gh always fails."""
    return _done(1, "", "unavailable")


class LocalQualityGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.artifacts = self.root / "artifacts"
        self.artifacts.mkdir()
        (self.artifacts / "pytest-coverage.json").write_text(json.dumps(COVERAGE), encoding="utf-8")
        (self.artifacts / "bandit.json").write_text(json.dumps(BANDIT), encoding="utf-8")

    def _main(self, *extra: str, runner=_no_tools) -> tuple[int, str]:
        out = io.StringIO()
        argv = [
            "--repo-root", str(self.root),
            "--artifacts-dir", str(self.artifacts),
            "--head-sha", SHA,
            *extra,
        ]
        with contextlib.redirect_stdout(out):
            code = local.main(argv, runner=runner)
        return code, out.getvalue()

    def _write_baseline(self, name: str, line_pct: float) -> Path:
        path = self.root / name
        path.write_text(json.dumps(_baseline(line_pct)), encoding="utf-8")
        return path

    def test_without_baseline_is_unknown_and_never_invents_numbers(self) -> None:
        code, text = self._main()
        self.assertEqual(3, code)
        self.assertIn("unknown", text.splitlines()[0])
        self.assertIn("no baseline", text)
        self.assertIn("**Baseline:** indisponível", text)
        self.assertIn(f"`{SHA}`", text)

    def test_explicit_baseline_gives_verdict_and_origin(self) -> None:
        path = self._write_baseline("base.json", 89.0)
        code, text = self._main("--baseline", str(path))
        self.assertEqual(0, code)
        self.assertIn("green", text.splitlines()[0])
        self.assertIn(f"SHA: `{BASE_SHA}`", text)
        self.assertNotIn("baseline aproximado", text)

    def test_regression_is_red_with_exit_2(self) -> None:
        path = self._write_baseline("base.json", 95.0)
        code, text = self._main("--baseline", str(path))
        self.assertEqual(2, code)
        self.assertIn("red", text.splitlines()[0])

    def test_fallback_baseline_is_marked_approximate_with_sha_and_date(self) -> None:
        path = self._write_baseline("versioned.json", 89.0)

        def runner(command, cwd):
            if command[0] == "git":
                return _done(0, "2026-11-01T10:00:00+00:00\n")
            return _done(1, "", "gh: no runs")

        code, text = self._main(
            "--baseline-from-main", "owner/repo", "--fallback-baseline", str(path), runner=runner
        )
        self.assertEqual(0, code)
        self.assertIn("baseline aproximado", text)
        self.assertIn(f"SHA: `{BASE_SHA}`", text)
        self.assertIn("Data: 2026-11-01T10:00:00+00:00", text)
        self.assertIn("gh run list falhou", text)

    def test_baseline_from_main_downloads_latest_green_artifact(self) -> None:
        calls = []

        def runner(command, cwd):
            calls.append(command)
            if command[:3] == ["gh", "run", "list"]:
                return _done(
                    0,
                    json.dumps(
                        [
                            {"databaseId": 11, "headSha": BASE_SHA, "createdAt": "2026-11-06T12:00:00Z"},
                            {"databaseId": 10, "headSha": "c" * 40, "createdAt": "2026-11-05T12:00:00Z"},
                        ]
                    ),
                )
            if command[:3] == ["gh", "run", "download"]:
                if command[3] == "11":
                    return _done(1, "", "no artifact")
                target = Path(command[command.index("-D") + 1]) / local.BASELINE_FILE
                target.write_text(json.dumps(_baseline(89.0, "c" * 40)), encoding="utf-8")
                return _done(0)
            return _done(1)

        code, text = self._main("--baseline-from-main", "owner/repo", runner=runner)
        self.assertEqual(0, code)
        self.assertIn("última execução verde da main (owner/repo, run 10)", text)
        self.assertIn("run 11: artefato quality-gate-baseline ausente", text)
        self.assertNotIn("baseline aproximado", text)
        self.assertIn("--branch", calls[0])
        self.assertIn("main", calls[0])

    def test_no_baseline_from_main_and_no_fallback_stays_unknown(self) -> None:
        code, text = self._main("--baseline-from-main", "owner/repo")
        self.assertEqual(3, code)
        self.assertIn("**Baseline:** indisponível", text)
        self.assertIn("gh run list falhou", text)

    def test_tier_3_and_missing_collectors_are_listed_as_not_collected(self) -> None:
        path = self._write_baseline("base.json", 89.0)
        _, text = self._main("--baseline", str(path))
        section = text.split("#### Não coletado")[1]
        for item in (
            "build Next completo",
            "E2E Docker",
            "Trivy de imagem",
            "suítes opt-in Postgres/mTLS reais",
        ):
            self.assertIn(f"- {item} (nível 3): unknown / depende do CI", section)
        self.assertIn("- pip-audit: artefato não encontrado", section)
        self.assertIn("- pnpm-audit: artefato não encontrado", section)
        self.assertNotIn("- bandit:", section)
        self.assertIn("jscpd (duplicação): nível 2 não solicitado", section)
        self.assertIn("ruff", section)
        self.assertIn("Veredito parcial", text)

    def test_tier_2_expects_jscpd_instead_of_skipping_it(self) -> None:
        path = self._write_baseline("base.json", 89.0)
        _, text = self._main("--tier", "2", "--baseline", str(path))
        section = text.split("#### Não coletado")[1]
        self.assertIn("jscpd (duplicação): artefato não encontrado", section)
        self.assertNotIn("nível 2 não solicitado", section)

    def test_output_is_deterministic_and_written_to_file(self) -> None:
        path = self._write_baseline("base.json", 89.0)
        out_file = self.root / "section.md"
        first_code, first = self._main("--baseline", str(path), "--output", str(out_file))
        second_code, second = self._main("--baseline", str(path), "--output", str(out_file))
        self.assertEqual(first, second)
        self.assertEqual(first_code, second_code)
        written = out_file.read_bytes().decode("utf-8")
        self.assertEqual(first, written)
        self.assertNotIn("\r", written)
        self.assertIn("**Comando:** `python -m scripts.quality_gate.local", first)
        self.assertNotIn("<!-- quality-gate", first)

    def test_usage_errors_do_not_collide_with_verdict_codes(self) -> None:
        cases = (
            ["--artifacts-dir", str(self.root / "missing"), "--head-sha", SHA],
            [
                "--artifacts-dir", str(self.artifacts), "--head-sha", SHA,
                "--fallback-baseline", str(self.root / "x.json"),
            ],
            [
                "--artifacts-dir", str(self.artifacts), "--head-sha", SHA,
                "--baseline", str(self.root / "missing.json"),
            ],
            ["--tier", "3"],
        )
        for argv in cases:
            with self.subTest(argv=argv), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as raised:
                    local.main(argv, runner=_no_tools)
                self.assertEqual(local.USAGE_ERROR, raised.exception.code)


class ExistingBehaviorUnchangedTests(unittest.TestCase):
    def test_run_py_exit_codes_and_emit_baseline_contract(self) -> None:
        self.assertEqual(
            [0, 1, 2, 3],
            [run._verdict_exit(v) for v in ("green", "yellow", "red", "unknown")],
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "pytest-coverage.json").write_text(json.dumps(COVERAGE), encoding="utf-8")
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = run.main(["--artifacts-dir", str(root), "--head-sha", SHA, "emit-baseline"])
        payload = json.loads(out.getvalue())
        self.assertEqual(0, code)
        self.assertEqual({"schema_version", "head_sha", "metrics"}, set(payload))
        self.assertEqual(1, payload["schema_version"])

    def test_run_py_does_not_depend_on_local_module(self) -> None:
        source = (ROOT / "scripts" / "quality_gate" / "run.py").read_text(encoding="utf-8")
        self.assertNotIn("quality_gate.local", source)

    def test_quality_gate_workflows_still_use_run_py_only(self) -> None:
        for name in ("_quality-gate-pr.yml", "_quality-gate-baseline.yml", "_quality-gate.yml"):
            text = (ROOT / ".github" / "workflows" / name).read_text(encoding="utf-8")
            with self.subTest(workflow=name):
                self.assertNotIn("quality_gate.local", text)
        pr = (ROOT / ".github" / "workflows" / "_quality-gate-pr.yml").read_text(encoding="utf-8")
        self.assertIn("python -m scripts.quality_gate.run", pr)

    def test_pr_metadata_workflow_does_not_require_the_section(self) -> None:
        text = (ROOT / ".github" / "workflows" / "_pr-metadata.yml").read_text(encoding="utf-8")
        self.assertNotIn("Quality gate", text)
        self.assertNotIn("quality_gate", text)


if __name__ == "__main__":
    unittest.main()
