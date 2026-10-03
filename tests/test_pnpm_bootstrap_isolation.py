"""pnpm bootstrap and collector stores must not share a persistent home."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
BOOTSTRAP = (
    "${{ runner.temp }}/pnpm-bootstrap-${{ github.run_id }}-"
    "${{ github.run_attempt }}-${{ github.job }}"
)
STORE = (
    "${{ runner.temp }}/pnpm-store-${{ github.run_id }}-"
    "${{ github.run_attempt }}-${{ github.job }}-${{ strategy.job-index }}"
)


def workflow(name: str) -> dict:
    return yaml.safe_load((ROOT / ".github/workflows" / name).read_text(encoding="utf-8"))


class PnpmBootstrapIsolationTests(unittest.TestCase):
    def test_repository_contract_inherits_its_own_package_store(self) -> None:
        steps = workflow("_repository-validation.yml")["jobs"]["validation"]["steps"]
        prepare = next(step for step in steps if step.get("name") == "Prepare job-local pnpm store")
        bootstrap = next(step for step in steps if step.get("name") == "Setup pnpm for repository contract")
        contract = next(step for step in steps if step.get("name") == "Run repository contract")
        self.assertEqual(prepare["if"], "inputs.pnpm_version != ''")
        self.assertEqual(
            prepare["env"]["PNPM_CONFIG_STORE_DIR"],
            "${{ runner.temp }}/pnpm-store-${{ github.run_id }}-${{ github.run_attempt }}-${{ github.job }}",
        )
        self.assertIn('>> "$GITHUB_ENV"', prepare["run"])
        self.assertLess(steps.index(prepare), steps.index(bootstrap))
        self.assertLess(steps.index(bootstrap), steps.index(contract))
        self.assertNotIn("PNPM_CONFIG_STORE_DIR", contract.get("env", {}))

    def test_all_pnpm_bootstraps_use_job_local_destinations(self) -> None:
        count = 0
        for path in sorted((ROOT / ".github/workflows").glob("*.yml")):
            document = workflow(path.name)
            for job_name, job in document.get("jobs", {}).items():
                for step in job.get("steps", []):
                    if not step.get("uses", "").startswith("pnpm/action-setup@"):
                        continue
                    count += 1
                    with self.subTest(workflow=path.name, job=job_name):
                        self.assertEqual(step.get("with", {}).get("dest"), BOOTSTRAP)
        self.assertEqual(count, 4)

    def test_collectors_share_one_isolated_store_with_every_step(self) -> None:
        for name, job_name in (
            ("_quality-gate-collect-security.yml", "collect-security"),
            ("_quality-gate-collect-dup.yml", "collect-dup"),
        ):
            with self.subTest(workflow=name):
                job = workflow(name)["jobs"][job_name]
                self.assertNotIn("PNPM_CONFIG_STORE_DIR", job.get("env", {}))
                steps = job["steps"]
                prepare = next(step for step in steps if step.get("name") == "Prepare job-local pnpm store")
                install = next(step for step in steps if step.get("name") == "Install pnpm")
                self.assertEqual(prepare.get("env", {}).get("PNPM_CONFIG_STORE_DIR"), STORE)
                self.assertIn('mkdir -p "$PNPM_CONFIG_STORE_DIR"', prepare["run"])
                self.assertIn('>> "$GITHUB_ENV"', prepare["run"])
                self.assertLess(steps.index(prepare), steps.index(install))
                for step in steps:
                    if step is not prepare:
                        self.assertNotIn("PNPM_CONFIG_STORE_DIR", step.get("env", {}))
                if job_name == "collect-security":
                    self.assertEqual(prepare["if"], "matrix.tool == 'pnpm-audit'")
                    cache = next(step for step in steps if step.get("name") == "Initialize pnpm cache")
                    self.assertEqual(cache["with"]["cache"], "pnpm")
                    self.assertLess(steps.index(install), steps.index(cache))

    def test_store_preparation_exports_the_real_directory(self) -> None:
        bash = shutil.which("bash")
        if os.name == "nt":
            git_bash = Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "Git/bin/bash.exe"
            if git_bash.is_file():
                bash = str(git_bash)
        self.assertIsNotNone(bash, "Bash is required for the workflow contract")
        for name, job_name in (
            ("_quality-gate-collect-security.yml", "collect-security"),
            ("_quality-gate-collect-dup.yml", "collect-dup"),
        ):
            with self.subTest(workflow=name), tempfile.TemporaryDirectory(prefix="pnpm-contract-") as directory:
                steps = workflow(name)["jobs"][job_name]["steps"]
                prepare = next(step for step in steps if step.get("name") == "Prepare job-local pnpm store")
                store = Path(directory) / "store"
                exports = Path(directory) / "github-env"
                env = os.environ.copy()
                env.update(PNPM_CONFIG_STORE_DIR=store.as_posix(), GITHUB_ENV=exports.as_posix())
                result = subprocess.run(
                    [bash, "--noprofile", "--norc", "-c", prepare["run"]],
                    env=env, capture_output=True, text=True, check=False,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertTrue(store.is_dir())
                self.assertEqual(exports.read_text().strip(), f"PNPM_CONFIG_STORE_DIR={store.as_posix()}")


if __name__ == "__main__":
    unittest.main()
