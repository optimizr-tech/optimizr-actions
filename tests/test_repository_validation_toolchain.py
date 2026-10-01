import os
import shutil
import subprocess
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/_repository-validation.yml"


class RepositoryValidationToolchainTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        bash = shutil.which("bash")
        if bash is None:
            raise unittest.SkipTest("the reusable Node toolchain validator runs in Bash")

        workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
        steps = workflow["jobs"]["validation"]["steps"]
        cls.validation_step = next(
            step for step in steps if step.get("name") == "Validate requested Node toolchain"
        )
        cls.bash = bash

    def _validate(self, *, node_version, npm_version, pnpm_version):
        environment = {
            "NODE_VERSION": node_version,
            "NPM_VERSION": npm_version,
            "PNPM_VERSION": pnpm_version,
        }
        return subprocess.run(
            [self.bash, "--noprofile", "--norc", "-c", self.validation_step["run"]],
            env=environment,
            capture_output=True,
            check=False,
            text=True,
        )

    def test_validator_runs_when_any_optional_toolchain_input_is_set(self):
        condition = self.validation_step["if"]

        self.assertEqual(
            condition,
            "inputs.node_version != '' || inputs.npm_version != '' || inputs.pnpm_version != ''",
        )

    def test_node_only_accepts_omitted_npm_and_pnpm(self):
        result = self._validate(node_version="24", npm_version="", pnpm_version="")

        self.assertEqual(result.returncode, 0, result.stderr)

    def test_explicit_npm_version_is_accepted(self):
        result = self._validate(node_version="24", npm_version="10.9.3", pnpm_version="")

        self.assertEqual(result.returncode, 0, result.stderr)

    def test_explicit_pnpm_version_does_not_require_npm_version(self):
        result = self._validate(node_version="24", npm_version="", pnpm_version="10.0.0")

        self.assertEqual(result.returncode, 0, result.stderr)

    def test_invalid_explicit_npm_version_is_still_rejected(self):
        result = self._validate(
            node_version="24", npm_version="10.9.3;echo unsafe", pnpm_version=""
        )

        self.assertEqual(result.returncode, 2)
        self.assertIn("npm_version contains unsupported characters", result.stdout)

    def test_package_manager_versions_still_require_node_version(self):
        for npm_version, pnpm_version in (("10.9.3", ""), ("", "10.0.0")):
            with self.subTest(npm_version=npm_version, pnpm_version=pnpm_version):
                result = self._validate(
                    node_version="", npm_version=npm_version, pnpm_version=pnpm_version
                )

                self.assertEqual(result.returncode, 2)
                self.assertIn("node_version is required", result.stdout)


if __name__ == "__main__":
    unittest.main()
