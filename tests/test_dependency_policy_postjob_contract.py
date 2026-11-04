from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import yaml

from scripts.dependency_policy.policy import detect_ecosystems


ROOT = Path(__file__).resolve().parents[1]
ACTION_PATH = ROOT / ".github" / "actions" / "dependency-policy" / "action.yml"


class DependencyPolicyUvPostJobContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        action = yaml.safe_load(ACTION_PATH.read_text(encoding="utf-8"))
        cls.steps = action["runs"]["steps"]

    def step(self, name):
        return next(step for step in self.steps if step.get("name") == name)

    def detect(self, manifests):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name, contents in manifests.items():
                (root / name).write_text(contents, encoding="utf-8")
            return detect_ecosystems(root)

    def test_npm_only_consumer_does_not_enable_uv_or_its_cache_hook(self):
        ecosystems = self.detect(
            {
                "package.json": json.dumps(
                    {"name": "npm-only", "packageManager": "npm@12.0.2"}
                ),
                "package-lock.json": "{}",
            }
        )
        self.assertEqual(
            ecosystems,
            [{"ecosystem": "node-npm", "lockfile": "package-lock.json"}],
        )

        detection = self.step("Detect dependency ecosystems")["run"]
        npm_case = detection.split("node-npm)", 1)[1].split(
            "node-pnpm|node-yarn)", 1
        )[0]
        python_case = detection.split("python-uv|python-poetry)", 1)[1].split(
            "esac", 1
        )[0]
        self.assertIn("npm_required=true", npm_case)
        self.assertNotIn("python_required=true", npm_case)
        self.assertIn("python_required=true", python_case)

        setup_uv = self.step("Setup uv")
        self.assertEqual(
            setup_uv["if"],
            "steps.ecosystems.outputs.python_required == 'true'",
        )
        self.assertEqual(setup_uv["with"].get("enable-cache"), "false")

    def test_python_uv_consumer_keeps_lockfile_validation(self):
        ecosystems = self.detect(
            {
                "pyproject.toml": (
                    "[project]\nname = \"python-uv\"\n"
                    "requires-python = \">=3.14\"\n"
                ),
                "uv.lock": "version = 1\n",
            }
        )
        self.assertEqual(
            ecosystems,
            [{"ecosystem": "python-uv", "lockfile": "uv.lock"}],
        )

        detection = self.step("Detect dependency ecosystems")["run"]
        python_case = detection.split("python-uv|python-poetry)", 1)[1].split(
            "esac", 1
        )[0]
        self.assertIn("python_required=true", python_case)
        self.assertEqual(
            self.step("Setup uv")["if"],
            "steps.ecosystems.outputs.python_required == 'true'",
        )

        validation = self.step("Validate lockfile synchronization")["run"]
        uv_case = validation.split("python-uv)", 1)[1].split(
            "python-poetry)", 1
        )[0]
        self.assertIn("UV_PYTHON=\"$python_version\" uv lock --check", uv_case)
        self.assertIn("uv lock --check", uv_case)

    def test_python_poetry_consumer_keeps_its_lockfile_validation(self):
        ecosystems = self.detect(
            {
                "pyproject.toml": "[tool.poetry]\nname = \"python-poetry\"\n",
                "poetry.lock": "# lock\n",
            }
        )
        self.assertEqual(
            ecosystems,
            [{"ecosystem": "python-poetry", "lockfile": "poetry.lock"}],
        )

        validation = self.step("Validate lockfile synchronization")["run"]
        poetry_case = validation.split("python-poetry)", 1)[1].split(
            "node-pnpm)", 1
        )[0]
        self.assertIn("uv tool install --force 'poetry==2.1.4'", poetry_case)
        self.assertIn("poetry check --lock", poetry_case)


if __name__ == "__main__":
    unittest.main()
