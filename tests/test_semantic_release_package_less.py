from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "release" / "validate_changelog_compatibility.py"
FIXTURE = ROOT / "tests" / "fixtures" / "package-less-release"


def run_validator(workspace: Path, package_mode: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--package-mode",
            package_mode,
            "--workspace",
            str(workspace),
        ],
        check=False,
        capture_output=True,
        text=True,
    )


def write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def release_config(*, preset: str | bool = "conventionalcommits") -> dict[str, object]:
    return {
        "plugins": [
            ["@semantic-release/commit-analyzer", {"preset": preset}],
            ["@semantic-release/release-notes-generator", {"preset": preset}],
            "@semantic-release/github",
        ]
    }


def write_runtime_package(workspace: Path, package_name: str, version: str, parent: str) -> None:
    write_json(
        workspace / "node_modules" / parent / "node_modules" / package_name / "package.json",
        {"name": package_name, "version": version},
    )


class PackageLessReleaseValidationTests(unittest.TestCase):
    def test_package_less_fixture_validates_without_node_project_manifests(self) -> None:
        self.assertFalse((FIXTURE / "package.json").exists())
        self.assertFalse((FIXTURE / "package-lock.json").exists())
        config = json.loads((FIXTURE / ".releaserc.json").read_text(encoding="utf-8"))
        plugin_names = {
            plugin if isinstance(plugin, str) else plugin[0]
            for plugin in config["plugins"]
        }
        self.assertNotIn("@semantic-release/npm", plugin_names)

        result = run_validator(FIXTURE, "package-less")

        self.assertEqual(0, result.returncode, result.stderr)

    def test_package_less_rejects_implicit_plugins_that_may_publish_npm(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory)
            write_json(workspace / ".releaserc.json", {"branches": ["main"]})

            result = run_validator(workspace, "package-less")

            self.assertNotEqual(0, result.returncode)
            self.assertIn("explicit non-empty plugins array", result.stderr)

    def test_package_less_rejects_empty_explicit_plugins(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory)
            write_json(workspace / ".releaserc.json", {"plugins": []})

            result = run_validator(workspace, "package-less")

            self.assertNotEqual(0, result.returncode)
            self.assertIn("non-empty plugins array", result.stderr)

    def test_package_less_validates_installed_changelog_pair_without_manifests(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory)
            write_json(workspace / ".releaserc.json", release_config())
            write_runtime_package(
                workspace,
                "conventional-changelog-conventionalcommits",
                "10.1.0",
                "@semantic-release/commit-analyzer",
            )
            write_runtime_package(
                workspace,
                "conventional-changelog-conventionalcommits",
                "10.1.0",
                "@semantic-release/release-notes-generator",
            )
            write_runtime_package(
                workspace,
                "conventional-changelog-writer",
                "9.0.0",
                "@semantic-release/release-notes-generator",
            )

            result = run_validator(workspace, "package-less")

            self.assertEqual(0, result.returncode, result.stderr)
            self.assertFalse((workspace / "package.json").exists())
            self.assertFalse((workspace / "package-lock.json").exists())

    def test_package_less_uses_installed_pair_when_only_analyzer_selects_preset(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory)
            config = release_config()
            config["plugins"][1][1] = {}
            write_json(workspace / ".releaserc.json", config)
            write_runtime_package(
                workspace,
                "conventional-changelog-conventionalcommits",
                "10.1.0",
                "@semantic-release/commit-analyzer",
            )
            write_runtime_package(
                workspace,
                "conventional-changelog-conventionalcommits",
                "10.1.0",
                "@semantic-release/release-notes-generator",
            )
            write_runtime_package(
                workspace,
                "conventional-changelog-writer",
                "9.0.0",
                "@semantic-release/release-notes-generator",
            )

            result = run_validator(workspace, "package-less")

            self.assertEqual(0, result.returncode, result.stderr)

    def test_package_less_rejects_incompatible_installed_changelog_pair(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory)
            write_json(workspace / ".releaserc.json", release_config())
            write_runtime_package(
                workspace,
                "conventional-changelog-conventionalcommits",
                "10.1.0",
                "@semantic-release/commit-analyzer",
            )
            write_runtime_package(
                workspace,
                "conventional-changelog-conventionalcommits",
                "10.1.0",
                "@semantic-release/release-notes-generator",
            )
            write_runtime_package(
                workspace,
                "conventional-changelog-writer",
                "8.4.0",
                "@semantic-release/release-notes-generator",
            )

            result = run_validator(workspace, "package-less")

            self.assertNotEqual(0, result.returncode)
            self.assertIn("preset 10.x + writer 9.x", result.stderr)

    def test_node_mode_keeps_manifest_and_lockfile_compatibility_validation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory)
            write_json(workspace / ".releaserc.json", release_config())
            write_json(
                workspace / "package.json",
                {
                    "devDependencies": {
                        "conventional-changelog-conventionalcommits": "^10.1.0",
                        "conventional-changelog-writer": "^9.0.0",
                    }
                },
            )
            write_json(
                workspace / "package-lock.json",
                {
                    "packages": {
                        "node_modules/conventional-changelog-conventionalcommits": {
                            "version": "10.1.0"
                        },
                        "node_modules/conventional-changelog-writer": {"version": "9.0.0"},
                    }
                },
            )

            result = run_validator(workspace, "node")

            self.assertEqual(0, result.returncode, result.stderr)


if __name__ == "__main__":
    unittest.main()
