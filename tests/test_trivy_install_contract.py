"""Static contract for the governed Trivy binary installation."""

from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TRIVY_ACTIONS = (
    ".github/actions/security-gate/action.yml",
    ".github/actions/dependency-policy/action.yml",
    ".github/actions/supply-chain-evidence/action.yml",
    ".github/actions/trivy-scan/action.yml",
)
INSTALL_DIR = (
    "TRIVY_INSTALL_DIR: ${{ runner.temp }}/optimizr-trivy/"
    "${{ github.run_id }}-${{ github.run_attempt }}-${{ github.job }}"
)


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


class TrivyInstallContractTests(unittest.TestCase):
    def test_every_trivy_action_uses_the_governed_installer(self) -> None:
        for action in TRIVY_ACTIONS:
            with self.subTest(action=action):
                content = read(action)
                self.assertNotIn("aquasecurity/setup-trivy", content)
                self.assertIn("- name: Install controlled Trivy", content)
                self.assertIn(INSTALL_DIR, content)
                self.assertIn("TRIVY_VERSION: ${{ inputs.trivy_version }}", content)
                self.assertIn(
                    'bash "$action_root/scripts/security_gate/install-trivy.sh" \\\n'
                    '          --version "$TRIVY_VERSION" \\\n'
                    '          --install-dir "$TRIVY_INSTALL_DIR"',
                    content,
                )
                install = content.index("- name: Install controlled Trivy")
                self.assertLess(install, content.index("trivy_cache_setup"))

    def test_trivy_version_input_contract_is_unchanged(self) -> None:
        for action in TRIVY_ACTIONS:
            with self.subTest(action=action):
                content = read(action)
                self.assertRegex(
                    content,
                    re.compile(r"  trivy_version:\n(?:    .*\n)*?    default: \"?v0\.74\.0\"?\n"),
                )

    def test_installer_bounds_network_and_verifies_before_use(self) -> None:
        script = read("scripts/security_gate/install-trivy.sh")
        for fragment in (
            "set -euo pipefail",
            "--fail",
            "--location",
            "--proto =https",
            "--proto-redir =https",
            "--tlsv1.2",
            "--connect-timeout",
            "--max-time",
            "OPTIMIZR_TRIVY_DOWNLOAD_ATTEMPTS:-4",
            "OPTIMIZR_TRIVY_RETRY_DELAY_SECONDS:-5",
            "OPTIMIZR_TRIVY_CONNECT_TIMEOUT_SECONDS:-20",
            "OPTIMIZR_TRIVY_MAX_TIME_SECONDS:-180",
            "sha256sum",
            "trivy-checksums.txt",
            "https://github.com/aquasecurity/trivy/releases/download",
            "optimizr-security-gate/trivy-binaries",
            "GITHUB_PATH",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, script)
        self.assertNotIn("install.sh", script)
        self.assertNotIn("latest", script)

    def test_pinned_checksums_cover_known_consumer_versions(self) -> None:
        checksums = read("scripts/security_gate/trivy-checksums.txt")
        entries = {}
        for line in checksums.splitlines():
            if not line or line.startswith("#"):
                continue
            digest, asset = line.split()
            self.assertRegex(digest, r"^[0-9a-f]{64}$")
            entries[asset] = digest
        self.assertEqual(
            entries["trivy_0.74.0_Linux-64bit.tar.gz"],
            "2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a",
        )
        for asset in (
            "trivy_0.74.0_Linux-ARM64.tar.gz",
            "trivy_0.70.0_Linux-64bit.tar.gz",
            "trivy_0.70.0_Linux-ARM64.tar.gz",
        ):
            with self.subTest(asset=asset):
                self.assertIn(asset, entries)

    def test_installer_is_documented_with_failure_modes_and_rollback(self) -> None:
        document = read("docs/TRIVY_INSTALL.md")
        for fragment in (
            "install-trivy.sh",
            "trivy-checksums.txt",
            "OPTIMIZR_TRIVY_DOWNLOAD_ATTEMPTS",
            "OPTIMIZR_TRIVY_RETRY_DELAY_SECONDS",
            "OPTIMIZR_TRIVY_CONNECT_TIMEOUT_SECONDS",
            "OPTIMIZR_TRIVY_MAX_TIME_SECONDS",
            "## Failure modes",
            "## Rollback",
            "## Consumer inventory",
            "exit code 28",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, document)
        self.assertIn("TRIVY_INSTALL.md", read("docs/SECURITY_GATE.md"))
        self.assertIn("trivy-checksums.txt", read("docs/ACTION_PINS.md"))


if __name__ == "__main__":
    unittest.main()
