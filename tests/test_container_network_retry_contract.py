"""Static contract for bounded registry network retries in container reusables."""

from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / ".github/workflows/_container-build-publish.yml"
PROMOTE = ROOT / ".github/workflows/_container-candidate-promote.yml"
RESOLVE = ROOT / ".github/actions/resolve-image-manifest/action.yml"
DOC = ROOT / "docs/CONTAINER_NETWORK_RETRY.md"
LOGIN_ACTION = "uses: docker/login-action@dbcb813823bdd20940b903addbd779551569679f"
HELPER = "RETRY_NETWORK: .optimizr-actions-source/scripts/container_release/retry_network.py"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _input_block(content: str, name: str, indent: str = "      ") -> str:
    start = content.index(f"{indent}{name}:\n")
    end = re.search(rf"\n{indent}[a-z_]+:\n|\n    secrets:|\noutputs:", content[start + 1 :])
    assert end
    return content[start : start + 1 + end.start()]


def _step(content: str, name: str) -> str:
    start = content.index(f"      - name: {name}\n")
    end = content.find("\n      - name:", start + 1)
    return content[start:] if end == -1 else content[start:end]


class ContainerNetworkRetryContractTests(unittest.TestCase):
    def test_new_inputs_are_optional_with_bounded_defaults(self) -> None:
        for path in (BUILD, PROMOTE):
            content = _read(path)
            with self.subTest(path=path.name):
                attempts = _input_block(content, "network_retry_attempts")
                backoff = _input_block(content, "network_retry_backoff_seconds")
                for block, default in ((attempts, "default: 3"), (backoff, "default: 5")):
                    self.assertIn("required: false", block)
                    self.assertIn("type: number", block)
                    self.assertIn(default, block)
                self.assertIn("network_retry_attempts must be an integer between 1 and 5", content)
                self.assertIn("network_retry_backoff_seconds must be an integer between 0 and 30", content)
                self.assertIn(HELPER, content)

    def test_existing_login_action_stays_first_attempt_and_failure_is_never_swallowed(self) -> None:
        cases = (
            (BUILD, "Log in to GHCR for publish", "registry-login", "Retry GHCR login after a failed attempt"),
            (
                BUILD,
                "Refresh registry login immediately before publish",
                "registry-refresh-login",
                "Retry registry login refresh after a failed attempt",
            ),
            (PROMOTE, "Log in to GHCR", "registry-login", "Retry GHCR login after a failed attempt"),
        )
        for path, login_name, step_id, retry_name in cases:
            content = _read(path)
            with self.subTest(path=path.name, step=login_name):
                login = _step(content, login_name)
                self.assertIn(LOGIN_ACTION, login)
                self.assertIn(f"id: {step_id}", login)
                self.assertIn("continue-on-error: true", login)
                names = re.findall(r"^      - name: (.+)$", content, re.MULTILINE)
                self.assertEqual(names.index(login_name) + 1, names.index(retry_name))
                retry = _step(content, retry_name)
                self.assertIn(f"steps.{step_id}.outcome == 'failure'", retry)
                self.assertNotIn("continue-on-error", retry)
                self.assertIn("--prior-failed-attempts 1", retry)
                self.assertIn("--stdin-env REGISTRY_PASSWORD", retry)
                self.assertIn("--password-stdin", retry)
                self.assertNotIn("--password ", retry)
                self.assertNotIn("echo", retry)

    def test_registry_reads_writes_and_pulls_use_the_retry_wrapper(self) -> None:
        for path in (BUILD, PROMOTE):
            content = _read(path)
            with self.subTest(path=path.name):
                bare = [
                    line
                    for line in content.splitlines()
                    if re.match(r"\s+docker (pull|buildx imagetools)", line)
                ]
                self.assertEqual([], bare)
                self.assertEqual(3, content.count('--stdout-file "$'))
                self.assertIn('--label "imagetools create release tags"', content)
                self.assertRegex(content, r'--label "docker pull quarantined? digest"')
                self.assertNotIn('> "$index_file"', content)

    def test_promotion_digest_gates_are_unchanged(self) -> None:
        build = _read(BUILD)
        promote = _read(PROMOTE)
        self.assertIn("steps.verify-quarantine-attestations.outcome == 'success'", build)
        self.assertIn("verify_published_digest.py", _step(build, "Promote verified image by digest"))
        self.assertIn("verify_published_digest.py", _step(promote, "Promote candidate digest to source SHA tags"))

    def test_permissions_are_not_broadened(self) -> None:
        build = _read(BUILD)
        self.assertIn(
            "    permissions:\n      contents: read\n      packages: write\n"
            "      attestations: write\n      id-token: write\n",
            build,
        )
        promote = _read(PROMOTE)
        self.assertIn("    permissions:\n      contents: read\n      packages: write\n    outputs:", promote)

    def test_resolve_image_manifest_pull_is_retried_and_fails_closed(self) -> None:
        content = _read(RESOLVE)
        for name, default in (("network_retry_attempts", '"3"'), ("network_retry_backoff_seconds", '"5"')):
            block = _input_block(content, name, indent="  ")
            self.assertIn("required: false", block)
            self.assertIn(f"default: {default}", block)
        self.assertIn('"../../../scripts/container_release/retry_network.py"', content)
        self.assertIn('"--", "docker", "pull", image,', content)
        self.assertIn("if pulled.returncode != 0:", content)
        self.assertNotIn("shell=True", content)

    def test_contract_is_documented(self) -> None:
        doc = _read(DOC)
        for needle in (
            "network_retry_attempts",
            "network_retry_backoff_seconds",
            "transient_exhausted",
            "permanent",
            "unclassified",
            "retry_disabled",
            "## Migration and rollback",
            "network_retry_attempts: 1",
        ):
            with self.subTest(needle=needle):
                self.assertIn(needle, doc)


if __name__ == "__main__":
    unittest.main()
