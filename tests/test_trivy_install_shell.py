"""Behavioral tests for the resilient, checksum-verified Trivy installer."""

from __future__ import annotations

import hashlib
import io
import os
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "scripts" / "security_gate" / "install-trivy.sh"
REQUIRES_POSIX_SHELL = bool(
    (os.name != "nt" or os.environ.get("OPTIMIZR_RUN_SHELL_TESTS_ON_WINDOWS") == "1")
    and shutil.which("bash")
    and shutil.which("tar")
    and shutil.which("sha256sum")
)

FAKE_CURL = """#!/usr/bin/env bash
set -euo pipefail
printf '%s\\n' "$*" >> "$FAKE_CURL_LOG"
output=""
url=""
while (($#)); do
  case "$1" in
    --output|-o) output="$2"; shift 2 ;;
    --connect-timeout|--max-time|--proto|--proto-redir|--retry|--speed-limit|--speed-time)
      shift 2 ;;
    -*) shift ;;
    *) url="$1"; shift ;;
  esac
done
name="${url##*/}"
count_file="$FAKE_CURL_STATE/${name}.count"
count=0
if [[ -f "$count_file" ]]; then count="$(cat "$count_file")"; fi
count=$((count + 1))
printf '%s' "$count" > "$count_file"
if (( count <= ${FAKE_CURL_FAIL_TIMES:-0} )); then
  echo "curl: (28) Operation timed out" >&2
  exit 28
fi
if [[ ! -f "$FAKE_RELEASE_DIR/$name" ]]; then
  echo "curl: (22) The requested URL returned error: 404" >&2
  exit 22
fi
cp "$FAKE_RELEASE_DIR/$name" "$output"
"""


def shell_path(path: Path) -> str:
    """Return a path the test shell understands (Git Bash needs POSIX form)."""
    if os.name != "nt":
        return str(path)
    return subprocess.check_output(["cygpath", "-u", str(path)], text=True).strip()


def fake_trivy(version: str) -> bytes:
    return (
        "#!/usr/bin/env bash\n"
        f"if [[ \"$1\" == --version ]]; then echo 'Version: {version}'; exit 0; fi\n"
        "exit 0\n"
    ).encode("utf-8")


def build_tarball(version: str) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for name, data, mode in (
            ("trivy", fake_trivy(version), 0o755),
            ("contrib/html.tpl", b"template\n", 0o644),
            ("LICENSE", b"license\n", 0o644),
        ):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = mode
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


@unittest.skipUnless(
    REQUIRES_POSIX_SHELL, "installer integration requires bash, tar and sha256sum"
)
class TrivyInstallShellTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.scripts = self.root / "action" / "scripts" / "security_gate"
        self.scripts.mkdir(parents=True)
        shutil.copy(INSTALLER, self.scripts / "install-trivy.sh")
        self.release_dir = self.root / "release"
        self.release_dir.mkdir()
        self.state = self.root / "curl-state"
        self.state.mkdir()
        bin_dir = self.root / "bin"
        bin_dir.mkdir()
        (bin_dir / "curl").write_text(FAKE_CURL, encoding="utf-8")
        (bin_dir / "curl").chmod(0o755)
        (bin_dir / "uname").write_text(
            '#!/usr/bin/env bash\nif [[ "$1" == -m ]]; then echo x86_64; else echo Linux; fi\n',
            encoding="utf-8",
        )
        (bin_dir / "uname").chmod(0o755)
        self.curl_log = self.root / "curl.log"
        self.github_path = self.root / "github_path"
        self.install_dir = self.root / "temp" / "optimizr-trivy" / "1-1-job"
        self.cache_home = self.root / "cache"
        self.environment = os.environ.copy()
        self.environment.update(
            {
                "PATH": f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}",
                "FAKE_CURL_LOG": shell_path(self.curl_log),
                "FAKE_CURL_STATE": shell_path(self.state),
                "FAKE_RELEASE_DIR": shell_path(self.release_dir),
                "GITHUB_PATH": shell_path(self.github_path),
                "XDG_CACHE_HOME": shell_path(self.cache_home),
                "OPTIMIZR_TRIVY_RETRY_DELAY_SECONDS": "0",
            }
        )
        self.environment.pop("OPTIMIZR_TRIVY_DOWNLOAD_ATTEMPTS", None)

    def publish(self, version: str, *, pin: bool = True, served_version: str | None = None) -> str:
        number = version.removeprefix("v")
        asset = f"trivy_{number}_Linux-64bit.tar.gz"
        data = build_tarball(served_version or number)
        (self.release_dir / asset).write_bytes(data)
        digest = hashlib.sha256(data).hexdigest()
        (self.release_dir / f"trivy_{number}_checksums.txt").write_text(
            f"{digest}  {asset}\n", encoding="utf-8"
        )
        checksums = self.scripts / "trivy-checksums.txt"
        if pin:
            with checksums.open("a", encoding="utf-8") as handle:
                handle.write(f"{digest}  {asset}\n")
        elif not checksums.exists():
            checksums.write_text("", encoding="utf-8")
        return digest

    def install(self, version: str = "v0.74.0", **extra: str) -> subprocess.CompletedProcess[str]:
        environment = self.environment.copy()
        environment.update(extra)
        return subprocess.run(
            [
                "bash",
                str(self.scripts / "install-trivy.sh"),
                "--version",
                version,
                "--install-dir",
                shell_path(self.install_dir),
            ],
            check=False,
            capture_output=True,
            text=True,
            env=environment,
        )

    def curl_calls(self) -> list[str]:
        if not self.curl_log.exists():
            return []
        return self.curl_log.read_text(encoding="utf-8").splitlines()

    def installed_binary(self) -> Path:
        return self.install_dir / "trivy-bin" / "trivy"

    def test_retries_transient_download_failures_with_bounded_timeouts(self) -> None:
        self.publish("v0.74.0")

        result = self.install(FAKE_CURL_FAIL_TIMES="2")

        self.assertEqual(result.returncode, 0, result.stderr)
        calls = self.curl_calls()
        self.assertEqual(len(calls), 3)
        for call in calls:
            self.assertIn("--connect-timeout", call)
            self.assertIn("--max-time", call)
            self.assertIn("--fail", call)
            self.assertIn("--proto =https", call)
            self.assertIn(
                "https://github.com/aquasecurity/trivy/releases/download/v0.74.0/"
                "trivy_0.74.0_Linux-64bit.tar.gz",
                call,
            )
        self.assertTrue(os.access(self.installed_binary(), os.X_OK))
        self.assertTrue((self.install_dir / "trivy-bin" / "contrib" / "html.tpl").is_file())
        self.assertEqual(
            self.github_path.read_text(encoding="utf-8").strip(),
            shell_path(self.install_dir / "trivy-bin"),
        )
        self.assertIn("attempt 1/4", result.stderr)

    def test_fails_closed_after_the_configured_number_of_attempts(self) -> None:
        self.publish("v0.74.0")

        result = self.install(FAKE_CURL_FAIL_TIMES="99", OPTIMIZR_TRIVY_DOWNLOAD_ATTEMPTS="3")

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(len(self.curl_calls()), 3)
        self.assertIn("after 3 attempts", result.stderr)
        self.assertFalse(self.installed_binary().exists())
        self.assertFalse(self.github_path.exists())

    def test_attempt_count_is_bounded(self) -> None:
        self.publish("v0.74.0")

        result = self.install(OPTIMIZR_TRIVY_DOWNLOAD_ATTEMPTS="50")

        self.assertEqual(result.returncode, 2)
        self.assertEqual(self.curl_calls(), [])

    def test_checksum_mismatch_fails_closed_without_retry_or_cache(self) -> None:
        self.publish("v0.74.0")
        (self.scripts / "trivy-checksums.txt").write_text(
            f"{'0' * 64}  trivy_0.74.0_Linux-64bit.tar.gz\n", encoding="utf-8"
        )

        result = self.install()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("checksum mismatch", result.stderr)
        self.assertEqual(len(self.curl_calls()), 1)
        self.assertFalse(self.installed_binary().exists())
        cache = self.cache_home / "optimizr-security-gate" / "trivy-binaries"
        self.assertEqual(list(cache.rglob("*.tar.gz")) if cache.exists() else [], [])

    def test_reuses_verified_cached_tarball_without_network(self) -> None:
        self.publish("v0.74.0")
        first = self.install()
        self.assertEqual(first.returncode, 0, first.stderr)
        shutil.rmtree(self.install_dir)
        self.github_path.unlink()

        second = self.install(FAKE_CURL_FAIL_TIMES="99")

        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(len(self.curl_calls()), 1)
        self.assertIn("verified cached", second.stderr)
        self.assertTrue(os.access(self.installed_binary(), os.X_OK))

    def test_corrupted_cache_is_discarded_and_downloaded_again(self) -> None:
        self.publish("v0.74.0")
        first = self.install()
        self.assertEqual(first.returncode, 0, first.stderr)
        cached = next(
            (self.cache_home / "optimizr-security-gate" / "trivy-binaries").rglob("*.tar.gz")
        )
        cached.write_bytes(b"tampered")
        shutil.rmtree(self.install_dir)

        second = self.install()

        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertIn("discarding cached", second.stderr)
        self.assertEqual(len(self.curl_calls()), 2)
        self.assertEqual(
            hashlib.sha256(cached.read_bytes()).hexdigest(),
            hashlib.sha256((self.release_dir / cached.name).read_bytes()).hexdigest(),
        )

    def test_unpinned_version_is_verified_against_release_checksums(self) -> None:
        self.publish("v0.73.1", pin=False)

        result = self.install("v0.73.1")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("not pinned", result.stderr)
        self.assertTrue(any("trivy_0.73.1_checksums.txt" in call for call in self.curl_calls()))

    def test_unpinned_version_with_mismatching_release_checksum_fails(self) -> None:
        self.publish("v0.73.1", pin=False)
        (self.release_dir / "trivy_0.73.1_checksums.txt").write_text(
            f"{'1' * 64}  trivy_0.73.1_Linux-64bit.tar.gz\n", encoding="utf-8"
        )

        result = self.install("v0.73.1")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("checksum mismatch", result.stderr)
        self.assertFalse(self.installed_binary().exists())

    def test_rejects_uncontrolled_versions_before_network(self) -> None:
        for version in ("latest", "../v0.74.0", "v0.74", ""):
            with self.subTest(version=version):
                result = self.install(version)
                self.assertEqual(result.returncode, 2)
        self.assertEqual(self.curl_calls(), [])

    def test_accepts_version_without_v_prefix(self) -> None:
        self.publish("v0.74.0")

        result = self.install("0.74.0")

        self.assertEqual(result.returncode, 0, result.stderr)

    def test_binary_reporting_another_version_fails_closed(self) -> None:
        self.publish("v0.74.0", served_version="0.69.4")

        result = self.install()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("reports an unexpected version", result.stderr)
        self.assertFalse(self.github_path.exists())

    def test_symlinked_binary_cache_fails_closed(self) -> None:
        if os.name == "nt":
            self.skipTest("creating symbolic links requires privileges on Windows")
        self.publish("v0.74.0")
        target = self.root / "elsewhere"
        target.mkdir()
        (self.cache_home / "optimizr-security-gate").mkdir(parents=True)
        (self.cache_home / "optimizr-security-gate" / "trivy-binaries").symlink_to(target)

        result = self.install()

        self.assertEqual(result.returncode, 2)
        self.assertIn("symbolic link", result.stderr)
        self.assertEqual(self.curl_calls(), [])


if __name__ == "__main__":
    unittest.main()
