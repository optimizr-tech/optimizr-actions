from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REQUIRES_LINUX_FLOCK = (
    os.name != "nt" and shutil.which("bash") and shutil.which("flock")
)


@unittest.skipUnless(
    REQUIRES_LINUX_FLOCK, "shared cache integration requires Linux bash and flock"
)
class TrivyCacheShellTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.bin_dir = self.root / "bin"
        self.bin_dir.mkdir()
        self.trivy_log = self.root / "trivy.log"
        self.cache_home = self.root / "cache"
        fake_trivy = self.bin_dir / "trivy"
        fake_trivy.write_text(
            """#!/usr/bin/env bash
set -euo pipefail
args="$*"
cache_dir=""
while (($#)); do
  if [[ "$1" == --cache-dir ]]; then
    cache_dir="$2"
    shift 2
  else
    shift
  fi
done
if [[ "$args" == *--download-db-only* ]]; then
  if [[ "${TRIVY_FAIL_DOWNLOAD:-0}" == 1 ]]; then
    echo download-failed >> "$TRIVY_LOG"
    exit 17
  fi
  mkdir -p "$cache_dir/db"
  printf 'test-db' > "$cache_dir/db/trivy.db"
  downloaded_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf '{"Version":2,"DownloadedAt":"%s"}\\n' "$downloaded_at" > "$cache_dir/db/metadata.json"
  echo download >> "$TRIVY_LOG"
  exit 0
fi
if [[ "$args" == *--skip-db-update* ]]; then
  if flock -n -x "$TRIVY_LOCK_PATH" -c true; then
    echo scan-without-read-lock >> "$TRIVY_LOG"
    exit 18
  fi
  if [[ -n "${TRIVY_SCAN_MARKER:-}" ]]; then
    : > "$TRIVY_SCAN_MARKER"
    deadline=$((SECONDS + 8))
    while [[ ! -f "$TRIVY_SCAN_RELEASE" ]]; do
      if ((SECONDS >= deadline)); then
        echo scan-wait-timeout >> "$TRIVY_LOG"
        exit 20
      fi
      sleep 0.05
    done
  fi
  echo scan >> "$TRIVY_LOG"
  exit 0
fi
exit 19
""",
            encoding="utf-8",
        )
        fake_trivy.chmod(0o700)
        self.environment = os.environ.copy()
        self.environment.update(
            {
                "ACTION_ROOT": str(ROOT),
                "GITHUB_REPOSITORY": "optimizr-tech/cache-shell-test",
                "PATH": f"{self.bin_dir}{os.pathsep}{os.environ.get('PATH', '')}",
                "TRIVY_LOG": str(self.trivy_log),
                "XDG_CACHE_HOME": str(self.cache_home),
            }
        )
        lock_path = (
            self.cache_home
            / "optimizr-security-gate"
            / "shared"
            / "trivy-v0.74.0.db.lock"
        )
        self.environment["TRIVY_LOCK_PATH"] = str(lock_path)

    def shared_scan_script(self) -> str:
        return """set -euo pipefail
source "$ACTION_ROOT/scripts/security_gate/trivy-cache.sh"
trivy_cache_setup "$ACTION_ROOT" "$GITHUB_REPOSITORY" v0.74.0 shared 30 14
trivy --cache-dir "$OPTIMIZR_TRIVY_CACHE_DIR" image \
  "${OPTIMIZR_TRIVY_DB_ARGS[@]}" alpine:3
"""

    def run_shared_scan(
        self, environment: dict[str, str] | None = None
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", "-c", self.shared_scan_script()],
            check=False,
            capture_output=True,
            text=True,
            env=environment or self.environment,
        )

    def test_shared_setup_refreshes_once_and_holds_read_lock_for_scans(self) -> None:
        first = self.run_shared_scan()
        second = self.run_shared_scan()

        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(
            self.trivy_log.read_text(encoding="utf-8").splitlines(),
            ["download", "scan", "scan"],
        )

    def test_fresh_shared_db_allows_different_repositories_to_scan_concurrently(self) -> None:
        warmup = self.run_shared_scan()
        self.assertEqual(warmup.returncode, 0, warmup.stderr)

        release = self.root / "release-scans"
        first_marker = self.root / "first-scan-started"
        second_marker = self.root / "second-scan-started"
        first_environment = self.environment.copy()
        first_environment.update(
            {
                "GITHUB_REPOSITORY": "optimizr-tech/cache-shell-first",
                "TRIVY_SCAN_MARKER": str(first_marker),
                "TRIVY_SCAN_RELEASE": str(release),
            }
        )
        second_environment = self.environment.copy()
        second_environment.update(
            {
                "GITHUB_REPOSITORY": "optimizr-tech/cache-shell-second",
                "TRIVY_SCAN_MARKER": str(second_marker),
                "TRIVY_SCAN_RELEASE": str(release),
            }
        )
        processes: list[subprocess.Popen[str]] = []
        try:
            first = subprocess.Popen(
                ["bash", "-c", self.shared_scan_script()],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=first_environment,
            )
            processes.append(first)
            self.assertTrue(self.wait_for_marker(first_marker, first))

            second = subprocess.Popen(
                ["bash", "-c", self.shared_scan_script()],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=second_environment,
            )
            processes.append(second)
            self.assertTrue(
                self.wait_for_marker(second_marker, second),
                "second repository did not reach its scan while the first was reading the DB",
            )
        finally:
            release.touch()
            for process in processes:
                if process.poll() is None:
                    process.communicate(timeout=10)

        for process in processes:
            stdout, stderr = process.communicate(timeout=10)
            self.assertEqual(process.returncode, 0, f"stdout={stdout}\nstderr={stderr}")

    @staticmethod
    def wait_for_marker(path: Path, process: subprocess.Popen[str]) -> bool:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if path.exists():
                return True
            if process.poll() is not None:
                return False
            time.sleep(0.05)
        return path.exists()

    def test_failed_shared_db_refresh_fails_before_a_scan(self) -> None:
        self.environment["TRIVY_FAIL_DOWNLOAD"] = "1"

        result = self.run_shared_scan()

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(
            self.trivy_log.read_text(encoding="utf-8").splitlines(),
            ["download-failed"],
        )


if __name__ == "__main__":
    unittest.main()
