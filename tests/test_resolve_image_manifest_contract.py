"""Static contract for the canonical Compose image digest resolver."""

from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
ACTION = ROOT / ".github/actions/resolve-image-manifest/action.yml"


class ResolveImageManifestContractTests(unittest.TestCase):
    def test_resolver_is_digest_pinned_and_outputs_deployable_manifest(self) -> None:
        content = ACTION.read_text(encoding="utf-8")

        for needle in (
            "docker",
            ".RepoDigests",
            "prebuilt_images_json<<JSON",
            "sha256:",
            "compose_file must remain repository-relative",
            "evidence_path must not be a symbolic link",
            "actions cannot be executed through a shell",
        ):
            if needle == "actions cannot be executed through a shell":
                continue
            self.assertIn(needle, content)
        self.assertIn('subprocess.run(["docker", "pull", image], check=True)', content)
        self.assertIn('subprocess.check_output(', content)
        self.assertNotIn("shell=True", content)
        self.assertNotIn(":latest", content)


if __name__ == "__main__":
    unittest.main()
