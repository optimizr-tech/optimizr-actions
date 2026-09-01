from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
PYTHON_WORKFLOW = ROOT / ".github/workflows/_python-uv-test.yml"
BUILD_WORKFLOW = ROOT / ".github/workflows/_container-build-publish.yml"


class ResourceGuardContractTests(unittest.TestCase):
    def test_integration_services_have_explicit_resource_caps(self) -> None:
        text = PYTHON_WORKFLOW.read_text(encoding="utf-8")
        self.assertEqual(4, text.count("--memory 512m"))
        self.assertEqual(2, text.count("--memory 256m"))
        self.assertEqual(4, text.count("--pids-limit 128"))
        self.assertEqual(2, text.count("--pids-limit 64"))
        self.assertEqual(4, text.count("--cpus 0.50"))
        self.assertEqual(2, text.count("--cpus 0.25"))

    def test_container_builds_are_serial_by_default_and_bounded(self) -> None:
        text = BUILD_WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("max_parallel:", text)
        self.assertIn("default: 1", text)
        self.assertIn("MAX_PARALLEL: ${{ inputs.max_parallel }}", text)
        self.assertIn("max_parallel must be between 1 and 8", text)
        self.assertIn("max-parallel: ${{ inputs.max_parallel }}", text)


if __name__ == "__main__":
    unittest.main()
