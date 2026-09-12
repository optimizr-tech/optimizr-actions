from pathlib import Path
import unittest


ROOT = Path(__file__).parents[1]
ACTION = ROOT / ".github/actions/python-uv-test-steps/action.yml"


class PythonUvTestStepsContractTests(unittest.TestCase):
    def test_python_steps_disable_bytecode_in_shared_workspace(self) -> None:
        text = ACTION.read_text(encoding="utf-8")

        self.assertEqual(4, text.count('PYTHONDONTWRITEBYTECODE: "1"'))

    def test_python_steps_verify_checkout_before_uv(self) -> None:
        text = ACTION.read_text(encoding="utf-8")

        self.assertIn("checkout-integrity@v1", text)
        self.assertIn("Validate Python project materialization", text)
        self.assertIn(
            "required_paths_json: ${{ steps.checkout_paths.outputs.required_paths_json }}",
            text,
        )
        self.assertLess(text.index("Verify checkout integrity"), text.index("Setup uv"))
        self.assertLess(
            text.index("Validate Python project materialization"),
            text.index("Install dependencies"),
        )


if __name__ == "__main__":
    unittest.main()
