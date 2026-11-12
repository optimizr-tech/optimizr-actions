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

    def test_mypy_cache_is_pinned_and_keyed_to_python_and_project_dependencies(self) -> None:
        text = ACTION.read_text(encoding="utf-8")

        cache_step = text.index("- name: Restore mypy cache")
        mypy_step = text.index("- name: Type check (mypy)")
        self.assertLess(cache_step, mypy_step)
        self.assertIn(
            "uses: actions/cache@0057852bfaa89a56745cba8c7296529d2fc39830",
            text,
        )
        self.assertIn("${{ inputs.working_directory }}/.mypy_cache", text)
        self.assertIn("${{ runner.os }}-py${{ inputs.python_version }}", text)
        self.assertIn("pyproject.toml", text)
        self.assertIn("uv.lock", text)
        self.assertIn("if: inputs.mypy_enabled == 'true'", text[cache_step:mypy_step])


if __name__ == "__main__":
    unittest.main()
