from pathlib import Path
import unittest


ROOT = Path(__file__).parents[1]
ACTION = ROOT / ".github/actions/python-uv-test-steps/action.yml"


class PythonUvTestStepsContractTests(unittest.TestCase):
    def test_python_steps_disable_bytecode_in_shared_workspace(self) -> None:
        text = ACTION.read_text(encoding="utf-8")

        self.assertEqual(4, text.count('PYTHONDONTWRITEBYTECODE: "1"'))


if __name__ == "__main__":
    unittest.main()
