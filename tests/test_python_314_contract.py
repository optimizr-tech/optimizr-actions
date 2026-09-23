from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]


def read(relative_path: str) -> str:
    return (ROOT / relative_path).read_text(encoding="utf-8")


def input_block(content: str, name: str, indent: str = "      ") -> str:
    child_indent = indent + "  "
    match = re.search(
        rf"^{re.escape(indent)}{name}:\n(?P<body>(?:{re.escape(child_indent)}.*\n)+)",
        content,
        re.MULTILINE,
    )
    if match is None:
        raise AssertionError(f"missing workflow input: {name}")
    return match.group("body")


class Python314ContractTests(unittest.TestCase):
    def test_python_uv_and_quality_gate_script_defaults_use_python_314(self) -> None:
        workflow = read(".github/workflows/_python-uv-test.yml")
        python_uv_steps = read(".github/actions/python-uv-test-steps/action.yml")
        action = read(".github/actions/quality-gate-scripts/action.yml")

        self.assertIn('default: "3.14"', input_block(workflow, "python_version"))
        self.assertIn(
            'default: "3.14"',
            input_block(python_uv_steps, "python_version", indent="  "),
        )
        self.assertIn(
            'default: "3.14"',
            input_block(action, "python_version", indent="  "),
        )

    def test_quality_gate_workflows_pin_python_314(self) -> None:
        setup_python = (
            "actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97"
        )
        for workflow_name in (
            "_quality-gate.yml",
            "_quality-gate-pr.yml",
            "_quality-gate-baseline.yml",
        ):
            content = read(f".github/workflows/{workflow_name}")
            with self.subTest(workflow=workflow_name):
                self.assertIn(setup_python, content)
                self.assertIn('python-version: "3.14"', content)

    def test_security_gate_sets_up_python_314_before_trivy(self) -> None:
        content = read(".github/actions/security-gate/action.yml")

        self.assertIn(
            "actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065",
            content,
        )
        self.assertIn('python-version: "3.14"', content)
        self.assertLess(content.index("Setup Python"), content.index("Install controlled Trivy"))

    def test_python_uv_canary_requires_python_314(self) -> None:
        for relative_path in (
            "tests/fixtures/python-uv-test-canary/pyproject.toml",
            "tests/fixtures/python-uv-test-canary/uv.lock",
        ):
            content = read(relative_path)
            with self.subTest(path=relative_path):
                self.assertIn('requires-python = ">=3.14"', content)


if __name__ == "__main__":
    unittest.main()
