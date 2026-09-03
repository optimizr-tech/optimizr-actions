from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/_python-uv-test.yml"
ACTION = ROOT / ".github/actions/python-uv-test-steps/action.yml"
DOCS = ROOT / "docs/PYTHON_UV_TEST_SHARDING.md"


class PythonUvShardingContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.workflow = WORKFLOW.read_text(encoding="utf-8")
        self.action = ACTION.read_text(encoding="utf-8")

    def test_sharding_inputs_are_additive_and_default_to_legacy_behavior(self) -> None:
        for input_name in (
            "shard_count",
            "max_parallel",
            "shard_distribution",
            "shard_durations_path",
            "pytest_split_version",
            "coverage_artifact_prefix",
        ):
            with self.subTest(input_name=input_name):
                self.assertIn(f"      {input_name}:", self.workflow)

        self.assertRegex(
            self.workflow,
            r"shard_count:\n\s+description:.*\n\s+required: false\n\s+type: number\n\s+default: 1",
        )
        self.assertRegex(
            self.workflow,
            r"max_parallel:\n\s+description:.*\n\s+required: false\n\s+type: number\n\s+default: 1",
        )
        self.assertRegex(
            self.workflow,
            r"shard_distribution:\n\s+description:.*\n\s+required: false\n\s+type: string\n\s+default: count",
        )
        self.assertIn('default: "0.11.0"', self.workflow)
        self.assertIn('default: "python-uv-test-coverage"', self.workflow)

    def test_plan_is_bounded_and_emits_every_stable_shard_index(self) -> None:
        self.assertIn("shard-plan:", self.workflow)
        self.assertIn("shard_indices:", self.workflow)
        self.assertIn("range(1, shard_count + 1)", self.workflow)
        self.assertIn("if shard_count < 2 or shard_count > 8", self.workflow)
        self.assertIn("if max_parallel < 1 or max_parallel > shard_count", self.workflow)
        self.assertIn("fromJSON(needs.shard-plan.outputs.shard_indices)", self.workflow)

    def test_matrix_is_fail_safe_and_uses_unique_shard_identity(self) -> None:
        self.assertIn("fail-fast: false", self.workflow)
        self.assertIn("max-parallel: ${{ inputs.max_parallel }}", self.workflow)
        self.assertIn("matrix.shard_index", self.workflow)
        self.assertIn("--splits", self.action)
        self.assertIn('"$SHARD_COUNT"', self.action)
        self.assertIn("--group", self.action)
        self.assertIn('"$SHARD_INDEX"', self.action)
        self.assertIn("SHARD_INDEX", self.action)
        self.assertIn("coverage_artifact_prefix }}-shard-${{ matrix.shard_index }}", self.workflow)

    def test_each_integration_shard_declares_its_own_services(self) -> None:
        self.assertIn("test-integration-sharded:", self.workflow)
        sharded_section = self.workflow.split("test-integration-sharded:", 1)[1]
        self.assertIn("services:", sharded_section)
        for image in (
            "postgres:16.14-alpine@sha256:",
            "redis:7.4.9-alpine@sha256:",
            "rabbitmq:4.2.9-management-alpine@sha256:",
        ):
            with self.subTest(image=image):
                self.assertIn(image, sharded_section)

    def test_aggregate_gate_requires_all_shards_and_preserves_threshold(self) -> None:
        self.assertIn("aggregate-coverage:", self.workflow)
        aggregate_section = self.workflow.split("aggregate-coverage:", 1)[1]
        download_section = aggregate_section.split(
            "- name: Download every shard coverage artifact", 1
        )[1].split("Merge coverage and enforce aggregate threshold:", 1)[0]
        self.assertIn("needs.test-sharded.result", aggregate_section)
        self.assertIn("needs.test-integration-sharded.result", aggregate_section)
        self.assertIn("include-hidden-files: true", download_section)
        self.assertIn("coverage combine coverage-input", aggregate_section)
        self.assertIn("--fail-under=\"$COVERAGE_MIN\"", aggregate_section)
        self.assertIn("EXPECTED_COUNT: ${{ inputs.shard_count }}", aggregate_section)
        self.assertIn('if [ "$found_count" -ne "$EXPECTED_COUNT" ]; then', aggregate_section)
        self.assertIn("coverage_gate_enabled: false", self.workflow)
        self.assertIn('default: "true"', self.action)
        upload_section = self.action.split("- name: Upload coverage artifact", 1)[1]
        self.assertIn("include-hidden-files: true", upload_section)

    def test_third_party_actions_remain_immutable(self) -> None:
        for text in (self.workflow, self.action):
            self.assertIsNone(
                re.search(
                    r"uses:\s+(?:actions|astral-sh)/[^@\s]+@v\d",
                    text,
                )
            )

    def test_documentation_covers_cache_merge_retries_and_runner_guidance(self) -> None:
        docs = DOCS.read_text(encoding="utf-8")
        for phrase in (
            "cache",
            "coverage combine",
            "retry",
            "max_parallel",
            "shard_count",
            "pytest-split",
            "threshold",
        ):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, docs.lower())


if __name__ == "__main__":
    unittest.main()
