"""Contract tests for the opt-in export-then-push publication mode."""

from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BUILD_WORKFLOW = ROOT / ".github/workflows/_container-build-publish.yml"
RESILIENCE_DOC = ROOT / "docs/CONTAINER_PUBLISH_AUTH_RESILIENCE.md"
BUILD_DOC = ROOT / "docs/IMMUTABLE_CONTAINER_DEPLOY.md"
CATALOG = ROOT / "catalog/capabilities.json"
LOGIN_ACTION = "docker/login-action@dbcb813823bdd20940b903addbd779551569679f"


def _workflow() -> str:
    return BUILD_WORKFLOW.read_text(encoding="utf-8")


def _build_job() -> str:
    content = _workflow()
    return content[content.index("  build:") : content.index("  aggregate:")]


def _step(job: str, name: str) -> str:
    start = job.index(f"      - name: {name}\n")
    end = job.find("\n      - name:", start + 1)
    return job[start:] if end == -1 else job[start:end]


def _input_block(name: str) -> str:
    content = _workflow()
    start = content.index(f"      {name}:\n")
    end = re.search(r"\n      [a-z_]+:\n|\n    secrets:", content[start + 1 :])
    assert end
    return content[start : start + 1 + end.start()]


class ContainerPublishAuthResilienceContractTests(unittest.TestCase):
    def test_publish_mode_is_opt_in_and_defaults_to_the_inline_v1_behavior(self) -> None:
        block = _input_block("publish_mode")
        self.assertIn("type: string", block)
        self.assertIn("default: inline", block)
        self.assertIn("required: false", block)

    def test_auth_retries_are_bounded_and_validated(self) -> None:
        block = _input_block("publish_auth_retries")
        self.assertIn("type: number", block)
        self.assertIn("default: 3", block)
        content = _workflow()
        self.assertIn("PUBLISH_MODE: ${{ inputs.publish_mode }}", content)
        self.assertIn("PUBLISH_AUTH_RETRIES: ${{ inputs.publish_auth_retries }}", content)
        self.assertIn("publish_mode must be one of: inline, export-then-push", content)
        self.assertIn("publish_auth_retries must be an integer between 1 and 5", content)

    def test_inline_mode_keeps_buildkit_registry_push(self) -> None:
        build = _step(_build_job(), "Build image")
        self.assertIn("push: ${{ inputs.push && inputs.publish_mode == 'inline' }}", build)
        self.assertIn("load: ${{ !inputs.push }}", build)
        self.assertIn("tags: ${{ env.CANDIDATE_IMAGE }}", build)
        self.assertIn("provenance: ${{ inputs.provenance }}", build)
        self.assertIn("sbom: ${{ inputs.sbom }}", build)

    def test_split_mode_exports_one_oci_layout_with_attestations(self) -> None:
        job = _build_job()
        build = _step(job, "Build image")
        self.assertIn(
            "outputs: ${{ inputs.push && inputs.publish_mode == 'export-then-push' && "
            "format('type=oci,dest={0},tar=false', env.OCI_LAYOUT_DIR) || '' }}",
            build,
        )
        self.assertIn("OCI_LAYOUT_DIR=${RUNNER_TEMP}/optimizr-oci-${SERVICE_NAME}-${GITHUB_RUN_ID}", job)

    def test_split_mode_reauthenticates_immediately_before_publishing(self) -> None:
        job = _build_job()
        names = re.findall(r"^      - name: (.+)$", job, re.MULTILINE)
        refresh = "Refresh registry login immediately before publish"
        publish = "Publish exported image with bounded auth refresh"
        self.assertEqual(names.index("Build image") + 1, names.index(refresh))
        self.assertEqual(names.index(refresh) + 1, names.index(publish))
        self.assertLess(names.index(publish), names.index("Verify quarantine SBOM and provenance"))

        refresh_step = _step(job, refresh)
        self.assertIn(f"uses: {LOGIN_ACTION}", refresh_step)
        self.assertIn("if: inputs.push && inputs.publish_mode == 'export-then-push'", refresh_step)
        self.assertIn("password: ${{ secrets.registry_password }}", refresh_step)

    def test_split_mode_pushes_the_same_built_digest_with_bounded_retries(self) -> None:
        publish = _step(_build_job(), "Publish exported image with bounded auth refresh")
        for needle in (
            "id: publish",
            "if: inputs.push && inputs.publish_mode == 'export-then-push'",
            "REGISTRY_USERNAME: ${{ secrets.registry_username }}",
            "REGISTRY_PASSWORD: ${{ secrets.registry_password }}",
            "IMAGE_DIGEST: ${{ steps.build.outputs.digest }}",
            "PUBLISH_AUTH_RETRIES: ${{ inputs.publish_auth_retries }}",
            "python3 .optimizr-actions-source/scripts/container_release/push_oci_layout.py",
            '--layout "$OCI_LAYOUT_DIR"',
            '--image-ref "$CANDIDATE_IMAGE"',
            '--expected-digest "$IMAGE_DIGEST"',
            '--max-auth-retries "$PUBLISH_AUTH_RETRIES"',
        ):
            with self.subTest(needle=needle):
                self.assertIn(needle, publish)
        self.assertNotIn("${{ secrets.registry_password }}\"", publish)
        self.assertNotIn("run: |\n          echo", publish)

    def test_downstream_steps_never_run_after_a_failed_publish(self) -> None:
        job = _build_job()
        guarded = "if: always() && steps.build.outcome == 'success' && steps.publish.outcome != 'failure'"
        for name in (
            "Evaluate and record image security decision",
            "Upload pre-promotion security evidence",
            "Write image digest fragment",
            "Require pre-promotion gates",
            "Upload image digest fragment",
        ):
            with self.subTest(step=name):
                self.assertIn(guarded, _step(job, name))
        self.assertNotIn("if: always() && steps.build.outcome == 'success'\n", job)

    def test_quarantine_verification_still_gates_promotion_in_both_modes(self) -> None:
        job = _build_job()
        verify = _step(job, "Verify quarantine SBOM and provenance")
        self.assertIn("if: inputs.push", verify)
        self.assertIn('image_ref="$CANDIDATE_IMAGE@$IMAGE_DIGEST"', verify)
        promote = _step(job, "Promote verified image by digest")
        self.assertIn("steps.verify-quarantine-attestations.outcome == 'success'", promote)
        self.assertIn("verify_published_digest.py", promote)

    def test_exported_layout_is_removed_even_on_failure(self) -> None:
        cleanup = _step(_build_job(), "Remove exported OCI layout")
        self.assertIn("if: always() && inputs.push && inputs.publish_mode == 'export-then-push'", cleanup)
        self.assertIn('rm -rf -- "$OCI_LAYOUT_DIR"', cleanup)

    def test_workflow_permissions_are_not_broadened(self) -> None:
        job = _build_job()
        permissions = job[job.index("    permissions:") : job.index("    strategy:")]
        self.assertEqual(
            "    permissions:\n      contents: read\n      packages: write\n"
            "      attestations: write\n      id-token: write\n",
            permissions,
        )

    def test_resilience_contract_is_documented(self) -> None:
        documentation = RESILIENCE_DOC.read_text(encoding="utf-8")
        for needle in (
            "publish_mode",
            "export-then-push",
            "publish_auth_retries",
            "401",
            "Failure modes",
            "Rollback",
            "Consumer inventory",
            "optimizr-monitoring",
            "disk",
        ):
            with self.subTest(needle=needle):
                self.assertIn(needle, documentation)
        self.assertIn("CONTAINER_PUBLISH_AUTH_RESILIENCE.md", BUILD_DOC.read_text(encoding="utf-8"))

    def test_capability_catalog_lists_the_new_inputs(self) -> None:
        catalog = json.loads(CATALOG.read_text(encoding="utf-8"))
        entries = [
            entry
            for entry in catalog["artifacts"]
            if entry.get("path") == ".github/workflows/_container-build-publish.yml"
        ]
        self.assertEqual(1, len(entries))
        self.assertIn("publish_mode", entries[0]["inputs"])
        self.assertIn("publish_auth_retries", entries[0]["inputs"])


if __name__ == "__main__":
    unittest.main()
