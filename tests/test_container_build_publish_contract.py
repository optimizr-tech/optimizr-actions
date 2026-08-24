"""Static contracts for immutable GHCR build and pull-only deployment."""

from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
BUILD_WORKFLOW = ROOT / ".github/workflows/_container-build-publish.yml"
ACTIONLINT_CONFIG = ROOT / ".github/actionlint.yaml"
BUILD_DOC = ROOT / "docs/IMMUTABLE_CONTAINER_DEPLOY.md"
GHCR_BUILD_DOC = ROOT / "docs/GHCR_IMAGE_BUILD_CONTRACT.md"
DEPLOY_WORKFLOW = ROOT / ".github/workflows/_vps-monorepo-deploy.yml"
SELF_HOSTED_DEPLOY_WORKFLOW = ROOT / ".github/workflows/_vps-self-hosted-deploy.yml"


class ContainerBuildPublishContractTests(unittest.TestCase):
    def test_build_workflow_publishes_matrix_images_by_digest(self) -> None:
        self.assertTrue(BUILD_WORKFLOW.exists())
        content = BUILD_WORKFLOW.read_text(encoding="utf-8")
        documentation = BUILD_DOC.read_text(encoding="utf-8")

        for needle in (
            "services_json:",
            "image_namespace:",
            "candidate_sha:",
            "registry:",
            "push:",
            "strategy:",
            "matrix:",
            "fromJSON(needs.validate.outputs.services_json)",
            "cache-from: type=gha",
            "cache-to: type=gha,mode=max",
            "steps.build.outputs.digest",
            "release-manifest.json",
            "prebuilt_images_json:",
            "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
            "docker/setup-buildx-action@8d2750c68a42422c14e847fe6c8ac0403b4cbd6f",
            "docker/build-push-action@10e90e3645eae34f1e60eeb005ba3a3d33f178e8",
            "Security gate for exact quarantine digest before promotion",
            "Promote verified image by digest",
            "verify_attestations.py",
            "attestation_verified",
        ):
            self.assertIn(needle, content)

        self.assertIn("permissions:\n      contents: read\n      packages: write", content)
        self.assertIn("attestations: write", content)
        self.assertIn("id-token: write", content)
        self.assertNotIn("permissions:\n  contents: read\n  packages: write", content)
        self.assertIn("github_attestation:", content)
        self.assertIn("requires Enterprise Cloud for private repositories", content)
        self.assertNotIn(":latest", content)
        self.assertNotIn("docker/build-push-action@v", content)
        self.assertIn("provenance: ${{ inputs.provenance }}", content)
        self.assertIn("sbom: ${{ inputs.sbom }}", content)
        self.assertIn("Caller permission contract", documentation)
        self.assertIn("attestations: write", documentation)
        self.assertIn("id-token: write", documentation)

    def test_build_workflow_does_not_publish_without_explicit_push(self) -> None:
        content = BUILD_WORKFLOW.read_text(encoding="utf-8")

        self.assertIn("default: false", content[content.index("      push:") :])
        self.assertIn("push: ${{ inputs.push }}", content)
        self.assertIn("if: inputs.push", content)
        self.assertIn("registry_password", content)
        self.assertIn("load: ${{ !inputs.push }}", content)
        self.assertIn("candidate-", content)

    def test_build_workflow_checks_out_exact_reusable_sources_for_portable_gates(self) -> None:
        content = BUILD_WORKFLOW.read_text(encoding="utf-8")

        self.assertIn("name: Checkout exact reusable implementation", content)
        self.assertIn("repository: ${{ job.workflow_repository }}", content)
        self.assertIn("ref: ${{ job.workflow_sha }}", content)
        self.assertIn("path: .optimizr-actions-source", content)
        self.assertIn(
            "python3 .optimizr-actions-source/scripts/container_release/verify_attestations.py",
            content,
        )
        self.assertIn(
            "uses: ./.optimizr-actions-source/.github/actions/security-gate",
            content,
        )
        self.assertNotIn("uses: ./.github/actions/security-gate", content)

    def test_actionlint_exception_is_scoped_to_exact_reusable_identity(self) -> None:
        content = ACTIONLINT_CONFIG.read_text(encoding="utf-8")

        workflow_start = content.index("  .github/workflows/_container-build-publish.yml:")
        workflow_block = content[workflow_start:].split("\n  .github/workflows/", 1)[0]

        self.assertIn(
            'property "workflow_(repository|sha)" is not defined in object type .+',
            workflow_block,
        )

    def test_build_workflow_exposes_unfixed_security_policy_to_both_gates(self) -> None:
        content = BUILD_WORKFLOW.read_text(encoding="utf-8")
        documentation = GHCR_BUILD_DOC.read_text(encoding="utf-8")

        self.assertIn(
            "security_ignore_unfixed:\n"
            "        description: Explicitly allow vendor-will-not-fix findings "
            "to pass the pre-publication gates\n"
            "        required: false\n"
            "        type: boolean\n"
            "        default: false",
            content,
        )
        self.assertEqual(
            2,
            content.count("ignore_unfixed: ${{ inputs.security_ignore_unfixed }}"),
        )
        self.assertIn("security_ignore_unfixed", documentation)
        self.assertIn(
            "fixed vulnerabilities, misconfigurations,\nsecrets",
            documentation,
        )

    def test_control_jobs_can_run_on_self_hosted_without_changing_build_runner(self) -> None:
        content = BUILD_WORKFLOW.read_text(encoding="utf-8")
        documentation = BUILD_DOC.read_text(encoding="utf-8")

        for needle in (
            "control_runner_json:",
            "JSON labels for validation and manifest aggregation",
            "default: '[\"ubuntu-latest\"]'",
            "runs-on: ${{ fromJSON(inputs.control_runner_json) }}",
        ):
            self.assertIn(needle, content)

        self.assertEqual(
            content.count("runs-on: ${{ fromJSON(inputs.control_runner_json) }}"),
            2,
        )
        self.assertIn("`control_runner_json`", documentation)
        self.assertIn("dedicated self-hosted container-builder", documentation)

    def test_build_contract_records_and_requires_security_evidence(self) -> None:
        content = BUILD_WORKFLOW.read_text(encoding="utf-8")

        self.assertIn("Upload pre-promotion security evidence", content)
        self.assertIn("Require pre-promotion gates", content)
        self.assertIn("published release manifest is missing attestation verification", content)
        self.assertIn("prebuilt_images_json=", content)
        self.assertIn("] if manifest[\"published\"] else []", content)

    def test_monorepo_deploy_supports_backward_compatible_pull_only_mode(self) -> None:
        content = DEPLOY_WORKFLOW.read_text(encoding="utf-8")

        for needle in (
            "deployment_mode:",
            "default: build",
            "prebuilt_images_json:",
            "prebuilt_compose_file:",
            "registry:",
            "registry_username:",
            "registry_password:",
            "docker_cmd login",
            "docker_cmd pull \"$image_ref\"",
            "@sha256:",
            "deployment_mode == 'prebuilt-images'",
            "compose_override_file:",
        ):
            self.assertIn(needle, content)

        self.assertIn("deployment_mode != 'prebuilt-images'", content)
        self.assertIn("docker_cmd compose \"${compose_args[@]}\"", content)
        self.assertIn("up_flags+=(--no-build)", content)

    def test_pull_only_mode_fails_closed_on_invalid_or_missing_digest(self) -> None:
        content = DEPLOY_WORKFLOW.read_text(encoding="utf-8")

        for needle in (
            "PREBUILT_IMAGES_JSON",
            "sha256:[0-9a-f]{64}",
            "prebuilt-images mode requires",
            "Refusing to deploy an image without an immutable digest",
            "actual_repo_digest",
        ):
            self.assertIn(needle, content)

    def test_self_hosted_deploy_supports_immutable_prebuilt_images(self) -> None:
        content = SELF_HOSTED_DEPLOY_WORKFLOW.read_text(encoding="utf-8")

        for needle in (
            "deployment_mode:",
            "prebuilt_images_json:",
            "prebuilt_compose_file:",
            "Prepare immutable registry images",
            "Using anonymous pulls for public prebuilt images",
            "Pulled image digest does not match requested digest",
            "compose_cmd()",
            "inputs.deployment_mode != 'prebuilt-images'",
            "compose_override_file:",
        ):
            self.assertIn(needle, content)
        self.assertNotIn('docker_cmd compose -f "$COMPOSE_FILE"', content)
        self.assertIn('--exclude="$PREBUILT_COMPOSE_FILE"', content)

    def test_prebuilt_deploy_auth_modes_are_explicit_and_least_privilege(self) -> None:
        monorepo = DEPLOY_WORKFLOW.read_text(encoding="utf-8")
        self_hosted = SELF_HOSTED_DEPLOY_WORKFLOW.read_text(encoding="utf-8")
        documentation = BUILD_DOC.read_text(encoding="utf-8")

        self.assertIn("registry_auth_mode:", monorepo)
        self.assertIn("default: explicit", monorepo)
        self.assertIn("registry_auth_mode:", self_hosted)
        self.assertIn("default: anonymous", self_hosted)

        for content in (monorepo, self_hosted):
            self.assertIn("anonymous", content)
            self.assertIn("github-token", content)
            self.assertIn("explicit", content)
            self.assertIn("GITHUB_TOKEN: ${{ github.token }}", content)
            self.assertIn("REGISTRY_AUTH_MODE", content)
        self.assertIn("packages: read", documentation)

    def test_prebuilt_deploy_isolates_and_cleans_registry_docker_config(self) -> None:
        for workflow in (DEPLOY_WORKFLOW, SELF_HOSTED_DEPLOY_WORKFLOW):
            content = workflow.read_text(encoding="utf-8")
            with self.subTest(workflow=workflow.name):
                self.assertIn("DOCKER_CONFIG_DIR", content)
                self.assertIn("DOCKER_CONFIG=$DOCKER_CONFIG_DIR", content)
                self.assertIn('sudo env "DOCKER_CONFIG=', content)
                self.assertIn("docker logout", content)
                self.assertIn("Clean registry authentication state", content)


if __name__ == "__main__":
    unittest.main()
