"""Static contracts for immutable GHCR build and pull-only deployment."""

from __future__ import annotations

import unittest
from pathlib import Path

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
            "format('type=gha,scope={0}-{1}'",
            "format('type=gha,mode=max,scope={0}-{1}'",
            "steps.build.outputs.digest",
            "release-manifest.json",
            "prebuilt_images_json:",
            "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
            "docker/setup-buildx-action@f87e5991a6d7451dcb8d9637bfbc97413f497069",
            "docker/login-action@dbcb813823bdd20940b903addbd779551569679f",
            "docker/build-push-action@c3c9e263c25d99ce0380d002d59b67737d91b0dc",
            "Security gate for exact quarantine digest before promotion",
            "Promote verified image by digest",
            "verify_published_digest.py",
            '--image-ref "$RELEASE_IMAGE"',
            '--expected-digest "$IMAGE_DIGEST"',
            "verify_attestations.py",
            "image_ref=\"$CANDIDATE_IMAGE@$IMAGE_DIGEST\"",
            "--sbom-input \"$sbom_file\"",
            "--provenance-input \"$provenance_file\"",
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

    def test_matrix_build_job_has_bounded_timeout_and_service_evidence(self) -> None:
        content = BUILD_WORKFLOW.read_text(encoding="utf-8")
        build_job = content[content.index("  build:") : content.index("  aggregate:")]

        self.assertIn("timeout-minutes: ${{ inputs.timeout_minutes }}", build_job)
        self.assertIn("name: Build ${{ matrix.service.name }}", build_job)
        self.assertIn("SERVICE_NAME: ${{ matrix.service.name }}", build_job)
        self.assertIn("- name: Build image", build_job)

    def test_build_timeout_is_configurable_and_bounded(self) -> None:
        content = BUILD_WORKFLOW.read_text(encoding="utf-8")

        timeout_start = content.index("      timeout_minutes:")
        timeout_input = content[timeout_start:].split("      provenance:", 1)[0]
        self.assertIn("type: number", timeout_input)
        self.assertIn("default: 150", timeout_input)
        self.assertIn('TIMEOUT_MINUTES: ${{ inputs.timeout_minutes }}', content)
        self.assertIn("timeout_minutes must be an integer between 1 and 360", content)

    def test_build_cache_backend_is_selectable_and_local_path_is_required(self) -> None:
        content = BUILD_WORKFLOW.read_text(encoding="utf-8")
        build_job = content[content.index("  build:") : content.index("  aggregate:")]

        self.assertIn("cache_type:", content)
        self.assertIn("default: gha", content)
        self.assertIn('CACHE_TYPE: ${{ inputs.cache_type }}', content)
        self.assertIn('LOCAL_CACHE_PATH: ${{ inputs.local_cache_path }}', content)
        self.assertIn('cache_type must be one of: gha, local, none', content)
        self.assertIn("local_cache_path is required when cache_type is local", content)
        self.assertIn("local_cache_path must be an absolute path", content)
        self.assertIn("format('type=gha,scope={0}-{1}'", build_job)
        self.assertIn("format('type=gha,mode=max,scope={0}-{1}'", build_job)
        self.assertIn("format('type=local,src={0}/{1}'", build_job)
        self.assertIn("format('type=local,dest={0}/{1},mode=max'", build_job)
        cache_lines = [
            line
            for line in build_job.splitlines()
            if line.strip().startswith(("cache-from:", "cache-to:"))
        ]
        self.assertEqual(
            ["cache-from", "cache-to"],
            [line.strip().split(":", 1)[0] for line in cache_lines],
        )
        self.assertTrue(all(line.endswith("|| '' }}") for line in cache_lines))

        documentation = BUILD_DOC.read_text(encoding="utf-8")
        self.assertIn("local_cache_path", documentation)
        self.assertIn("outside `GITHUB_WORKSPACE`", documentation)
        self.assertIn("serialize separate workflow runs", documentation)

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

    def test_aggregate_manifest_keeps_same_named_fragments_isolated(self) -> None:
        content = BUILD_WORKFLOW.read_text(encoding="utf-8")
        aggregate = content[content.index("  aggregate:"):]

        self.assertIn("merge-multiple: false", aggregate)
        self.assertIn('rglob("release-fragment.json")', aggregate)
        self.assertNotIn("merge-multiple: true", aggregate)
        self.assertNotIn(
            'Path(os.environ["FRAGMENTS_DIR"]).glob("release-fragment.json")',
            aggregate,
        )

    def test_promotion_uses_bounded_fail_closed_digest_verification(self) -> None:
        content = BUILD_WORKFLOW.read_text(encoding="utf-8")

        self.assertIn("verify_published_digest.py", content)
        self.assertIn('--image-ref "$RELEASE_IMAGE"', content)
        self.assertIn('--expected-digest "$IMAGE_DIGEST"', content)
        self.assertNotIn(
            'promoted_digest="$(docker buildx imagetools inspect "$RELEASE_IMAGE"',
            content,
        )

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

    def test_prebuilt_deploy_accepts_the_build_manifest_directly(self) -> None:
        documentation = BUILD_DOC.read_text(encoding="utf-8")
        for workflow in (DEPLOY_WORKFLOW, SELF_HOSTED_DEPLOY_WORKFLOW):
            content = workflow.read_text(encoding="utf-8")
            with self.subTest(workflow=workflow.name):
                self.assertIn("release_manifest_json:", content)
                self.assertIn("RELEASE_MANIFEST_JSON", content)
                self.assertIn('"schema_version"', content)
                self.assertIn('"published"', content)
                self.assertIn("release manifest is required", content)
        self.assertIn("release_manifest_json: ${{ needs.images.outputs.manifest_json }}", documentation)
        self.assertIn("prebuilt_images_json", documentation)

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
                self.assertIn(
                    'DOCKER_CONFIG="$DOCKER_CONFIG_DIR" docker_cmd logout "$REGISTRY"',
                    content,
                )
                self.assertNotIn('sudo env "DOCKER_CONFIG=', content)
                self.assertIn("Clean registry authentication state", content)


if __name__ == "__main__":
    unittest.main()
