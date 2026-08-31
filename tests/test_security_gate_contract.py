"""Static policy tests for billing-independent security gates."""

from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


class SecurityGateContractTests(unittest.TestCase):
    def test_trivy_actions_use_one_versioned_repository_cache(self) -> None:
        for action in (
            ".github/actions/security-gate/action.yml",
            ".github/actions/dependency-policy/action.yml",
            ".github/actions/supply-chain-evidence/action.yml",
            ".github/actions/trivy-scan/action.yml",
        ):
            with self.subTest(action=action):
                content = read(action)
                self.assertIn('cache.py" path', content)
                self.assertIn('--trivy-version "$TRIVY_VERSION"', content)
                self.assertIn("flock -x 9", content)
                self.assertIn('cache.py" prepare', content)

    def test_legacy_trivy_workflow_uses_the_shared_cache_contract(self) -> None:
        content = read(".github/workflows/_trivy-scan.yml")
        self.assertIn(
            "uses: optimizr-tech/optimizr-actions/.github/actions/trivy-scan@f042163c0d83712736bbc9cc168c4f9f98c488cf",
            content,
        )
        self.assertIn("exit_code", content)
        self.assertIn("trivy-results.txt", content)
        self.assertNotIn("aquasecurity/trivy-action@", content)

    def test_every_trivy_install_is_isolated_per_job(self) -> None:
        install_path = (
            "path: ${{ runner.temp }}/optimizr-trivy/"
            "${{ github.run_id }}-${{ github.run_attempt }}-${{ github.job }}"
        )

        for action in (
            ".github/actions/security-gate/action.yml",
            ".github/actions/dependency-policy/action.yml",
            ".github/actions/supply-chain-evidence/action.yml",
        ):
            with self.subTest(action=action):
                content = read(action)
                self.assertIn(install_path, content)
                self.assertNotIn("path: $HOME", content)

    def test_composite_action_reports_all_and_blocks_only_actionable_findings(self) -> None:
        content = read(".github/actions/security-gate/action.yml")

        self.assertIn(
            "aquasecurity/setup-trivy@81e514348e19b6112ce2a7e3ecbafe19c1e1f567",
            content,
        )
        self.assertIn('default: "v0.70.0"', content)
        self.assertIn('default: "true"', content)
        self.assertIn("--download-db-only", content)
        self.assertIn("scripts/security_gate/cache.py", content)
        self.assertIn("flock -x 9", content)
        self.assertIn("chmod 700", content)
        self.assertIn("validate-db", content)
        self.assertIn("render-exceptions", content)
        self.assertIn("filter-report", content)
        self.assertIn('filtered_blocking_json_report="${prefix}-filtered.json"', content)
        self.assertIn(
            'cp "$filtered_blocking_json_report" "$enforced_json_report"',
            content,
        )
        self.assertNotIn(
            'cp "$blocking_json_report" "$enforced_json_report"',
            content,
        )
        self.assertIn("scripts/security_gate/report.py", content)
        self.assertIn("scripts/security_gate/aggregate.py", content)
        self.assertIn("scripts/security_gate/remediation_window.py", content)
        self.assertIn("classification:", content)
        self.assertIn("remediation_window_allowed:", content)
        self.assertIn("remediation_state:", content)
        self.assertIn("remediation_window_reintroduced_count:", content)
        self.assertIn("nearest_deadline:", content)
        self.assertIn("policy_digest:", content)
        self.assertIn("evaluator_version:", content)
        self.assertIn("fixable_vulnerability_count:", content)
        self.assertIn("unfixed_vulnerability_count:", content)
        self.assertIn("misconfiguration_count:", content)
        self.assertIn("secret_count:", content)
        self.assertIn("report_args=(", content)
        self.assertIn('fs) scanners="vuln,misconfig,secret" ;;', content)
        self.assertIn('image) scanners="vuln,secret" ;;', content)
        self.assertIn('--scanners "$scanners"', content)
        self.assertIn('blocking_args=("${report_args[@]}" --ignore-unfixed)', content)
        self.assertIn('--format json --exit-code 0 --output "$json_report"', content)
        self.assertIn('--format json --exit-code 1 --output "$blocking_json_report"', content)
        self.assertIn('--report "blocking_json=$blocking_json_report"', content)
        self.assertIn('--report "summary=$finding_summary"', content)
        self.assertIn("vulnerabilities without an available fix remain visible", content)
        self.assertNotIn("ALLOW_MISSING_TRIVY", content)
        self.assertNotIn("continue-on-error: true", content)

    def test_remediation_window_contract_is_exposed_additively(self) -> None:
        action = read(".github/actions/security-gate/action.yml")
        workflow = read(".github/workflows/_security-gate.yml")
        self_hosted = read(".github/workflows/_vps-self-hosted-deploy.yml")
        monorepo = read(".github/workflows/_vps-monorepo-deploy.yml")

        for content in (action, workflow, self_hosted, monorepo):
            self.assertIn("remediation_window_enabled", content)
            self.assertIn("remediation_window_policy_file", content)
            self.assertIn("remediation_window_service_scope", content)
            self.assertIn("remediation_window_exposure_criticality", content)
            self.assertNotIn("remediation_window_evaluated_at", content)

        self.assertIn("remediation_window_allowed", action)
        self.assertIn("remediation_window_uncovered", action)
        self.assertIn("remediation_state", action)
        self.assertIn("remediation_window_allowed", workflow)
        self.assertIn("remediation_window_allowed", self_hosted)
        self.assertIn("remediation_window_allowed", monorepo)

    def test_missing_flock_is_an_actionable_runner_prerequisite_failure(self) -> None:
        content = read(".github/actions/security-gate/action.yml")

        self.assertIn("failure_reason:", content)
        self.assertIn("failure_reason=missing_flock", content)
        self.assertIn("Install util-linux", content)
        self.assertIn("self-hosted runner", content)
        self.assertIn("do not bypass the lock", content)

        documentation = read("docs/SECURITY_GATE.md")
        self.assertIn("`flock` from the `util-linux` package", documentation)
        self.assertIn("runner provisioning", documentation)

    def test_image_gate_has_deterministic_docker_transport_recovery(self) -> None:
        action = read(".github/actions/security-gate/action.yml")
        transport = read("scripts/security_gate/image_transport.py")
        deploy = read(".github/workflows/_vps-self-hosted-deploy.yml")
        monorepo = read(".github/workflows/_vps-monorepo-deploy.yml")
        standalone = read(".github/workflows/_security-gate.yml")

        self.assertIn("docker_mode:", action)
        self.assertIn('default: "auto"', action)
        self.assertIn("auto|direct|sudo", action)
        self.assertIn("scripts/security_gate/image_transport.py", action)
        self.assertIn('["sudo", "-n", "docker", "save"', transport)
        self.assertIn("--input", action)
        self.assertIn("trap cleanup_transport_artifacts EXIT", action)
        self.assertIn("rm -f -- \"$temporary_image\"", action)
        self.assertIn("failure_reason:", action)
        self.assertIn("docker_save_failed", transport)
        self.assertIn("docker_archive_ownership_failed", transport)

        for workflow in (deploy, monorepo):
            self.assertIn("docker_mode:", workflow)
            self.assertIn("default: sudo", workflow)
            self.assertIn("Local Docker access mode for deployment", workflow)
            self.assertIn("docker_mode: ${{ inputs.docker_mode }}", workflow)

        self.assertIn("docker_mode:", standalone)
        self.assertIn("docker_mode: ${{ inputs.docker_mode }}", standalone)

    def test_rebuild_timeout_and_scope_are_explicit_and_bounded(self) -> None:
        self_hosted = read(".github/workflows/_vps-self-hosted-deploy.yml")
        monorepo = read(".github/workflows/_vps-monorepo-deploy.yml")
        rebuild_action = read(".github/actions/security-rebuild/action.yml")
        rebuild_runtime = read("scripts/security_gate/rebuild.py")

        for workflow in (self_hosted, monorepo):
            self.assertIn("deploy_timeout_minutes:", workflow)
            timeout_contract = (
                "timeout-minutes: ${{ inputs.deploy_timeout_minutes != 0 && inputs.deploy_timeout_minutes || inputs.timeout_minutes }}"
                if "      timeout_minutes:\n" in workflow
                else "timeout-minutes: ${{ inputs.deploy_timeout_minutes }}"
            )
            self.assertIn(timeout_contract, workflow)
            self.assertIn("Effective deployment timeout", workflow)
            self.assertIn("allowed range is 30-120 minutes", workflow)

        self.assertIn("security_rebuild_services:", self_hosted)
        self.assertIn("build_all: ${{ inputs.security_rebuild_services == '' }}", self_hosted)
        self.assertIn("required_services: ${{ inputs.security_rebuild_services }}", self_hosted)
        self.assertIn("failure_reason:", rebuild_action)
        self.assertIn("security_rebuild_timeout", rebuild_runtime)

    def test_filesystem_owns_configuration_analysis_and_image_owns_runtime_packages(self) -> None:
        documentation = read("docs/SECURITY_GATE.md")

        self.assertIn("filesystem source gate owns configuration analysis", documentation)
        self.assertIn("image gate owns runtime packages and secrets", documentation)

    def test_reusable_workflow_runs_same_gate_on_selected_runner(self) -> None:
        content = read(".github/workflows/_security-gate.yml")

        self.assertIn("runs-on: ${{ fromJSON(inputs.runner_json) }}", content)
        self.assertIn('default: \'["ubuntu-latest"]\'', content)
        self.assertIn(
            "uses: optimizr-tech/optimizr-actions/.github/actions/security-gate@f042163c0d83712736bbc9cc168c4f9f98c488cf",
            content,
        )
        self.assertIn(
            "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
            content,
        )
        self.assertIn("if: always()", content)
        self.assertIn("permissions:\n  contents: read", content)
        self.assertNotIn("pull_request_target", content)

    def test_single_service_deploy_gates_filesystem_and_final_image_before_rollout(self) -> None:
        content = read(".github/workflows/_vps-self-hosted-deploy.yml")

        self.assertNotIn("security_gate_required:", content)
        self.assertIn("security_require_image_scan:", content)
        self.assertIn("security_rebuild_retry_enabled:", content)
        self.assertNotIn("inputs.security_gate_required", content)
        filesystem = content.index("Security gate (filesystem)")
        sync = content.index("Backup and synchronize files")
        build = content.index("Build images")
        pull = content.index("Pull declared runtime images")
        discover = content.index("Discover declarative Compose images")
        initial = content.index("Security gate (images, initial)")
        rebuild = content.index("Rebuild actionable image vulnerabilities")
        final = content.index("Security gate (images, remediated)")
        enforce = content.index("Enforce final image security result")
        deploy = content.index("Roll out and verify primary container")
        self.assertLess(filesystem, sync)
        self.assertLess(build, pull)
        self.assertLess(pull, discover)
        self.assertLess(discover, initial)
        self.assertLess(initial, rebuild)
        self.assertLess(rebuild, final)
        self.assertLess(final, enforce)
        self.assertLess(enforce, deploy)
        self.assertIn('compose_cmd config --images', content)
        self.assertIn(
            'compose_cmd pull --ignore-buildable', content
        )
        self.assertIn("docker_cmd image inspect", content)
        self.assertNotIn('docker compose -f "$COMPOSE_FILE" images --quiet', content)
        self.assertIn("Configured image unavailable after build", content)
        self.assertIn("No Compose images available for required security scan", content)
        self.assertIn("Upload security evidence", content)

    def test_actionable_image_classification_triggers_rebuild_independent_of_step_outcome(self) -> None:
        for workflow in (
            ".github/workflows/_vps-self-hosted-deploy.yml",
            ".github/workflows/_vps-monorepo-deploy.yml",
        ):
            with self.subTest(workflow=workflow):
                content = read(workflow)
                rebuild_start = content.index("id: security-rebuild")
                rebuild_end = content.index("continue-on-error: true", rebuild_start)
                rebuild_condition = content[rebuild_start:rebuild_end]

                self.assertIn(
                    "steps.security-images-initial-gate.outputs.classification == 'actionable_vulnerability'",
                    rebuild_condition,
                )
                self.assertNotIn(
                    "steps.security-images-initial-gate.outcome == 'failure'",
                    rebuild_condition,
                )

    def test_monorepo_deploy_gates_filesystem_and_final_images_before_rollout(self) -> None:
        content = read(".github/workflows/_vps-monorepo-deploy.yml")

        self.assertNotIn("security_gate_required:", content)
        self.assertNotIn("inputs.security_gate_required", content)
        filesystem = content.index("Security gate (filesystem)")
        sync = content.index("Backup and synchronize files")
        build = content.index("Build required services")
        pull = content.index("Pull declared runtime images")
        discover = content.index("Discover declarative Compose images")
        initial = content.index("Security gate (images, initial)")
        rebuild = content.index("Rebuild actionable image vulnerabilities")
        final = content.index("Security gate (images, remediated)")
        enforce = content.index("Enforce final image security result")
        rollout = content.index("Roll out services")
        self.assertLess(filesystem, sync)
        self.assertLess(build, pull)
        self.assertLess(pull, discover)
        self.assertLess(discover, initial)
        self.assertLess(initial, rebuild)
        self.assertLess(rebuild, final)
        self.assertLess(final, enforce)
        self.assertLess(enforce, rollout)
        self.assertIn("compose_cmd config --images", content)
        self.assertIn("compose_cmd pull --ignore-buildable", content)
        self.assertIn("docker_cmd image inspect", content)
        self.assertIn("No Compose images available for required security scan", content)
        self.assertIn("Upload security evidence", content)


if __name__ == "__main__":
    unittest.main()
