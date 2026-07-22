"""Static policy tests for billing-independent security gates."""

from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


class SecurityGateContractTests(unittest.TestCase):
    def test_composite_action_reports_all_and_blocks_only_actionable_findings(self) -> None:
        content = read(".github/actions/security-gate/action.yml")

        self.assertIn(
            "aquasecurity/setup-trivy@81e514348e19b6112ce2a7e3ecbafe19c1e1f567",
            content,
        )
        self.assertIn('default: "v0.70.0"', content)
        self.assertIn('default: "true"', content)
        self.assertIn("--download-db-only", content)
        self.assertIn("optimizr-security-gate", content)
        self.assertIn("flock -x 9", content)
        self.assertIn("chmod 700", content)
        self.assertIn("validate-db", content)
        self.assertIn("render-exceptions", content)
        self.assertIn("scripts/security_gate/report.py", content)
        self.assertIn("scripts/security_gate/aggregate.py", content)
        self.assertIn("classification:", content)
        self.assertIn("fixable_vulnerability_count:", content)
        self.assertIn("unfixed_vulnerability_count:", content)
        self.assertIn("misconfiguration_count:", content)
        self.assertIn("secret_count:", content)
        self.assertIn("report_args=(", content)
        self.assertIn('blocking_args=("${report_args[@]}" --ignore-unfixed)', content)
        self.assertIn('--format json --exit-code 0 --output "$json_report"', content)
        self.assertIn('--format json --exit-code 1 --output "$blocking_json_report"', content)
        self.assertIn('--report "blocking_json=$blocking_json_report"', content)
        self.assertIn('--report "summary=$finding_summary"', content)
        self.assertIn("vulnerabilities without an available fix remain visible", content)
        self.assertNotIn("ALLOW_MISSING_TRIVY", content)
        self.assertNotIn("continue-on-error: true", content)

    def test_reusable_workflow_runs_same_gate_on_selected_runner(self) -> None:
        content = read(".github/workflows/_security-gate.yml")

        self.assertIn("runs-on: ${{ fromJSON(inputs.runner_json) }}", content)
        self.assertIn('default: \'["ubuntu-latest"]\'', content)
        self.assertIn(
            "uses: optimizr-tech/optimizr-actions/.github/actions/security-gate@v1",
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
        initial = content.index("Security gate (images, initial)")
        rebuild = content.index("Rebuild actionable image vulnerabilities")
        final = content.index("Security gate (images, remediated)")
        enforce = content.index("Enforce final image security result")
        deploy = content.index("Roll out and verify primary container")
        self.assertLess(filesystem, sync)
        self.assertLess(build, initial)
        self.assertLess(initial, rebuild)
        self.assertLess(rebuild, final)
        self.assertLess(final, enforce)
        self.assertLess(enforce, deploy)
        self.assertIn('docker compose -f "$COMPOSE_FILE" config --images', content)
        self.assertIn("docker image inspect", content)
        self.assertNotIn('docker compose -f "$COMPOSE_FILE" images --quiet', content)
        self.assertIn("Configured image unavailable after build", content)
        self.assertIn("No Compose images available for required security scan", content)
        self.assertIn("Upload security evidence", content)

    def test_monorepo_deploy_gates_filesystem_and_final_images_before_rollout(self) -> None:
        content = read(".github/workflows/_vps-monorepo-deploy.yml")

        self.assertNotIn("security_gate_required:", content)
        self.assertNotIn("inputs.security_gate_required", content)
        filesystem = content.index("Security gate (filesystem)")
        sync = content.index("Backup and synchronize files")
        build = content.index("Build required services")
        initial = content.index("Security gate (images, initial)")
        rebuild = content.index("Rebuild actionable image vulnerabilities")
        final = content.index("Security gate (images, remediated)")
        enforce = content.index("Enforce final image security result")
        rollout = content.index("Roll out services")
        self.assertLess(filesystem, sync)
        self.assertLess(build, initial)
        self.assertLess(initial, rebuild)
        self.assertLess(rebuild, final)
        self.assertLess(final, enforce)
        self.assertLess(enforce, rollout)
        self.assertIn('docker compose -f "$COMPOSE_FILE" config --images', content)
        self.assertIn("docker image inspect", content)
        self.assertIn("No Compose images available for required security scan", content)
        self.assertIn("Upload security evidence", content)


if __name__ == "__main__":
    unittest.main()
