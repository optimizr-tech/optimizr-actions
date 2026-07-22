# Security Self-Healing Deploy Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add one bounded automatic image rebuild/remediation retry, safe Dependabot auto-merge, and organization adoption signals without introducing Ogozu or a parallel deployment system.

**Architecture:** The existing Trivy composite remains the source of truth and keeps its current `result=passed|failed` output for `v1` compatibility. It gains additive sanitized classification/count outputs. The two existing VPS deploy reusables capture an initial image-gate failure, retry only an actionable vulnerability once with fixed Compose pull/build commands, rescan new immutable image IDs, and promote only after the final gate succeeds. Repository-source changes continue through Dependabot and GitHub native auto-merge.

**Tech Stack:** GitHub Actions reusable workflows and composite actions, Bash, Python 3 standard library, Docker Compose, Trivy v0.70.0, Dependabot metadata action, GitHub CLI, Python `unittest`, actionlint, PyYAML/yq validation.

## Global Constraints

- Never promote an image with an actionable `HIGH` or `CRITICAL` vulnerability.
- Vulnerabilities without an available fix remain signal-only and stay in complete evidence.
- Retry image remediation at most once.
- Preserve the currently deployed known-good stack when remediation fails.
- Do not add Ogozu, a custom GitHub App, an external queue, AI-written patches, or arbitrary command inputs.
- Do not change existing `security-gate` output `result`; it remains `passed` or `failed` for governed `v1` compatibility.
- Add only optional reusable-workflow inputs with safe defaults.
- Pull-request code must not execute on production-capable self-hosted runners.
- Dependabot auto-merge must only enable GitHub native auto-merge; branch protection remains responsible for required checks.
- All third-party Actions references must use immutable 40-character commit SHAs.
- Publish through governed `v1` only after exact-SHA repository validation succeeds.

---

## File Map

- Modify `.github/actions/security-gate/action.yml`: expose additive classification/count outputs while preserving current exit behavior and `result`.
- Create `scripts/security_gate/aggregate.py`: combine per-target sanitized summaries and write bounded GitHub outputs.
- Create `tests/test_security_gate_aggregate.py`: behavioral coverage for aggregate classification and output writing.
- Modify `tests/test_security_gate_contract.py`: static contracts for new outputs and both deploy retry paths.
- Create `tests/test_security_rebuild_retry_runtime.py`: execute the embedded retry scripts against a fake fixed-argv `sudo` shim.
- Modify `.github/workflows/_vps-self-hosted-deploy.yml`: add one generic Compose pull/build/rescan retry.
- Modify `.github/workflows/_vps-monorepo-deploy.yml`: add the equivalent bounded retry for required/optional service builds.
- Modify `.github/actions/record-deploy-manifest/action.yml`: accept sanitized remediation state.
- Modify `scripts/deploy_manifest/record.py`: pass remediation state into the strict writer.
- Modify `scripts/deploy_manifest/write.py`: validate and persist remediation enums/boolean.
- Modify `tests/test_deploy_manifest_action.py` and `tests/test_deploy_manifest_record.py`: cover the additive evidence schema.
- Create `.github/workflows/_dependabot-security-automerge.yml`: reusable hosted workflow that enables native auto-merge for approved Dependabot update types.
- Create `templates/workflows/dependabot-security-automerge.yml`: explicit consumer caller template.
- Create `tests/test_dependabot_automerge_contract.py`: least-privilege and actor/update-policy contracts.
- Modify `scripts/org_audit/audit.py`: report missing Dependabot configuration/caller without mutating consumers.
- Modify `tests/test_org_audit.py`: behavioral coverage for the new audit rules.
- Modify `docs/SECURITY_GATE.md`: explain the retry state machine and failure behavior.
- Create `docs/DEPENDABOT_SECURITY_AUTOMERGE.md`: adoption, permissions, branch-protection prerequisites, and rollback.
- Modify `docs/ORG_ADOPTION_AUDIT.md`: document the new source-backed signals.
- Modify `README.md`: link the new contracts.

---

### Task 1: Aggregate Sanitized Security-Gate Classifications

**Files:**
- Create: `scripts/security_gate/aggregate.py`
- Create: `tests/test_security_gate_aggregate.py`

**Interfaces:**
- Consumes: schema-version-1 JSON summaries emitted by `scripts/security_gate/report.py`.
- Produces: `aggregate_summaries(paths: Sequence[Path]) -> dict[str, Any]`.
- Produces GitHub outputs: `classification`, `fixable_vulnerability_count`, `unfixed_vulnerability_count`, `misconfiguration_count`, and `secret_count`.
- Classification precedence: `gate_error` > `actionable_vulnerability` > `unfixed_warning` > `clean`.

- [ ] **Step 1: Write failing aggregate tests**

Create `tests/test_security_gate_aggregate.py`:

```python
from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from scripts.security_gate.aggregate import (
    AggregateError,
    aggregate_summaries,
    main,
)


class SecurityGateAggregateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def _summary(
        self,
        name: str,
        *,
        fixable: int = 0,
        unfixed: int = 0,
        misconfigurations: int = 0,
        secrets: int = 0,
    ) -> Path:
        path = self.root / name
        path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "vulnerabilities": {
                        "total": fixable + unfixed,
                        "fixable": fixable,
                        "unfixed": unfixed,
                        "by_severity": {},
                    },
                    "misconfigurations": misconfigurations,
                    "secrets": secrets,
                }
            ),
            encoding="utf-8",
        )
        return path

    def test_aggregates_counts_and_classifies_actionable_vulnerabilities(self) -> None:
        aggregate = aggregate_summaries(
            [
                self._summary("one.json", fixable=2, unfixed=3),
                self._summary("two.json", unfixed=4),
            ]
        )

        self.assertEqual("actionable_vulnerability", aggregate["classification"])
        self.assertEqual(2, aggregate["fixable_vulnerability_count"])
        self.assertEqual(7, aggregate["unfixed_vulnerability_count"])
        self.assertEqual(0, aggregate["misconfiguration_count"])
        self.assertEqual(0, aggregate["secret_count"])

    def test_non_rebuildable_findings_classify_as_gate_error(self) -> None:
        aggregate = aggregate_summaries(
            [self._summary("summary.json", fixable=1, misconfigurations=1)]
        )
        self.assertEqual("gate_error", aggregate["classification"])

    def test_only_unfixed_findings_are_signal_only(self) -> None:
        aggregate = aggregate_summaries(
            [self._summary("summary.json", unfixed=5)]
        )
        self.assertEqual("unfixed_warning", aggregate["classification"])

    def test_cli_writes_github_outputs(self) -> None:
        summary = self._summary("summary.json", fixable=1, unfixed=2)
        output = self.root / "github-output.txt"

        code = main(
            [
                "--summary",
                str(summary),
                "--github-output",
                str(output),
            ]
        )

        self.assertEqual(0, code)
        values = dict(
            line.split("=", 1)
            for line in output.read_text(encoding="utf-8").splitlines()
        )
        self.assertEqual("actionable_vulnerability", values["classification"])
        self.assertEqual("1", values["fixable_vulnerability_count"])
        self.assertEqual("2", values["unfixed_vulnerability_count"])

    def test_rejects_missing_or_malformed_summaries(self) -> None:
        with self.assertRaisesRegex(AggregateError, "at least one"):
            aggregate_summaries([])

        malformed = self.root / "malformed.json"
        malformed.write_text('{"schema_version": 2}', encoding="utf-8")
        with self.assertRaisesRegex(AggregateError, "schema version"):
            aggregate_summaries([malformed])


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run the new tests and verify RED**

Run:

```bash
python3 -m unittest tests.test_security_gate_aggregate -v
```

Expected: import failure because `scripts.security_gate.aggregate` does not exist.

- [ ] **Step 3: Implement the bounded aggregate helper**

Create `scripts/security_gate/aggregate.py`:

```python
"""Aggregate sanitized Trivy summaries into GitHub Action outputs."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any, Mapping, Sequence


class AggregateError(ValueError):
    """Raised when sanitized security summaries violate the contract."""


def _non_negative_int(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise AggregateError(f"{field} must be a non-negative integer")
    return value


def _load_summary(path: Path) -> Mapping[str, Any]:
    if not path.is_file() or path.is_symlink():
        raise AggregateError("summary must be a regular non-symlink file")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AggregateError("summary must be valid UTF-8 JSON") from exc
    if not isinstance(payload, Mapping):
        raise AggregateError("summary must be a JSON object")
    if payload.get("schema_version") != 1:
        raise AggregateError("unsupported summary schema version")
    return payload


def aggregate_summaries(paths: Sequence[Path]) -> dict[str, Any]:
    if not paths:
        raise AggregateError("at least one summary is required")

    totals = {
        "fixable_vulnerability_count": 0,
        "unfixed_vulnerability_count": 0,
        "misconfiguration_count": 0,
        "secret_count": 0,
    }
    for path in paths:
        payload = _load_summary(path)
        vulnerabilities = payload.get("vulnerabilities")
        if not isinstance(vulnerabilities, Mapping):
            raise AggregateError("vulnerabilities must be an object")
        totals["fixable_vulnerability_count"] += _non_negative_int(
            vulnerabilities.get("fixable"), "vulnerabilities.fixable"
        )
        totals["unfixed_vulnerability_count"] += _non_negative_int(
            vulnerabilities.get("unfixed"), "vulnerabilities.unfixed"
        )
        totals["misconfiguration_count"] += _non_negative_int(
            payload.get("misconfigurations"), "misconfigurations"
        )
        totals["secret_count"] += _non_negative_int(
            payload.get("secrets"), "secrets"
        )

    if totals["misconfiguration_count"] or totals["secret_count"]:
        classification = "gate_error"
    elif totals["fixable_vulnerability_count"]:
        classification = "actionable_vulnerability"
    elif totals["unfixed_vulnerability_count"]:
        classification = "unfixed_warning"
    else:
        classification = "clean"

    return {"classification": classification, **totals}


def _write_github_output(path: Path, aggregate: Mapping[str, Any]) -> None:
    if path.is_symlink():
        raise AggregateError("GitHub output must not be a symlink")
    with path.open("a", encoding="utf-8") as handle:
        for key in (
            "classification",
            "fixable_vulnerability_count",
            "unfixed_vulnerability_count",
            "misconfiguration_count",
            "secret_count",
        ):
            handle.write(f"{key}={aggregate[key]}\n")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--summary", action="append", type=Path, required=True)
    parser.add_argument("--github-output", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        aggregate = aggregate_summaries(args.summary)
        _write_github_output(args.github_output, aggregate)
        return 0
    except (AggregateError, OSError, KeyError) as exc:
        print(f"security summary aggregate error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 4: Run focused tests and Python compilation**

Run:

```bash
python3 -m unittest tests.test_security_gate_aggregate -v
python3 -m compileall -q scripts/security_gate tests/test_security_gate_aggregate.py
```

Expected: 5 tests pass and compilation exits `0`.

- [ ] **Step 5: Commit the aggregate helper**

```bash
git add scripts/security_gate/aggregate.py tests/test_security_gate_aggregate.py
git commit -m "feat(security): aggregate gate classifications"
```

---

### Task 2: Expose Backward-Compatible Security-Gate Outputs

**Files:**
- Modify: `.github/actions/security-gate/action.yml:44-50,73-79,149-163,281-316`
- Modify: `tests/test_security_gate_contract.py:18-44`
- Test: `tests/test_security_gate_aggregate.py`

**Interfaces:**
- Consumes: `scripts/security_gate/aggregate.py`.
- Preserves: `result=passed|failed`.
- Produces additive outputs: `classification`, `fixable_vulnerability_count`, `unfixed_vulnerability_count`, `misconfiguration_count`, and `secret_count`.

- [ ] **Step 1: Extend the static contract test first**

Add these assertions inside `test_composite_action_reports_all_and_blocks_only_actionable_findings` in `tests/test_security_gate_contract.py`:

```python
        self.assertIn("scripts/security_gate/aggregate.py", content)
        self.assertIn("classification:", content)
        self.assertIn("fixable_vulnerability_count:", content)
        self.assertIn("unfixed_vulnerability_count:", content)
        self.assertIn("misconfiguration_count:", content)
        self.assertIn("secret_count:", content)
        self.assertIn('echo "classification=gate_error"', content)
        self.assertIn('--summary "$finding_summary"', content)
        self.assertIn('--github-output "$GITHUB_OUTPUT"', content)
        self.assertIn('echo "result=passed"', content)
        self.assertIn('echo "result=failed"', content)
```

- [ ] **Step 2: Run the focused contract and verify RED**

Run:

```bash
python3 -m unittest \
  tests.test_security_gate_contract.SecurityGateContractTests.test_composite_action_reports_all_and_blocks_only_actionable_findings \
  -v
```

Expected: failure because the new outputs and aggregate invocation are absent.

- [ ] **Step 3: Add composite output declarations**

Extend `.github/actions/security-gate/action.yml` under `outputs` without changing the existing outputs:

```yaml
  classification:
    description: "clean, actionable_vulnerability, unfixed_warning, or gate_error"
    value: ${{ steps.scan.outputs.classification }}
  fixable_vulnerability_count:
    description: "Actionable vulnerabilities with an available fixed version"
    value: ${{ steps.scan.outputs.fixable_vulnerability_count }}
  unfixed_vulnerability_count:
    description: "Signal-only vulnerabilities without an available fixed version"
    value: ${{ steps.scan.outputs.unfixed_vulnerability_count }}
  misconfiguration_count:
    description: "Blocking Trivy misconfiguration findings"
    value: ${{ steps.scan.outputs.misconfiguration_count }}
  secret_count:
    description: "Blocking Trivy secret findings"
    value: ${{ steps.scan.outputs.secret_count }}
```

- [ ] **Step 4: Initialize safe failure outputs before operational work**

Immediately after defining `report_tool`, add the aggregate helper and default outputs:

```bash
        aggregate_tool="$action_root/scripts/security_gate/aggregate.py"
        {
          echo "classification=gate_error"
          echo "fixable_vulnerability_count=0"
          echo "unfixed_vulnerability_count=0"
          echo "misconfiguration_count=0"
          echo "secret_count=0"
        } >> "$GITHUB_OUTPUT"
```

The default remains `gate_error` when setup, database, evidence, or report processing fails before classification completes.

- [ ] **Step 5: Collect summary paths and write final aggregate outputs**

Before the target loop, initialize:

```bash
        finding_summaries=()
```

After `python3 "$report_tool" "${summary_args[@]}"`, append:

```bash
          finding_summaries+=("$finding_summary")
```

Before writing the existing `result` output, invoke the aggregate helper:

```bash
        aggregate_args=(--github-output "$GITHUB_OUTPUT")
        for finding_summary in "${finding_summaries[@]}"; do
          aggregate_args+=(--summary "$finding_summary")
        done
        python3 "$aggregate_tool" "${aggregate_args[@]}"
```

Keep the existing block unchanged:

```bash
        if [ "$aggregate_status" -eq 0 ]; then
          echo "result=passed" >> "$GITHUB_OUTPUT"
        else
          echo "result=failed" >> "$GITHUB_OUTPUT"
        fi
        exit "$aggregate_status"
```

- [ ] **Step 6: Run focused and full security-gate tests**

Run:

```bash
python3 -m unittest \
  tests.test_security_gate_report \
  tests.test_security_gate_aggregate \
  tests.test_security_gate_contract \
  -v
python3 -m compileall -q scripts/security_gate tests
```

Expected: all focused tests pass and compilation exits `0`.

- [ ] **Step 7: Validate composite metadata and embedded Bash**

Run:

```bash
python3 - <<'PY'
from pathlib import Path
import yaml

payload = yaml.safe_load(
    Path(".github/actions/security-gate/action.yml").read_text(encoding="utf-8")
)
assert payload["outputs"]["result"]["value"] == "${{ steps.scan.outputs.result }}"
assert payload["outputs"]["classification"]["value"] == "${{ steps.scan.outputs.classification }}"
print("security-gate YAML: PASS")
PY

python3 - <<'PY'
from pathlib import Path
import subprocess
import tempfile
import yaml

payload = yaml.safe_load(
    Path(".github/actions/security-gate/action.yml").read_text(encoding="utf-8")
)
script = payload["runs"]["steps"][1]["run"]
with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False) as handle:
    handle.write(script)
    path = handle.name
subprocess.run(["bash", "-n", path], check=True)
print("security-gate Bash: PASS")
PY
```

Expected: both commands print `PASS`.

- [ ] **Step 8: Commit additive outputs**

```bash
git add .github/actions/security-gate/action.yml tests/test_security_gate_contract.py
git commit -m "feat(security): expose remediation classifications"
```

---

### Task 3: Add One Bounded Retry to the Generic VPS Deploy

**Files:**
- Modify: `.github/workflows/_vps-self-hosted-deploy.yml:70-114,204-258`
- Modify: `tests/test_security_gate_contract.py:62-83`

**Interfaces:**
- Consumes: `steps.security-images-initial.outputs.classification`.
- Adds optional inputs:
  - `security_rebuild_retry_enabled: boolean = true`
  - `security_rebuild_retry_no_cache: boolean = true`
- Produces no new caller-required inputs.
- Final promotion condition: initial image gate succeeds, or retry image gate succeeds after an actionable-only failure.

- [ ] **Step 1: Write failing generic retry contracts**

Extend `test_single_service_deploy_gates_filesystem_and_image_before_rollout`:

```python
        self.assertIn("security_rebuild_retry_enabled:", content)
        self.assertIn("security_rebuild_retry_no_cache:", content)
        self.assertIn("id: security-images-initial", content)
        self.assertIn("id: security-gate-images-initial", content)
        self.assertIn("continue-on-error: true", content)
        self.assertIn("Retry actionable image remediation", content)
        self.assertIn('pull --ignore-buildable', content)
        self.assertIn('build --pull --no-cache', content)
        self.assertIn("id: security-images-retry", content)
        self.assertIn("id: security-gate-images-retry", content)
        self.assertIn("Enforce final image security result", content)
        self.assertIn("actionable_vulnerability", content)
        self.assertIn("retry occurs at most once", content)
```

Also assert ordering:

```python
        initial_gate = content.index("Security gate (images, initial)")
        retry = content.index("Retry actionable image remediation")
        retry_gate = content.index("Security gate (images, retry)")
        enforce = content.index("Enforce final image security result")
        self.assertLess(initial_gate, retry)
        self.assertLess(retry, retry_gate)
        self.assertLess(retry_gate, enforce)
        self.assertLess(enforce, deploy)
```

Create `tests/test_security_rebuild_retry_runtime.py` with a fake `sudo` shim that records fixed argv without invoking Docker:

```python
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[1]


def extract_run_script(path: str, step_name: str) -> str:
    lines = (ROOT / path).read_text(encoding="utf-8").splitlines()
    name_index = next(
        index
        for index, line in enumerate(lines)
        if line.strip() == f"- name: {step_name}"
    )
    run_index = next(
        index
        for index in range(name_index + 1, len(lines))
        if lines[index].strip() == "run: |"
    )
    run_indent = len(lines[run_index]) - len(lines[run_index].lstrip())
    selected: list[str] = []
    for line in lines[run_index + 1 :]:
        if line.strip():
            indent = len(line) - len(line.lstrip())
            if indent <= run_indent:
                break
        selected.append(line)
    return textwrap.dedent("\n".join(selected))


def run_retry_script(script: str) -> list[str]:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        fake_bin = root / "bin"
        fake_bin.mkdir()
        deploy_path = root / "deploy"
        deploy_path.mkdir()
        log_path = root / "sudo.log"
        sudo = fake_bin / "sudo"
        sudo.write_text(
            "#!/usr/bin/env bash\n"
            'printf "%s\\n" "$*" >> "$FAKE_DOCKER_LOG"\n'
            "exit 0\n",
            encoding="utf-8",
        )
        sudo.chmod(0o755)
        environment = os.environ.copy()
        environment.update(
            {
                "PATH": f"{fake_bin}:{environment['PATH']}",
                "FAKE_DOCKER_LOG": str(log_path),
                "DEPLOY_PATH": str(deploy_path),
                "COMPOSE_FILE": "docker-compose.yml",
            }
        )
        subprocess.run(
            ["bash", "-c", script],
            check=True,
            cwd=ROOT,
            env=environment,
        )
        return log_path.read_text(encoding="utf-8").splitlines()


class SecurityRebuildRetryRuntimeTests(unittest.TestCase):
    def test_generic_retry_uses_one_pull_and_one_fixed_build(self) -> None:
        script = extract_run_script(
            ".github/workflows/_vps-self-hosted-deploy.yml",
            "Retry actionable image remediation",
        )
        script = script.replace(
            "${{ inputs.build_image }}",
            "true",
        ).replace(
            "${{ inputs.security_rebuild_retry_no_cache }}",
            "true",
        )

        calls = run_retry_script(script)

        self.assertEqual(
            1,
            calls.count(
                "docker compose -f docker-compose.yml pull --ignore-buildable"
            ),
        )
        self.assertEqual(
            1,
            calls.count(
                "docker compose -f docker-compose.yml build --pull --no-cache"
            ),
        )


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run the generic deploy contracts and verify RED**

Run:

```bash
python3 -m unittest \
  tests.test_security_gate_contract.SecurityGateContractTests.test_single_service_deploy_gates_filesystem_and_image_before_rollout \
  tests.test_security_rebuild_retry_runtime.SecurityRebuildRetryRuntimeTests.test_generic_retry_uses_one_pull_and_one_fixed_build \
  -v
```

Expected: failures because the retry inputs/step and embedded runtime script are absent.

- [ ] **Step 3: Add optional retry inputs**

Add after `security_db_max_age_hours`:

```yaml
      security_rebuild_retry_enabled:
        description: Retry actionable image vulnerabilities once after pulling fresh image inputs
        required: false
        type: boolean
        default: true
      security_rebuild_retry_no_cache:
        description: Disable Docker build cache during the single security remediation retry
        required: false
        type: boolean
        default: true
```

- [ ] **Step 4: Rename the initial discovery and gate step IDs**

Change the current discovery step to:

```yaml
      - name: Discover declarative Compose images (initial)
        id: security-images-initial
```

Change the current image gate to:

```yaml
      - name: Security gate (images, initial)
        id: security-gate-images-initial
        if: inputs.security_require_image_scan
        continue-on-error: true
        uses: optimizr-tech/optimizr-actions/.github/actions/security-gate@v1
        with:
          scan_type: image
          image_refs: ${{ steps.security-images-initial.outputs.refs }}
          severity: ${{ inputs.security_severity }}
          ignore_unfixed: ${{ inputs.security_ignore_unfixed }}
          exceptions_file: ${{ inputs.security_exceptions_file }}
          trivy_version: ${{ inputs.security_trivy_version }}
          db_max_age_hours: ${{ inputs.security_db_max_age_hours }}
          evidence_dir: artifacts/security-gate/initial
```

- [ ] **Step 5: Add the single fixed-command remediation retry**

Insert after the initial image gate:

```yaml
      # The retry occurs at most once. It never edits source or lockfiles.
      - name: Retry actionable image remediation
        id: security-rebuild-retry
        if: >-
          inputs.security_require_image_scan &&
          inputs.security_rebuild_retry_enabled &&
          steps.security-gate-images-initial.outcome == 'failure' &&
          steps.security-gate-images-initial.outputs.classification == 'actionable_vulnerability'
        shell: bash
        run: |
          set -euo pipefail
          cd "$DEPLOY_PATH"
          sudo docker compose -f "$COMPOSE_FILE" pull --ignore-buildable
          if [ "${{ inputs.build_image }}" = true ]; then
            build_args=(--pull)
            if [ "${{ inputs.security_rebuild_retry_no_cache }}" = true ]; then
              build_args+=(--no-cache)
            fi
            sudo docker compose -f "$COMPOSE_FILE" build "${build_args[@]}"
          fi
```

- [ ] **Step 6: Rediscover immutable image IDs after retry**

Duplicate the existing fixed discovery logic under:

```yaml
      - name: Discover declarative Compose images (retry)
        id: security-images-retry
        if: steps.security-rebuild-retry.outcome == 'success'
        shell: bash
        run: |
          set -euo pipefail
          cd "$DEPLOY_PATH"
          mapfile -t configured_images < <(
            sudo docker compose -f "$COMPOSE_FILE" config --images | sed '/^$/d' | sort -u
          )
          [ "${#configured_images[@]}" -gt 0 ] || {
            echo "::error::No Compose images available for required security rescan" >&2
            exit 1
          }
          image_ids=()
          for image_ref in "${configured_images[@]}"; do
            image_id="$(sudo docker image inspect --format '{{.Id}}' "$image_ref" 2>/dev/null || true)"
            [ -n "$image_id" ] || {
              echo "::error::Configured image unavailable after remediation rebuild: $image_ref" >&2
              exit 1
            }
            image_ids+=("$image_id")
          done
          mapfile -t image_ids < <(printf '%s\n' "${image_ids[@]}" | sort -u)
          {
            echo 'refs<<OPTIMIZR_IMAGES'
            printf '%s\n' "${image_ids[@]}"
            echo OPTIMIZR_IMAGES
          } >> "$GITHUB_OUTPUT"
```

- [ ] **Step 7: Rescan and enforce one final result**

Add:

```yaml
      - name: Security gate (images, retry)
        id: security-gate-images-retry
        if: steps.security-images-retry.outcome == 'success'
        continue-on-error: true
        uses: optimizr-tech/optimizr-actions/.github/actions/security-gate@v1
        with:
          scan_type: image
          image_refs: ${{ steps.security-images-retry.outputs.refs }}
          severity: ${{ inputs.security_severity }}
          ignore_unfixed: ${{ inputs.security_ignore_unfixed }}
          exceptions_file: ${{ inputs.security_exceptions_file }}
          trivy_version: ${{ inputs.security_trivy_version }}
          db_max_age_hours: ${{ inputs.security_db_max_age_hours }}
          evidence_dir: artifacts/security-gate/retry

      - name: Enforce final image security result
        if: always() && inputs.security_require_image_scan
        shell: bash
        env:
          INITIAL_OUTCOME: ${{ steps.security-gate-images-initial.outcome }}
          INITIAL_CLASSIFICATION: ${{ steps.security-gate-images-initial.outputs.classification }}
          RETRY_OUTCOME: ${{ steps.security-gate-images-retry.outcome }}
        run: |
          set -euo pipefail
          if [ "$INITIAL_OUTCOME" = success ]; then
            exit 0
          fi
          if [ "$INITIAL_CLASSIFICATION" != actionable_vulnerability ]; then
            echo "::error::Initial image security failure is not rebuild-remediable" >&2
            exit 1
          fi
          if [ "${{ inputs.security_rebuild_retry_enabled }}" != true ]; then
            echo "::error::Actionable image vulnerabilities remain and retry is disabled" >&2
            exit 1
          fi
          if [ "$RETRY_OUTCOME" != success ]; then
            echo "::error::Image security remediation retry did not produce a clean candidate" >&2
            exit 1
          fi
```

The existing pre-deploy validation and rollout steps remain after this enforcement step, so a final failure makes them unreachable.

- [ ] **Step 8: Run focused contracts and syntax validation**

Run:

```bash
python3 -m unittest tests.test_security_gate_contract -v
python3 - <<'PY'
from pathlib import Path
import yaml
yaml.safe_load(Path(".github/workflows/_vps-self-hosted-deploy.yml").read_text())
print("generic deploy YAML: PASS")
PY
docker run --rm \
  -v "$PWD:/repo" \
  -w /repo \
  rhysd/actionlint@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667 \
  .github/workflows/_vps-self-hosted-deploy.yml
```

Expected: tests pass, YAML prints `PASS`, and actionlint exits `0`.

- [ ] **Step 9: Commit the generic retry**

```bash
git add \
  .github/workflows/_vps-self-hosted-deploy.yml \
  tests/test_security_gate_contract.py \
  tests/test_security_rebuild_retry_runtime.py
git commit -m "feat(deploy): retry actionable image remediation"
```

---

### Task 4: Apply the Same Bounded Retry to the Monorepo Deploy

**Files:**
- Modify: `.github/workflows/_vps-monorepo-deploy.yml:89-133,230-302`
- Modify: `tests/test_security_gate_contract.py:84-100`

**Interfaces:**
- Consumes the same `classification` output.
- Mirrors required service builds with `--pull` and optional service warning semantics.
- Does not add a second retry or alter existing `services_up` selection.

- [ ] **Step 1: Write failing monorepo retry contracts**

Extend `test_monorepo_deploy_gates_filesystem_and_images_before_rollout`:

```python
        self.assertIn("security_rebuild_retry_enabled:", content)
        self.assertIn("security_rebuild_retry_no_cache:", content)
        self.assertIn("id: security-gate-images-initial", content)
        self.assertIn("Retry actionable monorepo image remediation", content)
        self.assertIn('pull --ignore-buildable', content)
        self.assertIn('build_args=(--pull)', content)
        self.assertIn('for service in ${{ inputs.services_build }}', content)
        self.assertIn('for service in ${{ inputs.services_build_optional }}', content)
        self.assertIn("Security gate (images, retry)", content)
        self.assertIn("Enforce final image security result", content)
        self.assertIn("retry occurs at most once", content)
```

Add ordering assertions equivalent to Task 3.

Extend `SecurityRebuildRetryRuntimeTests` in
`tests/test_security_rebuild_retry_runtime.py`:

```python
    def test_monorepo_retry_preserves_required_and_optional_build_scopes(self) -> None:
        script = extract_run_script(
            ".github/workflows/_vps-monorepo-deploy.yml",
            "Retry actionable monorepo image remediation",
        )
        script = (
            script.replace(
                "${{ inputs.security_rebuild_retry_no_cache }}",
                "true",
            )
            .replace("${{ inputs.services_build }}", "api worker")
            .replace("${{ inputs.services_build_optional }}", "admin")
        )

        calls = run_retry_script(script)

        self.assertEqual(
            1,
            calls.count(
                "docker compose -f docker-compose.yml pull --ignore-buildable"
            ),
        )
        self.assertIn(
            "docker compose -f docker-compose.yml build --pull --no-cache api",
            calls,
        )
        self.assertIn(
            "docker compose -f docker-compose.yml build --pull --no-cache worker",
            calls,
        )
        self.assertIn(
            "docker compose -f docker-compose.yml build --pull --no-cache admin",
            calls,
        )
        self.assertEqual(
            3,
            sum(" build --pull --no-cache " in call for call in calls),
        )
```

- [ ] **Step 2: Run the monorepo contracts and verify RED**

Run:

```bash
python3 -m unittest \
  tests.test_security_gate_contract.SecurityGateContractTests.test_monorepo_deploy_gates_filesystem_and_images_before_rollout \
  tests.test_security_rebuild_retry_runtime.SecurityRebuildRetryRuntimeTests.test_monorepo_retry_preserves_required_and_optional_build_scopes \
  -v
```

Expected: failures because the monorepo retry inputs/step and runtime command contract are absent.

- [ ] **Step 3: Add the same optional inputs and initial gate capture**

Add the two inputs from Task 3 after `security_db_max_age_hours`.

Rename the existing discovery/gate IDs to `security-images-initial` and `security-gate-images-initial`, add `continue-on-error: true`, use `artifacts/security-gate/initial`, and reference `steps.security-images-initial.outputs.refs`.

- [ ] **Step 4: Add monorepo pull/build retry with existing service scopes**

Insert:

```yaml
      # The retry occurs at most once and preserves existing optional-build warnings.
      - name: Retry actionable monorepo image remediation
        id: security-rebuild-retry
        if: >-
          inputs.security_require_image_scan &&
          inputs.security_rebuild_retry_enabled &&
          steps.security-gate-images-initial.outcome == 'failure' &&
          steps.security-gate-images-initial.outputs.classification == 'actionable_vulnerability'
        shell: bash
        run: |
          set -euo pipefail
          cd "$DEPLOY_PATH"
          sudo docker compose -f "$COMPOSE_FILE" pull --ignore-buildable
          build_args=(--pull)
          if [ "${{ inputs.security_rebuild_retry_no_cache }}" = true ]; then
            build_args+=(--no-cache)
          fi
          for service in ${{ inputs.services_build }}; do
            sudo docker compose -f "$COMPOSE_FILE" build "${build_args[@]}" "$service"
          done
          for service in ${{ inputs.services_build_optional }}; do
            if ! sudo docker compose -f "$COMPOSE_FILE" build "${build_args[@]}" "$service"; then
              echo "::warning title=${service} remediation build failed::Keeping previous image"
            fi
          done
```

- [ ] **Step 5: Add retry discovery, rescan, and final enforcement**

Use the exact retry discovery and image-gate blocks from Task 3, with the same IDs and `artifacts/security-gate/retry`. Add the same `Enforce final image security result` block before `Roll out services`.

- [ ] **Step 6: Run focused contracts and actionlint**

Run:

```bash
python3 -m unittest tests.test_security_gate_contract -v
python3 - <<'PY'
from pathlib import Path
import yaml
yaml.safe_load(Path(".github/workflows/_vps-monorepo-deploy.yml").read_text())
print("monorepo deploy YAML: PASS")
PY
docker run --rm \
  -v "$PWD:/repo" \
  -w /repo \
  rhysd/actionlint@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667 \
  .github/workflows/_vps-monorepo-deploy.yml
```

Expected: tests pass, YAML prints `PASS`, and actionlint exits `0`.

- [ ] **Step 7: Commit the monorepo retry**

```bash
git add \
  .github/workflows/_vps-monorepo-deploy.yml \
  tests/test_security_gate_contract.py \
  tests/test_security_rebuild_retry_runtime.py
git commit -m "feat(deploy): retry monorepo image remediation"
```

---

### Task 5: Add Minimal Dependabot Native Auto-Merge

**Files:**
- Create: `.github/workflows/_dependabot-security-automerge.yml`
- Create: `templates/workflows/dependabot-security-automerge.yml`
- Create: `tests/test_dependabot_automerge_contract.py`

**Interfaces:**
- Reusable input: `allow_minor: boolean = false`.
- Accepts only `pull_request` events authored by `dependabot[bot]`.
- Allows `version-update:semver-patch`; allows `version-update:semver-minor` only when `allow_minor=true`.
- Enables `gh pr merge --auto --merge`; it never executes checked-out PR code.
- Requires caller/repository branch protection to enforce status checks.

- [ ] **Step 1: Write failing reusable/caller contracts**

Create `tests/test_dependabot_automerge_contract.py`:

```python
from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


class DependabotAutomergeContractTests(unittest.TestCase):
    def test_reusable_only_enables_native_automerge_for_dependabot(self) -> None:
        content = read(".github/workflows/_dependabot-security-automerge.yml")

        self.assertIn("workflow_call:", content)
        self.assertIn("allow_minor:", content)
        self.assertIn("default: false", content)
        self.assertIn("contents: write", content)
        self.assertIn("pull-requests: write", content)
        self.assertIn("github.event.pull_request.user.login == 'dependabot[bot]'", content)
        self.assertIn(
            "dependabot/fetch-metadata@d7267f607e9d3fb96fc2fbe83e0af444713e90b7",
            content,
        )
        self.assertIn("version-update:semver-patch", content)
        self.assertIn("version-update:semver-minor", content)
        self.assertIn('gh pr merge --auto --merge "$PR_URL"', content)
        self.assertNotIn("actions/checkout@", content)
        self.assertNotIn("pull_request_target", content)
        self.assertNotIn("secrets: inherit", content)
        self.assertNotIn("runs-on: self-hosted", content)

    def test_consumer_template_is_an_explicit_thin_caller(self) -> None:
        content = read("templates/workflows/dependabot-security-automerge.yml")

        self.assertIn("pull_request:", content)
        self.assertIn("types: [opened, synchronize, reopened]", content)
        self.assertIn("contents: write", content)
        self.assertIn("pull-requests: write", content)
        self.assertIn(
            "uses: optimizr-tech/optimizr-actions/.github/workflows/"
            "_dependabot-security-automerge.yml@v1",
            content,
        )
        self.assertIn("allow_minor: false", content)
        self.assertNotIn("secrets: inherit", content)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run the tests and verify RED**

Run:

```bash
python3 -m unittest tests.test_dependabot_automerge_contract -v
```

Expected: file-not-found failures for the reusable and template.

- [ ] **Step 3: Create the reusable workflow**

Create `.github/workflows/_dependabot-security-automerge.yml`:

```yaml
name: _dependabot-security-automerge

on:
  workflow_call:
    inputs:
      allow_minor:
        description: Allow Dependabot semver-minor updates in addition to patches
        required: false
        type: boolean
        default: false

permissions:
  contents: write
  pull-requests: write

jobs:
  enable-automerge:
    name: Enable Dependabot native auto-merge
    if: >-
      github.event_name == 'pull_request' &&
      github.event.pull_request.user.login == 'dependabot[bot]'
    runs-on: ubuntu-latest
    timeout-minutes: 5
    steps:
      - name: Read Dependabot metadata
        id: metadata
        uses: dependabot/fetch-metadata@d7267f607e9d3fb96fc2fbe83e0af444713e90b7
        with:
          github-token: ${{ github.token }}

      - name: Evaluate approved update type
        id: policy
        shell: bash
        env:
          UPDATE_TYPE: ${{ steps.metadata.outputs.update-type }}
          ALLOW_MINOR: ${{ inputs.allow_minor }}
        run: |
          set -euo pipefail
          eligible=false
          case "$UPDATE_TYPE" in
            version-update:semver-patch)
              eligible=true
              ;;
            version-update:semver-minor)
              if [ "$ALLOW_MINOR" = true ]; then
                eligible=true
              else
                echo "::notice::Dependabot minor update remains open for review"
              fi
              ;;
            *)
              echo "::notice::Dependabot update type remains open for review: $UPDATE_TYPE"
              ;;
          esac
          echo "eligible=$eligible" >> "$GITHUB_OUTPUT"

      - name: Enable GitHub native auto-merge
        if: steps.policy.outputs.eligible == 'true'
        env:
          GH_TOKEN: ${{ github.token }}
          PR_URL: ${{ github.event.pull_request.html_url }}
        run: gh pr merge --auto --merge "$PR_URL"
```

Unsupported update types complete successfully without enabling auto-merge. The repository's normal CI/security checks remain the merge requirements for eligible pull requests.

- [ ] **Step 4: Create the thin consumer template**

Create `templates/workflows/dependabot-security-automerge.yml`:

```yaml
name: Dependabot security auto-merge

on:
  pull_request:
    types: [opened, synchronize, reopened]

permissions:
  contents: write
  pull-requests: write

jobs:
  dependabot-automerge:
    if: github.event.pull_request.user.login == 'dependabot[bot]'
    uses: optimizr-tech/optimizr-actions/.github/workflows/_dependabot-security-automerge.yml@v1
    with:
      allow_minor: false
```

- [ ] **Step 5: Run focused tests, YAML parsing, and actionlint**

Run:

```bash
python3 -m unittest tests.test_dependabot_automerge_contract -v
python3 - <<'PY'
from pathlib import Path
import yaml
for path in (
    ".github/workflows/_dependabot-security-automerge.yml",
    "templates/workflows/dependabot-security-automerge.yml",
):
    yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    print(f"{path}: PASS")
PY
docker run --rm \
  -v "$PWD:/repo" \
  -w /repo \
  rhysd/actionlint@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667 \
  .github/workflows/_dependabot-security-automerge.yml
```

Expected: 2 tests pass, both YAML files parse, and actionlint exits `0`.

- [ ] **Step 6: Commit the minimal auto-merge contract**

```bash
git add \
  .github/workflows/_dependabot-security-automerge.yml \
  templates/workflows/dependabot-security-automerge.yml \
  tests/test_dependabot_automerge_contract.py
git commit -m "feat(security): add Dependabot native automerge"
```

---

### Task 6: Record Sanitized Remediation Evidence in Deploy Manifests

**Files:**
- Modify: `.github/actions/record-deploy-manifest/action.yml`
- Modify: `scripts/deploy_manifest/record.py:145-196`
- Modify: `scripts/deploy_manifest/write.py:31-60,171-229,281-328`
- Modify: `.github/workflows/_vps-self-hosted-deploy.yml:338-end`
- Modify: `.github/workflows/_vps-monorepo-deploy.yml:385-end`
- Modify: `tests/test_deploy_manifest_action.py:62-69`
- Modify: `tests/test_deploy_manifest_record.py:75-101`

**Interfaces:**
- Adds only sanitized enum/boolean fields:
  - `security_initial_classification`
  - `security_rebuild_attempted`
  - `security_rebuild_classification`
  - `security_final_classification`
- Allowed classifications: `clean`, `actionable_vulnerability`, `unfixed_warning`, `gate_error`, `not-reported`.
- No CVE IDs, package names, host paths, report bodies, or source snippets enter deploy manifests.

- [ ] **Step 1: Write failing manifest evidence tests**

Extend `test_recorder_collects_through_one_canonical_python_entrypoint` in `tests/test_deploy_manifest_action.py`:

```python
        self.assertIn("security_initial_classification:", content)
        self.assertIn("security_rebuild_attempted:", content)
        self.assertIn("security_rebuild_classification:", content)
        self.assertIn("security_final_classification:", content)
```

Add to `tests/test_deploy_manifest_record.py`:

```python
    def test_records_sanitized_security_remediation_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            deploy_path = Path(temporary)
            result = write_manifest(
                ManifestConfig(
                    deploy_path=deploy_path,
                    status="success",
                    repository="optimizr-tech/example",
                    deployed_sha="b" * 40,
                    deployed_ref="refs/heads/main",
                    environment="production",
                    workflow="Deploy",
                    run_id="2",
                    actor="bot",
                    runner_name="runner",
                    services=["api"],
                    images=[],
                    healthchecks=[],
                    security_initial_classification="actionable_vulnerability",
                    security_rebuild_attempted=True,
                    security_rebuild_classification="clean",
                    security_final_classification="clean",
                    now=dt.datetime(2026, 7, 21, tzinfo=dt.timezone.utc),
                )
            )

            payload = json.loads(
                result.manifest_path.read_text(encoding="utf-8")
            )
            self.assertEqual(
                "actionable_vulnerability",
                payload["security_initial_classification"],
            )
            self.assertTrue(payload["security_rebuild_attempted"])
            self.assertEqual(
                "clean",
                payload["security_rebuild_classification"],
            )
            self.assertEqual(
                "clean",
                payload["security_final_classification"],
            )
            serialized = json.dumps(payload)
            self.assertNotIn("CVE-", serialized)
            self.assertNotIn("package", serialized.lower())
```

- [ ] **Step 2: Run focused manifest tests and verify RED**

Run:

```bash
python3 -m unittest \
  tests.test_deploy_manifest_action \
  tests.test_deploy_manifest_record \
  -v
```

Expected: failures because the new fields and action inputs are absent.

- [ ] **Step 3: Extend the strict manifest schema**

In `scripts/deploy_manifest/write.py`, add:

```python
_SECURITY_CLASSIFICATIONS = frozenset(
    {
        "clean",
        "actionable_vulnerability",
        "unfixed_warning",
        "gate_error",
        "not-reported",
    }
)
```

Extend `ManifestConfig`:

```python
    security_initial_classification: str = "not-reported"
    security_rebuild_attempted: bool = False
    security_rebuild_classification: str = "not-reported"
    security_final_classification: str = "not-reported"
```

Validate before constructing the payload:

```python
    for name, value in (
        (
            "security_initial_classification",
            config.security_initial_classification,
        ),
        (
            "security_rebuild_classification",
            config.security_rebuild_classification,
        ),
        (
            "security_final_classification",
            config.security_final_classification,
        ),
    ):
        if value not in _SECURITY_CLASSIFICATIONS:
            raise ValueError(f"{name} is not an allowed value")
    if not isinstance(config.security_rebuild_attempted, bool):
        raise ValueError("security_rebuild_attempted must be a boolean")
```

Add to the manifest payload:

```python
        "security_initial_classification": (
            config.security_initial_classification
        ),
        "security_rebuild_attempted": config.security_rebuild_attempted,
        "security_rebuild_classification": (
            config.security_rebuild_classification
        ),
        "security_final_classification": (
            config.security_final_classification
        ),
```

Extend the direct `write.py` CLI:

```python
    parser.add_argument(
        "--security-initial-classification",
        choices=sorted(_SECURITY_CLASSIFICATIONS),
        default="not-reported",
    )
    parser.add_argument(
        "--security-rebuild-attempted",
        action="store_true",
    )
    parser.add_argument(
        "--security-rebuild-classification",
        choices=sorted(_SECURITY_CLASSIFICATIONS),
        default="not-reported",
    )
    parser.add_argument(
        "--security-final-classification",
        choices=sorted(_SECURITY_CLASSIFICATIONS),
        default="not-reported",
    )
```

Pass them into `ManifestConfig`:

```python
        security_initial_classification=(
            args.security_initial_classification
        ),
        security_rebuild_attempted=args.security_rebuild_attempted,
        security_rebuild_classification=(
            args.security_rebuild_classification
        ),
        security_final_classification=(
            args.security_final_classification
        ),
```

- [ ] **Step 4: Extend the canonical recorder CLI and composite action**

In `scripts/deploy_manifest/record.py`, add parser arguments:

```python
    parser.add_argument(
        "--security-initial-classification",
        choices=(
            "clean",
            "actionable_vulnerability",
            "unfixed_warning",
            "gate_error",
            "not-reported",
        ),
        default="not-reported",
    )
    parser.add_argument(
        "--security-rebuild-attempted",
        choices=("true", "false"),
        default="false",
    )
    parser.add_argument(
        "--security-rebuild-classification",
        choices=(
            "clean",
            "actionable_vulnerability",
            "unfixed_warning",
            "gate_error",
            "not-reported",
        ),
        default="not-reported",
    )
    parser.add_argument(
        "--security-final-classification",
        choices=(
            "clean",
            "actionable_vulnerability",
            "unfixed_warning",
            "gate_error",
            "not-reported",
        ),
        default="not-reported",
    )
```

Pass them into `ManifestConfig`:

```python
                security_initial_classification=(
                    args.security_initial_classification
                ),
                security_rebuild_attempted=(
                    args.security_rebuild_attempted == "true"
                ),
                security_rebuild_classification=(
                    args.security_rebuild_classification
                ),
                security_final_classification=(
                    args.security_final_classification
                ),
```

Add these optional inputs to `.github/actions/record-deploy-manifest/action.yml`:

```yaml
  security_initial_classification:
    description: Sanitized initial security classification
    required: false
    default: not-reported
  security_rebuild_attempted:
    description: Whether the bounded image remediation retry ran
    required: false
    default: "false"
  security_rebuild_classification:
    description: Sanitized retry security classification
    required: false
    default: not-reported
  security_final_classification:
    description: Sanitized final security classification
    required: false
    default: not-reported
```

Map them to environment values and fixed arguments:

```yaml
        INPUT_SECURITY_INITIAL_CLASSIFICATION: ${{ inputs.security_initial_classification }}
        INPUT_SECURITY_REBUILD_ATTEMPTED: ${{ inputs.security_rebuild_attempted }}
        INPUT_SECURITY_REBUILD_CLASSIFICATION: ${{ inputs.security_rebuild_classification }}
        INPUT_SECURITY_FINAL_CLASSIFICATION: ${{ inputs.security_final_classification }}
```

```bash
          --security-initial-classification "$INPUT_SECURITY_INITIAL_CLASSIFICATION" \
          --security-rebuild-attempted "$INPUT_SECURITY_REBUILD_ATTEMPTED" \
          --security-rebuild-classification "$INPUT_SECURITY_REBUILD_CLASSIFICATION" \
          --security-final-classification "$INPUT_SECURITY_FINAL_CLASSIFICATION" \
```

- [ ] **Step 5: Feed workflow step outputs into the existing recorder**

In both deploy reusables, extend the final recorder `with` block:

```yaml
          security_initial_classification: >-
            ${{ steps.security-gate-images-initial.outputs.classification != '' &&
                steps.security-gate-images-initial.outputs.classification ||
                'not-reported' }}
          security_rebuild_attempted: >-
            ${{ (steps.security-rebuild-retry.outcome == 'success' ||
                 steps.security-rebuild-retry.outcome == 'failure') &&
                'true' || 'false' }}
          security_rebuild_classification: >-
            ${{ steps.security-gate-images-retry.outputs.classification != '' &&
                steps.security-gate-images-retry.outputs.classification ||
                'not-reported' }}
          security_final_classification: >-
            ${{ steps.security-gate-images-retry.outputs.classification != '' &&
                steps.security-gate-images-retry.outputs.classification ||
                (steps.security-gate-images-initial.outputs.classification != '' &&
                 steps.security-gate-images-initial.outputs.classification ||
                 'not-reported') }}
```

Do not change manifest creation ordering or `last-successful.json` behavior.

- [ ] **Step 6: Run manifest and deploy contract suites**

Run:

```bash
python3 -m unittest \
  tests.test_deploy_manifest_action \
  tests.test_deploy_manifest_record \
  tests.test_deploy_manifest_reusable_contract \
  tests.test_security_gate_contract \
  -v
python3 -m compileall -q scripts/deploy_manifest tests
```

Expected: all focused tests pass and compilation exits `0`.

- [ ] **Step 7: Commit sanitized remediation evidence**

```bash
git add \
  .github/actions/record-deploy-manifest/action.yml \
  .github/workflows/_vps-self-hosted-deploy.yml \
  .github/workflows/_vps-monorepo-deploy.yml \
  scripts/deploy_manifest/record.py \
  scripts/deploy_manifest/write.py \
  tests/test_deploy_manifest_action.py \
  tests/test_deploy_manifest_record.py
git commit -m "feat(deploy): record security remediation evidence"
```

---

### Task 7: Extend Organization Adoption Signals

**Files:**
- Modify: `scripts/org_audit/audit.py:21-31,119-161,226-251`
- Modify: `tests/test_org_audit.py:14-55`

**Interfaces:**
- Existing `audit_workflows(repository, visibility, workflows)` remains callable.
- The fetched automation mapping additionally includes `.github/dependabot.yml` when present.
- New rules:
  - `MISSING_DEPENDABOT_CONFIG`
  - `MISSING_DEPENDABOT_AUTOMERGE_CALLER`
- The audit reports only source-backed drift; it does not claim the repository security setting is disabled.

- [ ] **Step 1: Write failing audit behavior tests**

Add to `tests/test_org_audit.py`:

```python
    def test_reports_missing_dependabot_source_contracts(self):
        workflows = {
            ".github/workflows/ci.yml": """
on:
  pull_request:
    paths: ["**"]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd
"""
        }

        findings = audit_workflows(
            "optimizr-tech/service",
            "private",
            workflows,
        )
        rules = {finding.rule_id for finding in findings}

        self.assertIn("MISSING_DEPENDABOT_CONFIG", rules)
        self.assertIn("MISSING_DEPENDABOT_AUTOMERGE_CALLER", rules)

    def test_accepts_dependabot_config_and_canonical_automerge_caller(self):
        workflows = {
            ".github/dependabot.yml": """
version: 2
updates:
  - package-ecosystem: github-actions
    directory: /
    schedule:
      interval: weekly
""",
            ".github/workflows/dependabot-security-automerge.yml": """
on:
  pull_request:
jobs:
  automerge:
    uses: optimizr-tech/optimizr-actions/.github/workflows/_dependabot-security-automerge.yml@v1
""",
        }

        findings = audit_workflows(
            "optimizr-tech/service",
            "private",
            workflows,
        )
        rules = {finding.rule_id for finding in findings}

        self.assertNotIn("MISSING_DEPENDABOT_CONFIG", rules)
        self.assertNotIn("MISSING_DEPENDABOT_AUTOMERGE_CALLER", rules)
```

- [ ] **Step 2: Run the audit tests and verify RED**

Run:

```bash
python3 -m unittest tests.test_org_audit -v
```

Expected: both new assertions fail because the rules do not exist.

- [ ] **Step 3: Add source-backed rules once per repository**

At the start of `audit_workflows`, before iterating files, add:

```python
    has_dependabot_config = ".github/dependabot.yml" in workflows
    has_dependabot_automerge = any(
        "_dependabot-security-automerge.yml@v1" in content
        for path, content in workflows.items()
        if path.startswith(".github/workflows/")
    )
    if not has_dependabot_config:
        findings.append(
            Finding(
                repository,
                visibility,
                ".github/dependabot.yml",
                "MISSING_DEPENDABOT_CONFIG",
                "No source-backed Dependabot configuration was found; repository security-update settings require separate verification.",
            )
        )
    if not has_dependabot_automerge:
        findings.append(
            Finding(
                repository,
                visibility,
                ".github/workflows/",
                "MISSING_DEPENDABOT_AUTOMERGE_CALLER",
                "No caller uses the canonical governed Dependabot auto-merge reusable.",
            )
        )
```

Do not change existing rule IDs or rendering.

- [ ] **Step 4: Fetch `.github/dependabot.yml` through the existing API boundary**

Rename `_fetch_workflows` to `_fetch_automation_files` and preserve its return type. Replace the current early return for a missing workflow directory with an empty mapping so the optional Dependabot configuration is still checked:

```python
    workflows: dict[str, str] = {}
    if listing is not None:
        if not isinstance(listing, list):
            raise AuditError("workflow directory response is invalid")
        for item in listing:
            if not isinstance(item, Mapping) or item.get("type") != "file":
                continue
            path = str(item.get("path", ""))
            if not path.endswith((".yml", ".yaml")):
                continue
            file_data = _api_json(
                f"{API_ROOT}/repos/{repository}/contents/{parse.quote(path)}",
                token,
            )
            if (
                not isinstance(file_data, Mapping)
                or file_data.get("encoding") != "base64"
            ):
                raise AuditError("workflow content response is invalid")
            encoded = str(file_data.get("content", "")).replace("\n", "")
            raw = base64.b64decode(encoded, validate=True)
            if len(raw) > MAX_WORKFLOW_BYTES:
                raise AuditError("workflow exceeds the audit size limit")
            workflows[path] = raw.decode("utf-8")
```

Then fetch the optional configuration:

```python
    dependabot_data = _api_json(
        f"{API_ROOT}/repos/{repository}/contents/.github/dependabot.yml",
        token,
    )
    if dependabot_data is not None:
        if (
            not isinstance(dependabot_data, Mapping)
            or dependabot_data.get("encoding") != "base64"
        ):
            raise AuditError("Dependabot configuration response is invalid")
        encoded = str(dependabot_data.get("content", "")).replace("\n", "")
        raw = base64.b64decode(encoded, validate=True)
        if len(raw) > MAX_WORKFLOW_BYTES:
            raise AuditError("Dependabot configuration exceeds the audit size limit")
        workflows[".github/dependabot.yml"] = raw.decode("utf-8")
```

Update `_audit_selected`:

```python
        visibility, workflows = _fetch_automation_files(repository, token)
```

- [ ] **Step 5: Run audit and contract suites**

Run:

```bash
python3 -m unittest tests.test_org_audit tests.test_org_audit_contract -v
python3 -m compileall -q scripts/org_audit tests/test_org_audit.py
```

Expected: all audit tests pass and compilation exits `0`.

- [ ] **Step 6: Commit adoption signals**

```bash
git add scripts/org_audit/audit.py tests/test_org_audit.py
git commit -m "feat(governance): audit Dependabot remediation adoption"
```

---

### Task 8: Document Behavior, Adoption, and Rollback

**Files:**
- Modify: `docs/SECURITY_GATE.md`
- Create: `docs/DEPENDABOT_SECURITY_AUTOMERGE.md`
- Modify: `docs/ORG_ADOPTION_AUDIT.md`
- Modify: `README.md`

**Interfaces:**
- Documentation must use the exact input/output and workflow names implemented above.
- It must distinguish promotion blocking from workflow self-remediation.
- It must state that unsupported Dependabot updates remain open rather than being merged.

- [ ] **Step 1: Update the security-gate/deploy documentation**

Add these sections to `docs/SECURITY_GATE.md`:

```markdown
## Bounded image remediation retry

The VPS deploy reusables keep the filesystem gate fail-closed and capture only
the initial image-gate outcome. When the image gate classifies the failure as
`actionable_vulnerability`, the deploy may perform exactly one remediation
attempt:

1. `docker compose pull --ignore-buildable`;
2. rebuild selected images with `--pull` and, by default, `--no-cache`;
3. resolve the rebuilt immutable image IDs again;
4. run the same image security gate against those IDs;
5. continue to rollout only when the final scan succeeds.

Secrets, misconfigurations, database/setup failures, malformed evidence, and
filesystem findings never trigger this retry. A failed or missing final result
keeps `docker compose up` unreachable, preserving the currently deployed stack.

The compatible inputs are:

| Input | Default | Meaning |
|---|---:|---|
| `security_rebuild_retry_enabled` | `true` | Permit one actionable image remediation retry. |
| `security_rebuild_retry_no_cache` | `true` | Disable build cache during that retry. |

The `security-gate` action preserves `result=passed|failed` and adds the
sanitized `classification` output plus aggregate finding counts.
```

- [ ] **Step 2: Create Dependabot auto-merge documentation**

Create `docs/DEPENDABOT_SECURITY_AUTOMERGE.md`:

```markdown
# Dependabot security auto-merge

The reusable `_dependabot-security-automerge.yml` enables GitHub native
auto-merge for Dependabot-authored semver patch updates. Consumers may
explicitly allow minor updates with `allow_minor: true`. Major and unknown
update types remain open for review.

The workflow does not check out or execute pull-request code. It uses the
official Dependabot metadata action pinned to an immutable SHA and runs on a
GitHub-hosted runner. Required repository CI and security gates must be
configured as required branch-protection checks; native auto-merge waits for
those checks before merging.

## Consumer caller

Copy `templates/workflows/dependabot-security-automerge.yml` into
`.github/workflows/dependabot-security-automerge.yml`.

Required permissions are limited to:

- `contents: write`;
- `pull-requests: write`.

Do not use `secrets: inherit` and do not route this workflow to a self-hosted
runner. The normal push to the protected deployment branch triggers the
existing deployment workflow.

## Repository configuration

Enable Dependabot security updates in repository or organization settings.
Commit `.github/dependabot.yml` for ecosystems that also need scheduled version
updates and source-backed audit evidence. Enable GitHub auto-merge and require
the repository's tests and security gates before merge.

## Rollback

Disable or remove the thin consumer caller. Vulnerability detection and
deployment security gates continue to operate independently.
```

- [ ] **Step 3: Document audit semantics**

Append to `docs/ORG_ADOPTION_AUDIT.md`:

```markdown
The audit also reports missing source-backed Dependabot remediation adoption:

- `MISSING_DEPENDABOT_CONFIG` means `.github/dependabot.yml` was not found. It
  does not prove that the repository-level security-update setting is disabled;
  that setting must be verified separately.
- `MISSING_DEPENDABOT_AUTOMERGE_CALLER` means no workflow calls
  `_dependabot-security-automerge.yml@v1`.

These rules are signals only. The audit never edits repositories, enables
security settings, creates pull requests, or merges dependency updates.
```

- [ ] **Step 4: Link the new documentation from README**

Add under `## Security gates`:

```markdown
Actionable image findings may use one bounded pull/rebuild/rescan remediation
attempt before rollout. Dependabot-authored repository updates can opt into the
hosted native-auto-merge contract documented in
[`docs/DEPENDABOT_SECURITY_AUTOMERGE.md`](docs/DEPENDABOT_SECURITY_AUTOMERGE.md).
```

- [ ] **Step 5: Run documentation contract and whitespace checks**

Run:

```bash
python3 -m unittest discover -v
git diff --check
```

Expected: full suite passes and `git diff --check` exits `0`.

- [ ] **Step 6: Commit documentation**

```bash
git add \
  README.md \
  docs/SECURITY_GATE.md \
  docs/DEPENDABOT_SECURITY_AUTOMERGE.md \
  docs/ORG_ADOPTION_AUDIT.md
git commit -m "docs(security): document automatic remediation flow"
```

---

### Task 9: Final Exact-SHA Validation and Pull Request

**Files:**
- Verify all files listed in the File Map.
- No implementation changes are expected unless validation exposes a defect.

**Interfaces:**
- The branch must remain backward-compatible with governed `v1`.
- The pull request must explain that a vulnerable candidate remains promotion-blocked while remediation continues automatically.

- [ ] **Step 1: Run the complete local validation suite**

Run:

```bash
python3 -m unittest discover -v
python3 -m compileall -q scripts tests
git diff --check main...HEAD
```

Expected: all tests pass, Python compilation exits `0`, and diff check exits `0`.

- [ ] **Step 2: Validate every workflow and composite**

Run:

```bash
docker run --rm \
  -v "$PWD:/repo" \
  -w /repo \
  rhysd/actionlint@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667

docker run --rm \
  -v "$PWD:/repo" \
  -w /repo \
  mikefarah/yq@sha256:76def1f56f456ecc1c3173ea275218ee17139bc2018c5a07887b15afd88ec03e \
  eval 'true' .github/actions/*/action.yml
```

Expected: both commands exit `0`.

- [ ] **Step 3: Inspect branch scope**

Run:

```bash
git status --short
git log --oneline main..HEAD
git diff --stat main...HEAD
```

Expected: clean working tree; only the planned security, deploy, Dependabot, audit, test, and documentation files changed; commits remain split by independently reviewable behavior.

- [ ] **Step 4: Push and open a pull request**

```bash
git push -u origin HEAD
gh pr create \
  --base main \
  --title ":shield: feat(security): add bounded automatic remediation" \
  --body-file /tmp/security-self-healing-pr.md
```

Write `/tmp/security-self-healing-pr.md` with:

```markdown
## Summary

- exposes additive sanitized security-gate classifications without changing the
  existing `result=passed|failed` contract;
- retries actionable image vulnerabilities exactly once with Compose
  pull/build/rescan;
- never retries secrets, misconfigurations, filesystem findings, or gate
  operational failures;
- keeps rollout unreachable when the final image scan fails;
- adds a hosted Dependabot native-auto-merge reusable for approved update types;
- extends the organization audit with source-backed remediation-adoption
  signals.

## Reused components

This change reuses the existing Trivy gate, VPS deploy reusables, immutable
image discovery, evidence artifacts, branch protection, Dependabot, GitHub
native auto-merge, validation suite, and governed `v1` publication. It adds no
Ogozu service, GitHub App, external queue, or AI patch generator.

## Security behavior

The candidate remains promotion-blocked until the original or remediated image
passes. The currently deployed known-good stack remains available when
remediation cannot produce a clean candidate.

## Validation

- full Python contract suite;
- Python compilation;
- actionlint;
- composite metadata validation;
- candidate diff check.

The hosted workflow result for the exact pull-request SHA is authoritative.
```

- [ ] **Step 5: Verify hosted checks on the exact PR SHA**

Use GitHub Actions to confirm `Validate pull request` completes successfully for the PR head SHA. Do not publish or advance `v1` while any required check is pending, skipped unexpectedly, or failed.

- [ ] **Step 6: Record publication and rollback evidence**

In the PR or release record, capture:

```text
previous_v1_sha=<40-character previous governed v1 target>
candidate_sha=<40-character merged commit>
validation_run=<GitHub Actions run URL>
rollback=move v1 to previous_v1_sha or pin affected consumer
```

Expected: reviewers can identify the exact validated revision and rollback target without repository-by-repository guesswork.
