# Exact-SHA validation authorization

`validation-authorization` is the canonical downstream authorization contract for release and deploy. It consumes the outputs of `_validation-gate.yml` and fails closed unless one complete exact-SHA attestation is eligible for delivery.

## Canonical inputs

The caller passes:

- `needs.validation-gate.result` as `gate_job_result`;
- `needs.validation-gate.outputs.result` as `gate_result`;
- the validated and candidate SHAs;
- the canonical evidence digest;
- the resolved Actions workflow SHA;
- the validation path;
- the caller ref.

The evidence digest format is exactly `sha256:<64 lowercase hex>`. A raw 64-character hexadecimal value is invalid because it is not the format produced by the central validation attestation.

```yaml
jobs:
  validation-gate:
    uses: optimizr-tech/optimizr-actions/.github/workflows/_validation-gate.yml@v1
    with:
      candidate_sha: ${{ github.sha }}
      script_path: scripts/ci/validate.sh
      security_profile: infra

  authorize-validation:
    needs: [validation-gate]
    if: always()
    runs-on: ubuntu-latest
    steps:
      - name: Authorize exact-SHA delivery
        id: authorization
        uses: optimizr-tech/optimizr-actions/.github/actions/validation-authorization@v1
        with:
          gate_job_result: ${{ needs.validation-gate.result }}
          gate_result: ${{ needs.validation-gate.outputs.result }}
          validated_sha: ${{ needs.validation-gate.outputs.validated_sha }}
          candidate_sha: ${{ github.sha }}
          evidence_digest: ${{ needs.validation-gate.outputs.evidence_digest }}
          actions_workflow_sha: ${{ needs.validation-gate.outputs.actions_workflow_sha }}
          validation_path: ${{ needs.validation-gate.outputs.validation_path }}
          candidate_ref: ${{ github.ref }}
```

Release and deploy depend on the same successful `authorize-validation` job and therefore on the same attestation. They do not poll GitHub Actions, reconstruct marker conditions, or independently decide which validation result is acceptable.

## Authorization rules

Authorization requires:

- the gate job result is `success`;
- the gate output is `passed`;
- `validated_sha` and `candidate_sha` are valid lowercase Git SHAs and equal;
- `evidence_digest` uses the canonical `sha256:` format;
- `actions_workflow_sha` is a valid lowercase Git SHA;
- the validation path is in the reviewed allowlist;
- the caller ref equals `required_ref`, which defaults to `refs/heads/main`.

The action writes no outputs until every rule passes. It does not check out candidate code, query the GitHub API, or consume secrets. It does not interpret `[skip-tests]`. Infrastructure routing remains the private caller's responsibility before invoking `_validation-gate.yml`.

## Monitoring migration

Monitoring PR #73 is the first consumer. Its local shell currently expects a raw 64-character digest, which conflicts with the canonical `sha256:<64 lowercase hex>` attestation. The migration replaces that shell with this action while keeping Monitoring-specific validation, preparation, deployment, observability checks, and protected-runner boundaries unchanged.

## Failure behavior

Malformed SHAs, digest, path JSON, or input enums exit as invalid input. A well-formed but failed, skipped, mismatched, untrusted-path, or non-protected-ref result exits as unauthorized. Neither case emits downstream authorization outputs.

## Rollback

A consumer may temporarily restore its last reviewed local authorization shell while the central action is rolled back. That shell must preserve the canonical digest format, exact-SHA equality, workflow-SHA validation, path allowlist, protected-ref requirement, and failure on `skipped`. It must not restore API polling or marker-based release authorization.
