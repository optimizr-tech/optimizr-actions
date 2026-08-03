# Exact-SHA Validation Authorization Design

## Problem

The validation gate publishes one canonical attestation, but consumers still duplicate the authorization logic that decides whether release and deploy may proceed. Monitoring PR #73 implements that logic as local shell, and its digest validation expects 64 hexadecimal characters even though the central attestation publishes `sha256:<64 hex>`.

Duplicating this logic allows consumers to drift on:

- accepted gate job/results;
- exact-SHA equality;
- digest format;
- accepted validation paths;
- resolved Actions workflow SHA;
- trusted delivery ref.

## Decision

Add a composite action named `validation-authorization` backed by a dependency-free Python script. It validates the canonical gate outputs and emits normalized outputs for downstream release/deploy jobs. Consumers provide the `needs.<gate>` job result and outputs explicitly; the action performs no checkout and receives no secrets.

## Input contract

Required inputs:

- `gate_job_result` — must equal `success`;
- `gate_result` — must equal `passed`;
- `validated_sha` — lowercase 40-character Git SHA;
- `candidate_sha` — lowercase 40-character Git SHA and equal to `validated_sha`;
- `evidence_digest` — canonical `sha256:<64 lowercase hex>`;
- `actions_workflow_sha` — lowercase 40-character Git SHA;
- `validation_path` — one item from the allowlisted paths;
- `candidate_ref` — delivery ref supplied by the caller.

Optional inputs:

- `required_ref`, default `refs/heads/main`;
- `allowed_paths_json`, default `["hosted","self-hosted","reviewed-emergency"]`.

## Outputs

- `result=authorized`;
- `validated_sha`;
- `evidence_digest`;
- `actions_workflow_sha`;
- `validation_path`.

No output is written before all checks pass.

## Failure behavior

The action fails closed for failed/cancelled/skipped gate jobs, non-passed gate results, malformed or mismatched SHAs, noncanonical digest, unknown paths, malformed path JSON, duplicate/empty path entries, or a candidate ref different from the required protected ref.

The action does not interpret `[skip-tests]`, query the GitHub API, check out candidate code, or accept production secrets.

## Consumer migration

Monitoring PR #73 becomes the first consumer. Its local shell authorization step will be replaced by this action, correcting the digest-prefix mismatch and keeping release/deploy on one exact attestation.

Other consumers will use the same action after their `_validation-gate.yml@v1` invocation. Product-specific preparation and post-deploy checks remain local.

## Testing

- unit tests execute the Python CLI across success and negative cases;
- action contract tests require all inputs/outputs and script invocation;
- the complete Actions suite and actionlint must remain green;
- a Monitoring canary must prove canonical digest acceptance and failure for missing evidence, SHA mismatch, skipped gate, invalid path, and non-main ref.

## Rollback

Consumers may temporarily restore their previously reviewed local authorization shell, but it must enforce the canonical `sha256:` digest format and identical fail-closed checks. The central action can then be reverted independently without changing the validation gate or deploy reusable.
