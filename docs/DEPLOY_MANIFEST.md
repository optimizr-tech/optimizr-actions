# Deploy manifest contract

The deploy-manifest tools record sanitized deployment evidence independently of a `.git` checkout on the target host.

## Location and permissions

For a deployment path such as `/opt/optimizr/optimizr-cdn`, manifests are stored under:

```text
/opt/optimizr/optimizr-cdn/.deploy-manifests/
```

The directory is forced to `0750`. Every JSON file is written with `0600` using a temporary file, `fsync` and atomic replacement. The deployment directory must already exist, must be absolute, must not be `/`, and neither it nor an existing path component may be a symlink.

Immutable attempts use:

```text
YYYYMMDDTHHMMSSZ-<first-12-sha-chars>-<run-id>.json
```

A successful attempt also atomically replaces `last-successful.json`. A failed attempt is retained but never replaces that pointer. Retention applies only to timestamped manifests; the default is 50 and the allowed range is 1–500.

## Schema 1.0

```json
{
  "actor": "deploy-bot",
  "deployed_at": "2026-07-19T12:00:00Z",
  "deployed_ref": "refs/heads/main",
  "deployed_sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "environment": "production",
  "healthchecks": [
    {"name": "primary-container", "status": "passed", "target": "optimizr-cdn-api"}
  ],
  "images": [
    {
      "digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      "image": "ghcr.io/optimizr-tech/optimizr-cdn-api"
    }
  ],
  "migration_result": "skipped",
  "optional_build_result": "not-reported",
  "repository": "optimizr-tech/optimizr-cdn",
  "rollback_of": null,
  "run_id": "12345",
  "runner_name": "cdn-runner",
  "schema_version": "1.0",
  "services": ["api"],
  "status": "success",
  "workflow": "Deploy"
}
```

Allowed deployment statuses are `success` and `failure`. Healthcheck statuses are `passed`, `failed` and `skipped`. Migration and optional-build results are `passed`, `failed`, `skipped` and `not-reported`.

Image digests must be `unknown` or a lowercase `sha256:<64 hex characters>` value.

## Prohibited data

Never record environment values, `.env` contents, passwords, tokens, cookies, authorization headers, private-key material, signed URLs, customer/tenant data, arbitrary JSON keys or command output. The writer rejects multiline values, secret-assignment patterns, private-key markers, signed-URL signatures, `.env` paths, unknown object keys and oversized values.

## Standalone writer

```yaml
- name: Record deployment evidence
  uses: optimizr-tech/optimizr-actions/.github/actions/write-deploy-manifest@<COMMIT_SHA>
  with:
    deploy_path: /opt/optimizr/optimizr-cdn
    status: success
    services_json: '["api"]'
    images_json: >-
      [{"image":"ghcr.io/optimizr-tech/optimizr-cdn-api","digest":"sha256:..."}]
    healthchecks_json: >-
      [{"name":"api","status":"passed","target":"optimizr-cdn-api"}]
    migration_result: skipped
    optional_build_result: not-reported
```

## VPS reusable integration

Both `_vps-self-hosted-deploy.yml` and `_vps-monorepo-deploy.yml` expose backward-compatible optional inputs:

```yaml
with:
  deploy_manifest_enabled: true
  deploy_manifest_retention: 50
  deploy_manifest_migration_result: passed
```

When disabled—the default—existing callers execute exactly as before.

When enabled, an `if: always()` final stage checks out `job.workflow_repository` at `job.workflow_sha` and invokes the local `record-deploy-manifest` action from that exact revision. This prevents a workflow called at an immutable SHA from silently loading manifest code from a newer floating `v1` revision.

The recorder uses fixed Docker argv to collect only:

- Compose service names;
- configured image names and immutable local image IDs;
- primary container health result;
- caller-declared migration result;
- explicit optional-build result in monorepo deploys.

A failed build, rollout, migration or health stage leaves the job failed and produces a failure manifest without replacing `last-successful.json`. A successful manifest is written only after rollout, verification, evidence upload and cleanup have completed.

The monorepo reusable no longer calls the compatibility `wait-for-healthcheck` action from `optimizr-infra-ops`; it retains the same health wait before post-deploy commands.

## Rollback

Consumers can disable manifest recording without changing any existing deployment input. To roll back the implementation itself, pin the preceding compatible `optimizr-actions` SHA. Historical manifests remain immutable and can be retained or removed according to the consumer's operating policy.
