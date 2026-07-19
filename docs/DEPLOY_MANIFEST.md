# Deploy manifest contract

The `write-deploy-manifest` composite action records sanitized deployment evidence independently of a `.git` checkout on the target host.

## Location and permissions

For a deployment path such as:

```text
/opt/optimizr/optimizr-cdn
```

the action writes to:

```text
/opt/optimizr/optimizr-cdn/.deploy-manifests/
```

The directory is forced to `0750`. Every JSON file is written with `0600` using a temporary file, `fsync` and atomic replacement.

The deployment directory must already exist, must be absolute, must not be `/`, and neither it nor an existing path component may be a symlink.

## Files

Immutable attempts use this naming pattern:

```text
YYYYMMDDTHHMMSSZ-<first-12-sha-chars>-<run-id>.json
```

A successful attempt also atomically replaces:

```text
last-successful.json
```

A failed attempt is preserved as evidence but never replaces `last-successful.json`.

Retention applies only to timestamped manifests. The default is 50 and the allowed range is 1 through 500.

## Schema 1.0

```json
{
  "actor": "deploy-bot",
  "deployed_at": "2026-07-19T12:00:00Z",
  "deployed_ref": "refs/heads/main",
  "deployed_sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "environment": "production",
  "healthchecks": [
    {
      "name": "api",
      "status": "passed",
      "target": "optimizr-cdn-api"
    }
  ],
  "images": [
    {
      "digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      "image": "ghcr.io/optimizr-tech/optimizr-cdn-api"
    }
  ],
  "migration_result": "skipped",
  "repository": "optimizr-tech/optimizr-cdn",
  "rollback_of": null,
  "run_id": "12345",
  "runner_name": "cdn-runner",
  "schema_version": "1.0",
  "services": [
    "api"
  ],
  "status": "success",
  "workflow": "Deploy"
}
```

Allowed deployment statuses are `success` and `failure`. Allowed healthcheck statuses are `passed`, `failed` and `skipped`. Allowed migration results are `passed`, `failed`, `skipped` and `not-reported`.

Image digests must be `unknown` or a lowercase `sha256:<64 hex characters>` value.

## Prohibited data

Do not pass:

- environment values or `.env` contents;
- passwords, tokens, cookies or authorization headers;
- private keys or certificates containing private material;
- signed URLs or query signatures;
- customer or tenant data;
- arbitrary JSON keys.

The writer rejects multiline values, secret-assignment patterns, private-key markers, signed-URL signature parameters, `.env` paths, unknown object keys and values longer than 512 characters.

## Composite usage

Pin the action to the reviewed immutable commit SHA during adoption:

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
```

The self-hosted runner requires `python3`. The action does not install Python, inspect the process environment, run Docker commands, perform healthchecks or infer service topology. The deploy workflow remains responsible for collecting sanitized values.

## Rollbacks

For a rollback deployment, set `rollback_of` to a prior deployed SHA or immutable manifest filename. A rollback creates another normal manifest; it does not alter historical files.

## Adoption order

1. Review and merge the standalone writer.
2. Publish it only after repository tests and actionlint pass.
3. Integrate it into reusable deploy workflows in a separate PR using optional inputs.
4. Migrate CDN through a dedicated caller PR without changing stateful service lifecycle.
5. Validate the resulting manifest during the next explicitly approved production deployment.
