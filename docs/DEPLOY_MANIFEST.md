# Deployment manifest contract

The `write-deploy-manifest` composite action records sanitized evidence of what a deployment attempted or successfully installed. It is intentionally independent from `.git` being present in the production directory.

## Location and permissions

Manifests are stored under:

```text
<DEPLOY_PATH>/.deploy-manifests/
```

The directory is mode `0750`; manifest files and `last-successful.json` are mode `0600`. The action rejects a relative, root, or symlink deployment path.

## Files

Immutable evidence uses the deterministic form:

```text
YYYYMMDDTHHMMSSZ-<sha-prefix>-<run-id>.json
```

`last-successful.json` is an atomically replaced regular file containing the latest successful manifest. A failed deployment writes its own immutable evidence but never replaces the last successful pointer.

The default retention is 50 immutable manifests. Consumers may choose a value from 1 to 500.

## Schema version 1.0

A manifest records only these fields:

- schema version and result;
- UTC deployment timestamp;
- repository, deployed SHA and ref;
- workflow and run ID;
- environment, actor and runner name;
- updated service names;
- image names and immutable digests;
- sanitized healthcheck names, targets and results;
- sanitized migration result;
- optional rollback source.

The action accepts no generic environment map, headers, arbitrary metadata object, or secret input.

## Prohibited data

Callers must never pass:

- `.env` content or variable values;
- passwords, tokens, cookies, authorization headers or private keys;
- signed URLs or URLs containing credentials/query signatures;
- customer or tenant data;
- raw logs;
- database connection strings.

Healthcheck targets should be stable public paths or container/service identifiers without query strings.

## Atomicity

The action writes to a temporary file in the destination directory, flushes and fsyncs it, applies mode `0600`, then uses `os.replace`. Successful pointer replacement uses the same atomic strategy.

## Rollback representation

A rollback is a normal deployment manifest with `rollback_of` set to the previous manifest filename or deployed SHA. The newly deployed rollback SHA remains the `deployed_sha`; history is not rewritten.

## Integration policy

Adding this action does not change deployment behavior. Each deploy reusable must integrate it in a separate compatibility-reviewed change after:

1. known consumers are inventoried;
2. image-digest collection is proven for their Compose topology;
3. healthcheck output is sanitized;
4. failure behavior is simulated;
5. the caller is restricted to an authorized deployment branch/environment;
6. human approval is obtained before production execution.

## Example

```yaml
- name: Record successful deployment
  uses: optimizr-tech/optimizr-actions/.github/actions/write-deploy-manifest@<immutable-sha-or-reviewed-v1>
  with:
    deploy_path: /opt/optimizr/optimizr-cdn
    status: success
    services_json: '["api"]'
    images_json: '[{"image":"optimizr-cdn-api","digest":"sha256:example"}]'
    healthchecks_json: '[{"name":"api","status":"passed","target":"optimizr-cdn-api"}]'
    migration_result: not-applicable
```

The example digest is synthetic.
