# Reusable post-deploy verification

The workflow verifies the exact deployed SHA on a protected, trusted self-hosted runner. A version-1 manifest declares container and HTTP readiness checks; optional negative boundary probes delegate to `_negative-probes.yml`.

```json
{
  "version": 1,
  "containers": [
    {"name": "api", "container": "optimizr-example-api", "health": "healthy"}
  ],
  "http": [
    {"name": "api-health", "target": "target1", "path": "/health", "expected_status": [200], "timeout_seconds": 5}
  ]
}
```

```yaml
jobs:
  verify:
    uses: optimizr-tech/optimizr-actions/.github/workflows/_post-deploy-verification.yml@v1
    with:
      environment_name: production-security
      runner_json: '["self-hosted","Linux","example"]'
      deployed_sha: ${{ github.sha }}
      manifest_path: .github/deploy/verification.json
      negative_manifest_path: .github/deploy/negative-probes.json
    secrets:
      VERIFY_TARGET_1: ${{ secrets.INTERNAL_VERIFY_ORIGIN }}
```

Evidence records aliases, results, durations, HTTP status, container state and immutable image ID. It excludes container names, origins, paths, headers and response bodies. HTTP checks do not follow redirects or use proxy environment variables.

Rollback by restoring equivalent consumer-owned checks while preserving the protected environment, exact-SHA binding and negative security probes.
