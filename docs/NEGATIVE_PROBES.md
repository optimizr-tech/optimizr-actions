# Post-deploy negative security probes

Negative probes verify that a deployed boundary rejects behavior that must remain prohibited. They are distinct from readiness and positive smoke tests.

The manifest is declarative JSON. It supports only `GET`, `HEAD`, and `OPTIONS`, at most 20 requests, 1–10 second timeouts, 64 KiB response bodies, expected status codes, required/forbidden headers, and forbidden response strings. Redirects are not followed. Destructive methods, arbitrary scripts, credentials in URLs, unbounded payloads, and target URLs in artifacts are prohibited.

```json
{
  "version": 1,
  "probes": [
    {
      "name": "admin-console-denies-public-access",
      "target": "target1",
      "path": "/admin/",
      "method": "GET",
      "expected_status": [401, 403, 404],
      "required_headers": {"X-Frame-Options": "DENY"},
      "body_must_not_contain": ["MINIO_ROOT_PASSWORD"],
      "timeout_seconds": 5
    }
  ]
}
```

Configure `PROBE_TARGET_1` through `PROBE_TARGET_5` as named repository or protected-environment secrets containing only HTTP(S) origins. Evidence stores aliases and a path hash, never the private origin or response body.

```yaml
jobs:
  negative-security:
    uses: optimizr-tech/optimizr-actions/.github/workflows/_negative-probes.yml@v1
    with:
      environment_name: production-security
      deployed_sha: ${{ github.sha }}
      manifest_path: .github/security/negative-probes.json
    secrets:
      PROBE_TARGET_1: ${{ secrets.PROBE_TARGET_1 }}
```

The workflow checks out the explicit 40-character `deployed_sha` and binds every result to that commit. A failed required probe, unavailable target, missing secret, malformed manifest or safety-limit violation fails the workflow after deployment. The protected environment should define reviewer approval and rollback/escalation ownership.
