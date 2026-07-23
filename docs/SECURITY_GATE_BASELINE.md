# Reviewed vulnerability baseline

A reviewed baseline is an emergency containment mechanism for immutable third-party runtime images when the latest compatible upstream release still contains fixable `HIGH` or `CRITICAL` findings.

It is not a severity reduction and does not disable Trivy. The complete table, JSON and SARIF reports remain available. The gate removes only exact approved fingerprints from the enforcement report and continues to block:

- any new vulnerability fingerprint;
- any changed package, installed version or fixed version;
- secrets and misconfigurations;
- scanner, database or evidence failures;
- missing, malformed, stale or expired baseline entries;
- an image ID not explicitly represented in the baseline.

## Schema

```json
{
  "version": 1,
  "owner": "optimizr-tech/security",
  "reviewed_at": "2026-07-22",
  "expires": "2026-08-22",
  "statement": "Latest compatible upstream image still contains reviewed findings",
  "compensating_control": "Private network, authenticated access and restricted ingress",
  "findings": [
    {
      "scope": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "target": "debian",
      "id": "CVE-2026-0001",
      "package": "libexample",
      "installed_version": "1.2.3",
      "fixed_version": "1.2.4"
    }
  ]
}
```

`scope` is the exact immutable Docker image ID discovered by the deployment workflow. The remaining fields are copied from the blocking Trivy JSON report. A baseline must be reviewed again whenever an image ID or package fingerprint changes.

## Adoption

The single-service VPS reusable exposes `security_baseline_file`. Keep the file in the consumer repository and pass its repository-relative path:

```yaml
uses: optimizr-tech/optimizr-actions/.github/workflows/_vps-self-hosted-deploy.yml@v1
with:
  security_baseline_file: .github/security/image-baseline.json
```

The first rollout is intentionally limited to the single-service reusable and the Monitoring canary. Monorepo adoption should follow after the canary produces clean evidence and the floating `v1` release is reviewed.

## Review and removal

Every baseline must have an accountable owner, review date, expiry date, justification and compensating control. Remove entries as soon as upstream images clear them. Expired entries fail closed rather than silently extending risk acceptance.
