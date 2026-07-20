# Controlled reusable SAST profiles

The SAST gate installs Semgrep 1.170.0 and executes only rule files committed to `optimizr-actions`. Consumers choose one allowlisted profile: `python`, `typescript`, or `all`. Remote registries, remote URLs and arbitrary rule inputs are not accepted.

```yaml
jobs:
  sast:
    uses: optimizr-tech/optimizr-actions/.github/workflows/_sast-gate.yml@v1
    with:
      profile: all
      baseline_file: .github/sast-baseline.json
      runner_json: '["self-hosted","Linux","security"]'
```

The initial profiles block command/code injection patterns and request-to-outbound-client SSRF flows. High-confidence findings use Semgrep `ERROR` severity. Evidence retains sanitized rule ID, repository-relative path, fingerprint, category and severity; source snippets are deliberately omitted.

A legacy finding may be baselined only by exact rule ID, path and fingerprint, with owner, statement and ISO expiry. Expired or malformed baselines fail closed. Rule tuning must be performed in this repository and released under the reviewed `@v1` process.

Rollback is to pin the preceding Actions commit while retaining an equivalent source-level security scan. Do not replace the SAST gate with a global warning-only mode.
