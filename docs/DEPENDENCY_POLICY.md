# Dependency and license policy gate

The reusable dependency gate validates the selected Python or Node lockfile before scanning the repository with controlled Trivy vulnerability and license scanners.

Supported contracts:

- `pyproject.toml` with exactly one of `uv.lock` or `poetry.lock`;
- `package.json` with one matching `pnpm-lock.yaml`, `package-lock.json`, or `yarn.lock`;
- `packageManager` selects the expected Node lockfile when present.

The native package manager performs an immutable/frozen lock check. A missing tool, network failure, stale lockfile, missing advisory data, malformed policy, denied license, or unexcepted High/Critical advisory fails closed.

```yaml
jobs:
  dependencies:
    uses: optimizr-tech/optimizr-actions/.github/workflows/_dependency-policy.yml@v1
    with:
      runner_json: '["self-hosted","Linux","security"]'
      policy_file: .github/dependency-policy.json
```

Policy exceptions are exact by kind, advisory/license identifier and package. Every exception requires owner, statement and ISO expiry. Evidence records lockfile and policy hashes, repository/SHA, the Trivy report hash, suppressed findings and blocking findings; it does not serialize credentials or package-manager environments.

The bundled policy blocks High/Critical advisories plus `AGPL-3.0-only` and `SSPL-1.0`. Consumers may replace it with a reviewed repository policy. Rollback requires pinning the prior Actions commit and retaining equivalent lock, advisory and license checks.
