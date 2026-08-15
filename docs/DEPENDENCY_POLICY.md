# Dependency and license policy gate

The reusable dependency gate validates the selected Python or Node lockfile before scanning a confined project directory with controlled Trivy vulnerability and license scanners.

Supported contracts:

- `pyproject.toml` with exactly one of `uv.lock` or `poetry.lock`;
- `package.json` with one matching `pnpm-lock.yaml`, `package-lock.json`, or `yarn.lock`;
- `packageManager` selects the expected Node lockfile when present.

For uv projects, `requires-python` must declare a minimum Python version, such
as `>=3.14` or `>=3.14,<3.15`. The action normalizes that lower bound to the
concrete runtime passed to uv (`3.14`); a constraint without a lower bound
fails closed.

For Node projects, the organization defaults are Node 24 and npm 12.0.2. The
versions are explicit reusable inputs and can be overridden only by a reviewed
consumer contract. npm projects are validated with the immutable command
`npm ci --ignore-scripts --no-audit --no-fund`; the gate never regenerates `package-lock.json`.
Engine incompatibility, an npm installation failure, or a stale lockfile fails
closed before vulnerability and license evaluation.

The project may live at the repository root or in a repository-relative `working_directory`. The action resolves the directory with `realpath`, rejects traversal and symlinks, runs package-manager validation from that directory, and keeps evidence under the repository artifact path.

The native package manager performs an immutable/frozen lock check. A missing tool, network failure, stale lockfile, missing advisory data, malformed policy, denied license, or unexcepted High/Critical advisory fails closed.

The sanitized toolchain evidence records detected ecosystems, requested Node/npm versions, and resolved Python/Node/npm versions. It does not contain environment variables, registry credentials, package contents, or install logs.

```yaml
jobs:
  dependencies:
    uses: optimizr-tech/optimizr-actions/.github/workflows/_dependency-policy.yml@v1
    with:
      runner_json: '["self-hosted","Linux","security"]'
      working_directory: frontend/apps/admin
      policy_file: .github/dependency-policy.json
      node_version: "24"
      npm_version: "12.0.2"
```

The same `node_version` and `npm_version` inputs are propagated through `_security-suite.yml@v1` and `_validation-gate.yml@v1`, allowing one reviewed organization contract to select the runtime without copying setup logic into consumers.

Policy exceptions are exact by kind, advisory/license identifier and package. Every exception requires owner, statement and ISO expiry. Evidence records lockfile and policy hashes, repository/SHA, the Trivy report hash, suppressed findings and blocking findings; it does not serialize credentials or package-manager environments.

The bundled policy blocks High/Critical advisories plus `AGPL-3.0-only` and `SSPL-1.0`. Consumers may replace it with a reviewed repository policy. Rollback requires pinning the prior Actions commit and retaining equivalent lock, advisory and license checks, including Node 24/npm 12.0.2 immutable npm validation for repositories that require that toolchain.
