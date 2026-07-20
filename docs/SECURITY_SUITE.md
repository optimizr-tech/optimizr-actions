# Reusable security suite

`_security-suite.yml` provides one caller contract for the portable Optimizr security gates.

Profiles:

| Profile | Static lint | Filesystem scan | Dependency policy | SAST | Image evidence |
|---|---:|---:|---:|---:|---:|
| `python` | yes | yes | yes | Python | no |
| `node` | yes | yes | yes | TypeScript/JavaScript | no |
| `compose` | yes | yes | no | no | when `image_refs` is supplied |
| `infra` | yes | yes | no | no | when `image_refs` is supplied |
| `monorepo` | yes | yes | yes | all | when `image_refs` is supplied |

```yaml
jobs:
  security:
    uses: optimizr-tech/optimizr-actions/.github/workflows/_security-suite.yml@v1
    with:
      profile: monorepo
      runner_json: '["ubuntu-latest"]'
      dependency_policy_file: .github/security/dependency-policy.json
      sast_baseline_file: .github/security/sast-baseline.json
```

The suite does not accept shell commands or secrets. Consumer-owned policy/baseline paths remain repository relative. For image evidence, build the final image first on the selected runner and pass only local image references.

Merge order: publish the static-lint, dependency-policy, SAST and supply-chain contracts before publishing the suite through `v1`. Rollback by pinning the preceding compatible Actions commit while retaining equivalent mandatory gates.
