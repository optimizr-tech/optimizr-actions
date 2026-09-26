# Revalidating a quarantined GHCR candidate

`_container-candidate-promote.yml` rechecks an existing GHCR image without
rebuilding it. Call it only from a protected branch on a `push` or
`workflow_dispatch` event. The caller grants `packages: write` and passes a
token that can access only the target package. The reusable accepts only
`ubuntu-latest` or a Linux self-hosted runner.
The controlled Trivy default is `v0.74.0`; callers that use the organization
variable can pass `${{ vars.TRIVY_VERSION || 'v0.74.0' }}`.

The caller supplies the image repository, its full `sha256:` digest, and the
source commit expected in BuildKit provenance. The reusable fetches SBOM and
provenance through that immutable image reference, verifies the attestation
index and source repository/commit, scans the same digest, then copies that
digest to the source-SHA release tags. It verifies both tags resolve to the
candidate digest. Any missing or mismatched evidence, expired exception,
additional blocking finding, or registry error prevents promotion and the
release manifest outputs.

An optional `security_exceptions_file` is read from the protected caller
revision. Every entry must be image-only, target exactly the supplied
`ghcr.io/...@sha256:...` reference, and include explicit PURLs. Wildcard targets,
lineage-only scopes, wildcard PURLs, filesystem scopes, and duplicate advisory
IDs are rejected before promotion. The normal security gate still validates
expiry, ownership, and required exception metadata. The complete Trivy report
is uploaded as a run artifact, including when the promotion is blocked.

Example caller job:

```yaml
permissions:
  contents: read
  packages: write

jobs:
  promote-candidate:
    uses: optimizr-tech/optimizr-actions/.github/workflows/_container-candidate-promote.yml@v1
    with:
      image_repository: ghcr.io/optimizr-tech/grafana
      candidate_digest: sha256:<full-digest>
      candidate_sha: <full-source-commit>
      security_exceptions_file: .github/security/grafana-candidate-exceptions.json
      security_trivy_version: ${{ vars.TRIVY_VERSION || 'v0.74.0' }}
    secrets:
      registry_username: ${{ github.actor }}
      registry_password: ${{ secrets.GITHUB_TOKEN }}
```

Use the returned `image_ref` or `manifest_json` for downstream deployment; do
not deploy from a mutable tag. If promotion must be rolled back, deploy the
previous verified digest. A caller can also disable exceptions by omitting the
policy input; the default blocking vulnerability behavior remains in force.
