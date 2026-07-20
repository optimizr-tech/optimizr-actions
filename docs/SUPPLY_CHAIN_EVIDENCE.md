# Image SBOM and provenance evidence

The supply-chain workflow generates two machine-readable inventories for every final local image selected for promotion:

- CycloneDX JSON;
- SPDX JSON.

It resolves the image's immutable repository digest or Docker image ID before producing a SLSA-compatible in-toto provenance statement. The statement binds source repository, exact commit, workflow identity, image digest, SBOM hashes, file sizes, and controlled Trivy version. Raw image references and Docker inspection data are not retained; evidence uses a non-reversible image alias.

```yaml
jobs:
  sbom:
    uses: optimizr-tech/optimizr-actions/.github/workflows/_supply-chain-evidence.yml@v1
    with:
      runner_json: '["self-hosted","Linux","security"]'
      image_refs: |
        my-service-api
        my-service-worker
```

The job fails when an image cannot be inspected, lacks an immutable SHA-256 identity, or either SBOM/provenance artifact cannot be written. Signing and registry publication remain consumer/infra responsibilities and must use named secrets rather than inherited secrets when introduced.

Rollback is to pin the previous Actions commit while retaining an equivalent SBOM tied to source SHA and image digest. Never promote evidence tied only to a mutable tag.
