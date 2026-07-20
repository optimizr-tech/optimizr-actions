# Supply-chain evidence design

## Goal

Create digest-bound CycloneDX, SPDX and provenance artifacts for final container images on hosted or trusted self-hosted Linux runners.

## Design

The composite action uses the already governed Trivy installer, resolves each image through Docker inspection, and falls back to a root-owned Docker save while running Trivy itself unprivileged. A Python evidence writer validates SHA-256 identities, hashes both SBOMs, removes raw target names, and emits an in-toto Statement using the SLSA provenance predicate. The reusable workflow retains artifacts with read-only permissions.

## Future signing boundary

The statement is intentionally unsigned until registry publishing and workload identity are available. Future signing must add named secrets or OIDC permissions in a separate compatible change; private registries and identities stay outside this public repository.
