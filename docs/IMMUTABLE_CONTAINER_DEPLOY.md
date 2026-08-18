# Immutable container build and deploy

`_container-build-publish.yml` is the generic Optimizr Actions contract for
building service images once and publishing them to an OCI registry. A caller
supplies a JSON service matrix and a full source SHA. The workflow builds the
matrix in parallel, uses isolated BuildKit GHA cache scopes, emits BuildKit
SBOM/provenance metadata, and uploads a `release-manifest.json` containing
digest-pinned image references.

Publishing is opt-in through `push: true`. The registry write credential is
only used by the build job and must be passed as a workflow secret. The
published SHA tags are convenience references; production must consume the manifest's
`image@sha256:...` values.

`_vps-monorepo-deploy.yml` keeps `deployment_mode: build` as its compatible
default. `deployment_mode: prebuilt-images` requires a non-empty
`prebuilt_images_json` array and a read-only registry credential. It then:

1. validates every service and full image digest;
2. logs in without printing the token;
3. pulls each requested digest and verifies Docker's returned RepoDigest;
4. generates a temporary Compose override containing only those exact images;
5. runs the existing filesystem/image Trivy gates, health checks, snapshots,
   cleanup, and deployment-manifest recorder using that override;
6. refuses rollout on malformed metadata, a missing digest, a pull mismatch,
   a failed security gate, or a failed health check.

The legacy build path remains available as a compatibility fallback. The
pull-only deploy contract supports rollback by rerunning it with the previous
successful manifest's service/image pairs; the VPS does not rebuild the
application images. Database rollback is not implicit: migrations must remain
expand/contract compatible before this mode is enabled.

For private repositories, GitHub artifact attestations require Enterprise
Cloud. Therefore `github_attestation` defaults to false while BuildKit
provenance and SBOM remain enabled. After the organization plan is confirmed,
callers may enable the GitHub attestation input and grant `attestations: write`
and `id-token: write`.

Serve integration is deliberately gated by the repository variable
`SERVE_DEPLOYMENT_MODE`. Leave it unset or set it to `build` during review. To
enable the pull-only production path after the images and registry permissions
have been validated, set it to `prebuilt-images` and configure the production
environment secrets `GHCR_DEPLOY_USERNAME` and `GHCR_DEPLOY_TOKEN` with a
read-only package scope.
