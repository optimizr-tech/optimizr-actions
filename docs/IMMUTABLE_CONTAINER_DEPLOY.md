# Immutable container build and deploy

`_container-build-publish.yml` is the generic Optimizr Actions contract for
building service images once and publishing them to an OCI registry. A caller
supplies a JSON service matrix and a full source SHA. The workflow builds the
matrix with bounded concurrency, uses a selectable BuildKit cache backend,
emits BuildKit SBOM/provenance metadata, and uploads a `release-manifest.json` containing
digest-pinned image references.

Publishing is opt-in through `push: true`. The registry write credential is
only used by the build job and must be passed as a workflow secret. A push run
first creates a unique, digest-addressed quarantine candidate. The exact
candidate is scanned with the canonical Trivy security gate and its BuildKit
attestation index plus SBOM and provenance predicates are verified against the
candidate digest before `imagetools create` promotes that same digest to the SHA
tags. A candidate that fails either check cannot be promoted. The published SHA
tags are convenience references; production must
consume the manifest's `image@sha256:...` values.

After promotion, the reusable performs a bounded read-after-write verification
of the release tag. This tolerates short GHCR registry propagation delays while
remaining fail-closed: the manifest is not emitted as published unless the tag
resolves to the exact verified digest. The retry is internal and does not add or
change any caller input or output.

## Caller permission contract

GitHub validates the caller's permission ceiling before it creates jobs in a
reusable workflow. Every caller job that uses this workflow must therefore
declare the permissions required by the reusable build job, even when
`push: false` or `github_attestation: false` is selected:

```yaml
permissions:
  contents: read
  packages: write
  attestations: write
  id-token: write
```

These permissions belong on the caller job containing `uses:`. Omitting the
attestation or OIDC scopes can produce `startup_failure` with no jobs or logs;
the failure happens before the reusable can evaluate its inputs. The
`github_attestation` input controls whether a GitHub artifact attestation is
published; it does not remove the declared permission contract.

The reusable accepts `runner_json` for the matrix build and
`control_runner_json` for service-definition validation and release-manifest
aggregation. Both default to `["ubuntu-latest"]` for backwards compatibility.
Organizations that do not rely on GitHub-hosted billing should set both inputs
to a dedicated self-hosted container-builder label with Docker, Buildx, Python,
and artifact-download support. Do not point these jobs at a production service
runner by default: the image matrix can contend for CPU, memory, disk, and
Docker cache.

Each matrix image build defaults to a 150-minute timeout. Callers may set
`timeout_minutes` from 1 through 360 for unusually long native builds; the
matrix job name and `SERVICE_NAME` environment value retain the service
identity in failure evidence, and the existing Buildx/action cleanup hooks
remain enabled.

The default `cache_type: gha` preserves isolated GitHub Actions cache scopes
(`cache_scope_prefix` plus service name). Set `cache_type: none` to omit
external cache import/export. For a persistent self-hosted cache, set
`cache_type: local` and provide `local_cache_path` as an absolute runner-local
cache root. The reusable creates one subdirectory per service, so parallel
services in a single call do not write the same cache directory. The path must
be runner-owned, outside `GITHUB_WORKSPACE` and every build context, and must
not contain secrets. The reusable does not impose a disk budget or prune local
cache files: runner operations must bound and clean the directory while no
build is using it. Callers must serialize separate workflow runs that share a
local cache root for the same service, or give those runs isolated roots.

Keep `max_parallel: 1` on shared or capacity-constrained runners. Raise it only
when `runner_json` selects a pool with enough simultaneously available builders
and CPU, memory, disk, and BuildKit capacity; local cache paths remain isolated
per service, but parallelism still increases host resource pressure.

The build job checks out the exact reusable revision selected by GitHub through
`job.workflow_repository` and `job.workflow_sha` into
`.optimizr-actions-source`. Portable verification scripts and the composite
security gate run from that checkout, never from the consumer repository. This
keeps the caller responsible for Docker contexts and source files while the
Actions repository remains the source of truth for its executable gates.

`_vps-monorepo-deploy.yml` and `_vps-self-hosted-deploy.yml` keep
`deployment_mode: build` as their compatible default. Their
`deployment_mode: prebuilt-images` mode requires a non-empty
`release_manifest_json` value from `_container-build-publish.yml` (preferred)
or, for backwards compatibility, a non-empty `prebuilt_images_json` array.
Private registries additionally receive a read-only registry credential; public
images are pulled anonymously. When the release manifest is supplied, the
deploy validates that it is published and uses its digest-pinned `images`
entries directly; callers must not provide both inputs. It then:

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

A caller can connect the build and deploy jobs without reconstructing the
image list manually:

```yaml
jobs:
  images:
    uses: optimizr-tech/optimizr-actions/.github/workflows/_container-build-publish.yml@v1
    permissions:
      contents: read
      packages: write
      attestations: write
      id-token: write
    with:
      candidate_sha: ${{ github.sha }}
      image_namespace: ${{ github.repository_owner }}/my-service
      services_json: '[{"name":"api","context":".","dockerfile":"Dockerfile"}]'
      # Optional: the default is 150; accepted values are 1 through 360.
      # timeout_minutes: 300
      # For a trusted persistent runner, use local plus an absolute path
      # outside the workspace; the runner owner manages cache budget/cleanup.
      # cache_type: local
      # local_cache_path: /runner-owned/buildkit-cache
      # Raise only when the selected runner pool has capacity.
      max_parallel: 1
      push: true

  deploy:
    needs: images
    uses: optimizr-tech/optimizr-actions/.github/workflows/_vps-self-hosted-deploy.yml@v1
    permissions:
      contents: read
      packages: read
    with:
      deployment_mode: prebuilt-images
      release_manifest_json: ${{ needs.images.outputs.manifest_json }}
      registry_auth_mode: github-token
      # ...the remaining deployment inputs...
```

This is the intended “build once in GHCR, pull by immutable digest on the
VPS” path. The old `prebuilt_images_json` input remains for existing callers
and rollback tooling that already stores only the service/image pairs.

### Registry authentication modes

Pull-only callers choose an explicit `registry_auth_mode`:

- `anonymous` pulls public images without credentials;
- `github-token` logs in to `ghcr.io` with the called workflow's short-lived
  `github.token` and requires the caller job to grant `packages: read`;
- `explicit` preserves the legacy credential contract and requires both
  `registry_username` and `registry_password`.

The `github-token` mode is preferred when the GHCR package is associated with
the caller repository. It does not require a PAT to be installed on the VPS.
The token is available only to the trusted deployment job and the reusable
must isolate Docker authentication under `$RUNNER_TEMP`, run `docker logout`,
and remove that directory before the job ends. If package access cannot be
granted to the caller repository, use a dedicated read-only `read:packages`
credential through a protected GitHub Environment secret; never write it to a
repository file or a permanent Docker config on the host.

For private repositories, GitHub artifact attestations require Enterprise
Cloud. Therefore `github_attestation` defaults to false. The registry-backed
BuildKit SBOM and provenance check is mandatory for every published image; the
workflow fails closed if the exact digest has no attestation manifest or either
predicate cannot be read. BuildKit may store both predicates in one attestation
manifest; the workflow validates the predicate contents instead of assuming
one descriptor per predicate. After the
organization plan is confirmed, callers may additionally enable the GitHub
attestation input.

The default `push: false` path loads the image locally and runs the same image
security gate without granting a deployable artifact. Existing callers that do
not call `_container-build-publish.yml` are unaffected. Existing callers of
`_vps-monorepo-deploy.yml` retain `deployment_mode: build`; they can migrate by
first consuming the release manifest and then opting into
`deployment_mode: prebuilt-images` in a separate reviewed change.

Repositories that consume upstream images can use the canonical composite
action `resolve-image-manifest@v1`. It converts Compose service image tags
into a sanitized service-to-`RepoDigest` manifest on the caller-selected runner
with Docker, so the shared self-hosted deploy reusable can consume the same
immutable contract without duplicating Docker-resolution logic in each
repository.

Migration checklist:

1. Add a caller build workflow with the exact source SHA and service matrix.
2. Select a dedicated self-hosted builder through both `runner_json` and
   `control_runner_json` when hosted billing is not available.
3. Store the resulting release manifest as the only deployment input.
4. Prefer `registry_auth_mode: github-token` with caller `packages: read`; if
   package access requires a separate identity, configure a read-only registry
   token on the protected self-hosted deployment environment.
5. Run the prebuilt path in staging and prove a missing or mismatched digest
   fails before Compose rollout.
6. Keep the previous successful manifest for rollback; rollback means rerunning
   the same pull-only deploy with that manifest. Database rollback is separate.

Serve integration is deliberately gated by the repository variable
`SERVE_DEPLOYMENT_MODE`. Leave it unset or set it to `build` during review. To
enable the pull-only production path after the images and registry permissions
have been validated, set it to `prebuilt-images` and configure the production
environment secrets `GHCR_DEPLOY_USERNAME` and `GHCR_DEPLOY_TOKEN` with a
read-only package scope.
