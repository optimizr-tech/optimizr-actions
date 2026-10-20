# Container publish auth resilience

`_container-build-publish.yml` can separate the image build from the registry
publication so a long build does not fail at the final push because the
registry authentication context went stale.

## Problem

In the default `inline` mode, `docker/build-push-action` pushes the quarantine
candidate from the BuildKit exporter at the very end of the build. The registry
login happens before the build starts. On a shared self-hosted build runner a
job can wait hours in the queue and then build for close to two hours; in
`optimizr-monitoring` run 39314816257 (service `alloy`) the login succeeded,
the job had `packages: write`, the layers were pushed, and then a blob `HEAD`
returned `401 Unauthorized` and the whole build was lost. The `GITHUB_TOKEN`
lifetime does not explain it; a stale BuildKit/registry auth context (or a
transient registry `401`) is the leading hypothesis. Rerunning repeats the full
queue wait and build.

## Contract

| Input | Type | Default | Meaning |
| --- | --- | --- | --- |
| `publish_mode` | string | `inline` | `inline` keeps the v1 behavior (BuildKit pushes from the exporter). `export-then-push` exports one OCI layout and publishes it separately. |
| `publish_auth_retries` | number | `3` | `export-then-push` only: maximum credential refreshes after HTTP `401` for the whole publication (1-5). |

No output, secret, or permission changes. The build job keeps exactly
`contents: read`, `packages: write`, `attestations: write`, `id-token: write`.

With `push: true` and `publish_mode: export-then-push` the build job:

1. builds once with SBOM and provenance and exports the image index, platform
   image, and attestation manifests to an OCI layout directory under
   `RUNNER_TEMP` (`type=oci,tar=false`); `steps.build.outputs.digest` is the
   digest of that index;
2. refreshes the registry login immediately before publishing
   (`docker/login-action`, same SHA pin as the initial login);
3. runs `scripts/container_release/push_oci_layout.py`, which:
   - refuses a layout whose root digest differs from the build digest and
     verifies every local blob against its sha256 before upload;
   - requests a fresh registry token before the first write;
   - pushes blobs (skipping blobs already present), child manifests by digest,
     then the candidate tag, byte-for-byte, so the published digest is the
     built digest and the SBOM/provenance attestation manifests are preserved;
   - on HTTP `401` only, refreshes the token and retries the same request, up
     to `publish_auth_retries` times for the whole publication, with
     exponential backoff (1, 2, 4 ... seconds, capped at 30);
   - verifies that the candidate tag resolves to the expected digest;
4. removes the OCI layout directory (also on failure);
5. continues with the unchanged gates: quarantine SBOM/provenance
   verification, exact-digest Trivy gate, promotion by digest with
   `verify_published_digest.py`, digest fragment, and the aggregate manifest.

The publisher uses only the Python standard library, never follows registry
redirects with credentials, never prints the credential, and allows plain HTTP
only for loopback test registries.

## Failure modes

| Situation | Behavior |
| --- | --- |
| Registry `401` during publication | Refresh token and retry, bounded by `publish_auth_retries` for the whole publication; a warning names each refresh. A `401` during a blob upload restarts that blob's upload session instead of reusing a session opened with the old credential. |
| Blob `HEAD` answers with a redirect | The blob is treated as present; redirects are never followed with credentials. |
| `401` persists after the bound | Publish step fails; nothing downstream runs; the candidate tag is not written. |
| `403`, `404` on upload, `5xx`, network error | Fail immediately without retry (not an auth staleness signal). |
| Layout root digest differs from the build digest | Fail before any registry call. |
| Missing or tampered local blob | Fail closed before the tag is written. |
| Registry reports another manifest digest, or the tag resolves to another digest | Fail closed. |
| Build succeeded, publication failed | Security decision, evidence upload, digest fragment, and gate steps are skipped (`steps.publish.outcome != 'failure'`), matching an inline build failure; the aggregate manifest is not produced. |
| Invalid `publish_mode` or `publish_auth_retries` | The `validate` job fails before any build. |

Operational notes:

- `export-then-push` needs runner disk for one uncompressed-index OCI layout per
  image (roughly the compressed image size) in `RUNNER_TEMP` while the job
  runs; it is deleted at the end of the job.
- Retries are cheap: blobs already accepted by the registry are skipped.
- `inline` mode is byte-for-byte unchanged apart from the `push` expression
  (`inputs.push && inputs.publish_mode == 'inline'`, equal to `inputs.push`
  when the default is used) and the added `steps.publish.outcome` guard, which
  is always satisfied when the publish step is skipped.

## Migration

Opt in per caller, ideally first on the slowest image:

```yaml
    uses: optimizr-tech/optimizr-actions/.github/workflows/_container-build-publish.yml@v1
    with:
      push: true
      publish_mode: export-then-push
      # publish_auth_retries: 3
```

No other caller change is required. The default stays `inline` under `v1`;
changing the default would need a separate decision after the opt-in mode has
production evidence.

## Rollback

- Caller: remove `publish_mode` (or set `inline`). No artifact or registry
  cleanup is needed; already published digests remain valid.
- Reusable: revert this change; callers that set `publish_mode` would then fail
  on an unknown input, so remove the input from callers first.

## Consumer inventory

Callers of `_container-build-publish.yml@v1` found on 2026-10-20 (GitHub code
search plus a direct scan of workflow directories). None sets `publish_mode`,
so all keep `inline` behavior until they opt in.

| Repository | Workflow |
| --- | --- |
| `optimizr-tech/optimizr-cdn` | `.github/workflows/delivery.yml` |
| `optimizr-tech/optimizr-corp-docs` | `.github/workflows/ci.yml` |
| `optimizr-tech/optimizr-infra-certbot` | `.github/workflows/ci.yml` |
| `optimizr-tech/optimizr-infra-keycloak` | `.github/workflows/ci.yml` |
| `optimizr-tech/optimizr-infra-nginx` | `.github/workflows/ci.yml` |
| `optimizr-tech/optimizr-infra-ops` | `.github/workflows/container-publish.yml` |
| `optimizr-tech/optimizr-monitoring` | `.github/workflows/deploy.yml`, `.github/workflows/publish-grafana-patched.yml` |
| `optimizr-tech/optimizr-payment` | `.github/workflows/ci.yml` |
| `optimizr-tech/optimizr-serve` | `.github/workflows/ci.yml` |

First candidate to opt in: `optimizr-monitoring` (`alloy` build, run
39314816257).
