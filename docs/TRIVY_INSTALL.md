# Governed Trivy installation

Every Optimizr action that runs Trivy (`security-gate`, `dependency-policy`,
`supply-chain-evidence`, `trivy-scan`) installs the binary with
`scripts/security_gate/install-trivy.sh` instead of `aquasecurity/setup-trivy`.

## Why

`setup-trivy` runs the upstream `contrib/install.sh`, which downloads the
release tarball with a single `curl` and no timeout or retry. On 2026-10-20 the
`optimizr-payment` run `39466913367` (job `security / Dependency and license
policy`) hung for about five minutes after `aquasecurity/trivy info found
version: 0.74.0` and failed with `Process completed with exit code 28` (curl
operation timeout). One network blip turned the whole security suite red on
`main`. Its `actions/cache` binary cache also never hit on self-hosted runners,
because the cache path is unique per run, so every job downloaded the tarball.

## Contract

Caller inputs, outputs and permissions are unchanged under `v1`:

- `trivy_version` keeps its meaning and default (`v0.74.0`); `0.74.0` without
  the `v` prefix is also accepted.
- The binary is still installed below the per-job directory
  `${{ runner.temp }}/optimizr-trivy/<run_id>-<run_attempt>-<job>/trivy-bin`
  and that directory is appended to `GITHUB_PATH`, so concurrent jobs sharing
  a runner user never replace an executable in use (`ETXTBSY`).
- The tarball's `contrib/` templates are installed next to the binary, as
  before.
- The vulnerability database cache (`trivy-cache.sh`) is not affected.

## Behavior

1. Validate the version (exact `vMAJOR.MINOR.PATCH`) and the runner platform
   (Linux `x86_64` or `aarch64`).
2. Resolve the expected SHA-256 digest of
   `trivy_<version>_Linux-<arch>.tar.gz`:
   - from the reviewed pins in `scripts/security_gate/trivy-checksums.txt`
     (currently `v0.74.0` and `v0.70.0`, `Linux-64bit` and `Linux-ARM64`);
   - for a version that is not pinned, from the upstream release
     `trivy_<version>_checksums.txt`, which is the trust model the upstream
     installer used. The job prints an `Unpinned Trivy version` warning.
3. Reuse `${XDG_CACHE_HOME:-$HOME/.cache}/optimizr-security-gate/trivy-binaries/<asset>`
   when it exists and its digest matches. A cached tarball that does not match
   (or an unpinned tarball without its recorded digest) is deleted and
   downloaded again. On ephemeral hosted runners the cache is simply empty.
4. Otherwise download from
   `https://github.com/aquasecurity/trivy/releases/download/<tag>/` with
   `curl --fail --location --proto =https --proto-redir =https --tlsv1.2`,
   a connect timeout, a total timeout and a low-speed abort, retrying with
   exponential backoff (5 s, 10 s, 20 s, capped at 60 s).
5. Verify the downloaded digest, extract into a staging directory, and require
   `trivy --version` to report the requested version.
6. Only then store the tarball in the runner cache (atomic rename), move the
   staging directory into place and append it to `GITHUB_PATH`.

Tuning, for runner operators only (defaults shown; values outside the bounds
fail with exit code 2):

| Variable | Default | Bounds |
| --- | --- | --- |
| `OPTIMIZR_TRIVY_DOWNLOAD_ATTEMPTS` | 4 | 1–10 |
| `OPTIMIZR_TRIVY_RETRY_DELAY_SECONDS` | 5 | 0–60 |
| `OPTIMIZR_TRIVY_CONNECT_TIMEOUT_SECONDS` | 20 | 1–120 |
| `OPTIMIZR_TRIVY_MAX_TIME_SECONDS` | 180 | 10–1800 |

With the defaults a job that cannot reach GitHub fails after at most about
12.5 minutes instead of hanging on one stalled connection.

## Failure modes

All failures are closed: no binary is added to `PATH` and the step fails.

| Exit | Annotation | Cause | Action |
| --- | --- | --- | --- |
| 2 | `trivy_version must be an exact release` | empty, `latest`, partial or path-like version | pass an exact version such as `v0.74.0` |
| 2 | `supports Linux runners only` / `unsupported runner architecture` | non-Linux or unsupported CPU | use a Linux `x86_64`/`aarch64` runner |
| 2 | `... is required on the runner` | `curl`, `tar` or `sha256sum` missing | provision the runner |
| 2 | `must not be a symbolic link` / `not owned by the runner user` | unsafe binary cache directory | fix ownership; remove the link |
| 3 | `checksum mismatch` / `no SHA-256 digest is available` | tampered or truncated artifact, or a version missing from the release checksums | investigate; do not override the pin |
| 3 | `reports an unexpected version` | archive does not contain the requested release | investigate the release asset |
| 4 | `could not download ... after N attempts (last curl exit code C)` | network outage longer than the retry budget (`exit code 28` is a timeout) | re-run once GitHub downloads recover |

A cache that fails verification is never a job failure by itself: it is
discarded and the tarball is downloaded and verified again.

## Adding a Trivy version

1. Download `trivy_<version>_checksums.txt` and the `Linux-64bit` and
   `Linux-ARM64` tarballs from the upstream release.
2. Confirm `sha256sum` of each tarball matches the checksums file (verify the
   `.sigstore.json` bundle with `cosign` when available).
3. Add both lines to `scripts/security_gate/trivy-checksums.txt` and extend the
   contract test if a consumer depends on the version.

## Consumer inventory

Inventoried on 2026-10-20 with GitHub code search (`org:optimizr-tech`,
`.github/workflows`). Every caller reaches the installer through `@v1`
reusable workflows (`_security-suite`, `_container-build-publish`,
`_vps-self-hosted-deploy`, `_vps-monorepo-deploy`, `_validation-gate`,
`_trivy-scan`, `_dependency-policy`) or the `security-gate` action directly:

- `optimizr-cdn`, `optimizr-corp-docs`, `optimizr-domjuan-dbaas`,
  `optimizr-infra-certbot`, `optimizr-infra-keycloak`, `optimizr-infra-nginx`,
  `optimizr-infra-ops`, `optimizr-marketing-site`, `optimizr-monitoring`,
  `optimizr-payment`, `optimizr-serve`.

Versions passed explicitly: `${{ vars.TRIVY_VERSION || 'v0.74.0' }}`
(`optimizr-payment`, `optimizr-infra-keycloak`, `optimizr-monitoring`,
`optimizr-serve`) and `v0.70.0` (`optimizr-infra-certbot`
`image-security-preflight.yml`). Both are pinned. The organization variable
value could not be read without `admin:org`; if it names another version, the
job keeps working through the release-checksums fallback with a warning. No
caller passes an empty version or `latest`. Searches for `_security-gate.yml`
and `_container-candidate-promote.yml` were rate limited; they are internal
callees of the workflows above.

## Rollback

Revert the commit that introduced `install-trivy.sh` (it restores the pinned
`aquasecurity/setup-trivy@81e514348e19b6112ce2a7e3ecbafe19c1e1f567` step in the
four actions) and move `v1` only through the normal release validation. The
runner cache directory `~/.cache/optimizr-security-gate/trivy-binaries` is
unused after a rollback and may be deleted.
