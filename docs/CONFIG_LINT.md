# Reusable configuration lint

`_config-lint.yml` runs Hadolint against tracked `Dockerfile*` files and applies
Compose policy checks to tracked Compose YAML. It uses only the caller's
repository checkout and a read-only permission contract.

```yaml
jobs:
  config-lint:
    uses: optimizr-tech/optimizr-actions/.github/workflows/_config-lint.yml@v1
    with:
      policy_file: .github/config-lint-policy.json
      compose_files: "docker-compose.yml docker-compose.dev.yml"
```

Copy `templates/config-lint-policy.json` into the consumer repository and
review its entries there. `compose_files` accepts space-separated repository
relative globs; when empty, tracked `compose*.yaml`, `compose*.yml`,
`docker-compose*.yaml`, and `docker-compose*.yml` files are discovered.

## Policy contract

The version-1 JSON policy contains:

- `fail_on`: Hadolint severities that fail the job (`error`, `warning`, `info`,
  or `style`);
- `compose.allowed_published_ports`: host port numbers permitted for published
  Compose ports;
- `compose.require_read_only` and `compose.require_cap_drop`: service names
  requiring `read_only: true` and `cap_drop: [ALL]`;
- `compose.severities`: optional severity per Compose rule. Unspecified rules
  use `error`;
- `exceptions`: exact rule exceptions, each with a `reason` and ISO `expires`
  date. Optional `path` and `service` fields narrow the exception. Hadolint
  rules use names such as `hadolint:DL3008`; Compose rules are `privileged`,
  `host-network`, `published-port`, `image-digest`, `read-only`, and `cap-drop`.

Expired or malformed exceptions and invalid policy values fail closed. Findings
produce GitHub annotations and a job summary; findings at a configured blocking
severity fail the job. Compose validation uses `docker compose config --format
json`; unavailable Docker/Compose, invalid Compose, missing selected files, or
invalid policy also fail. A repository with no tracked Dockerfiles or Compose
files gets a notice for that absent input category.

The Hadolint image is pinned to the verified multi-platform Docker Hub manifest
`hadolint/hadolint@sha256:32dac94127fd60b7b7e3fbfc65e1383b9b5e25c9bfd7b8536de7a539fe68a12d`.
The workflow needs `contents: read`; it declares no secrets or outputs. Third
party checkout is pinned to an immutable action commit.

## Rollback

Remove the caller's reusable-workflow job or pin its `uses:` reference to the
previous Actions commit. No `v1` tag movement is part of adoption. Keep the
consumer policy file with the caller so its exception rationale and expiry
remain reviewable.
