# Portable local validation

Local-first validation is an organization capability: a consumer repository
runs its authoritative gate locally and keeps evidence bound to its commit.
This repository supplies the portable runner and versioned presets; it never
receives consumer secrets or production configuration.

## Fiscal preset

The `presets/fiscal.json` contract requires Python 3.14 and real PostgreSQL,
RabbitMQ, MinIO, and Keycloak services. Redis is forbidden unless the consumer
records a justified override. The Fiscal repository owns its Compose lifecycle,
database roles, RLS assertions, and credentials.

Run a consumer gate without a shell string, supplying only service identities
and versions (never connection strings or credentials):

```powershell
python -m scripts.local_validation.run `
  --preset presets/fiscal.json `
  --evidence artifacts/local-validation.json `
  --service postgres=18 `
  --service rabbitmq=4.3 `
  --service minio=RELEASE.2026 `
  --service keycloak=26 `
  -- uv run pytest
```

The JSON evidence records repository SHA, clean-worktree state, tool versions,
lockfile checksum, declared real-service versions, command exit codes and
unresolved gaps. It intentionally never captures environment values, so
credentials and tenant data must not be passed to it.

Required missing services, a dirty worktree (unless explicitly allowed for
development), a missing command, and a failed command all fail closed.
