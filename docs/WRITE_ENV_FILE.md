# Atomic environment-file writer

The `write-env-file` composite writes a Docker Compose compatible `.env` file from a versioned JSON schema committed by the consumer. Values come from the job environment; secret values are never action inputs, logs, hashes, or evidence fields.

```json
{
  "version": 1,
  "entries": [
    {"key": "DATABASE_PASSWORD", "env": "DATABASE_PASSWORD", "required": true, "secret": true},
    {"key": "APP_ENV", "literal": "production", "secret": false},
    {"key": "LOG_LEVEL", "env": "LOG_LEVEL", "required": false, "default": "INFO", "secret": false}
  ]
}
```

```yaml
- name: Write production environment
  uses: optimizr-tech/optimizr-actions/.github/actions/write-env-file@v1
  env:
    DATABASE_PASSWORD: ${{ secrets.DATABASE_PASSWORD }}
    LOG_LEVEL: ${{ vars.LOG_LEVEL }}
  with:
    schema_path: .github/deploy/environment.json
    allowed_root: /opt/optimizr/example
    destination: /opt/optimizr/example/.env
```

The caller remains responsible for creating and owning `allowed_root`. The writer rejects traversal and symlinks, creates a temporary file in the destination directory, flushes it, sets the requested restricted mode, and atomically promotes it. Evidence contains only destination basename, mode, key names/hashes, source class and presence.

Rollback by restoring the prior inline writer while preserving atomic replacement, redaction, `$` escaping and restrictive permissions.
