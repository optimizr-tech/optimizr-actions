# PostgreSQL major-version logical migration reusable

`_postgres-major-logical-migration.yml` prepares a fresh target Docker volume by creating a custom-format database dump, preserving cluster-global roles and memberships, restoring both into an isolated target cluster, and comparing a consumer-supplied deterministic fingerprint on source and target.

The reusable is intentionally **not a cutover workflow**. It never changes a consumer Compose file, starts the application against the target, removes a Docker volume, or replaces the source cluster. Consumers own the separately reviewed cutover and rollback.

## Safety contract

- Runs only on a trusted self-hosted runner and uses the protected `production` environment.
- Accepts either an explicit source container or resolves it from a deployed Compose directory and service.
- Resolves and validates the physical source volume at the declared mount path when its Docker name is not fixed.
- Requires source and target major versions and volume names to differ.
- Requires the target image to be pinned with `@sha256:`.
- Refuses a target volume that is attached or non-empty.
- Quiesces declared application containers only while the logical backups and source fingerprint are captured, then restarts them through an EXIT trap.
- Uses `pg_dump -Fc` for the database and `pg_dumpall --globals-only` for roles, attributes and memberships.
- Validates the archive with target-version `pg_restore --list`.
- Keeps database/global backups on the trusted host with mode `0600`; they are never uploaded as artifacts.
- Restores globals and database into an isolated temporary target container.
- Compares only SHA-256 fingerprints in logs; query results and credentials are not printed.
- Writes a sanitized migration marker to the target volume and uploads only that marker as workflow evidence.
- Preserves the source volume and does not perform a production cutover.

## Consumer with explicit Docker names

```yaml
jobs:
  migrate-postgres:
    uses: optimizr-tech/optimizr-actions/.github/workflows/_postgres-major-logical-migration.yml@v1
    with:
      service_name: example-service
      runner_label: example
      source_container: example-postgres
      quiesce_containers: example-api
      source_volume: example_pgdata
      source_mount_path: /var/lib/postgresql/data
      source_major: "16"
      target_volume: example_pgdata_v18
      target_mount_path: /var/lib/postgresql
      target_pgdata: /var/lib/postgresql/18/docker
      target_major: "18"
      target_image: postgres:18.4-bookworm@sha256:<reviewed-digest>
      database_name: example
      database_user: example
      verification_sql: >-
        SELECT json_build_object('tables', count(*))::text
        FROM information_schema.tables
        WHERE table_schema = 'public';
    secrets:
      database_password: ${{ secrets.POSTGRES_PASSWORD }}
```

## Consumer resolved through deployed Compose

Use this mode when Compose does not declare stable `container_name` or volume `name` values:

```yaml
with:
  source_compose_directory: /opt/optimizr/example
  source_compose_file: docker-compose.yml
  source_service: postgres
  source_mount_path: /var/lib/postgresql/data
```

The reusable calls `docker compose ps -q` in the deployed directory and resolves the Docker volume attached at `source_mount_path`. A declared `source_volume` remains optional as an extra assertion.

A consumer must add a second, independently reviewed cutover PR only after the migration workflow has produced successful evidence.
