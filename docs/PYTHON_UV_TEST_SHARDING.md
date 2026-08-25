# Python UV test sharding

`_python-uv-test.yml` keeps its existing single-job behavior by default. A
consumer opts in by setting `shard_count` to a value from `2` to `8`.

```yaml
uses: optimizr-tech/optimizr-actions/.github/workflows/_python-uv-test.yml@v1
with:
  shard_count: 2
  max_parallel: 1
  coverage_min: 96
  coverage_artifact_prefix: backend-coverage
  shard_distribution: count
```

## Contract

- `shard_count: 1` uses the legacy `test` or `test-integration` job. Existing
  caller inputs, permissions, coverage threshold and artifact behavior remain
  unchanged.
- Values above eight are rejected. `max_parallel` must be between `1` and
  `shard_count`; start with `1` on shared self-hosted capacity and raise it
  only after measuring service and database contention.
- Matrix indices are stable and one-based (`1..shard_count`). The strategy
  uses `fail-fast: false`, so a failure does not cancel the remaining shards.
- `count` uses `pytest-split` with an empty duration map, which produces an
  even fallback distribution. `duration` requires a committed duration file
  at `shard_durations_path`; a missing file fails closed instead of silently
  reverting to count distribution.
- The reusable workflow installs the exact `pytest_split_version` only in
  sharded jobs. The consumer does not need a VPS token or a mutable global
  Python installation.

## Services and retries

The `serve` integration matrix declares PostgreSQL, Redis and RabbitMQ in each
matrix job. GitHub's job-scoped service namespace gives every shard its own
containers, database and `localhost` ports. This does not mean that one
self-hosted runner can execute two jobs at once; `max_parallel` still must be
chosen against the actual runner fleet and container memory.

There are no automatic test retries or retry loop. A failed shard remains failed, all other
shards are allowed to finish, and the aggregate job fails. A rerun must rerun
the failed workflow/job through GitHub Actions so the complete matrix and
coverage evidence remain attributable to the same run.

## Coverage and artifacts

Each shard exports `COVERAGE_FILE=.coverage.shard-N` and uploads an artifact
named `<coverage_artifact_prefix>-shard-N`. The aggregate job requires exactly
`shard_count` raw coverage files, runs `coverage combine`, generates the XML
and JSON reports, and applies the original `coverage_min` threshold once to
the combined data. Per-shard threshold enforcement is disabled only to avoid
rejecting partial coverage; the aggregate threshold is never reduced.

The aggregate artifact is named `<coverage_artifact_prefix>`. Existing
`upload_artifact_name` and `upload_artifact_paths` are still used unchanged
when `shard_count` is `1`; in sharded mode, `coverage_artifact_prefix` controls
the internal and final names so files cannot collide.

## Cache and migration guidance

`setup-uv` keeps using its lockfile-based cache. The normal test shards and the
aggregate job each run `uv sync`, so a cache hit is scoped by the consumer's
`uv.lock`, Python version and dependency metadata. The temporary
`pytest-split` overlay is version-pinned and should not be treated as a
replacement for the consumer lockfile.

Adopt in this order:

1. Merge and validate the `optimizr-actions` contract.
2. Add `shard_count`, `max_parallel: 1`, and `coverage_artifact_prefix` to the
   consumer's reusable call; keep its existing coverage minimum.
3. Confirm all shards execute, the aggregate artifact is present, and the
   combined coverage is at least the prior single-job result.
4. Only then evaluate a higher `max_parallel` or a committed duration file.
