# Self-hosted resource policy

Reusable workflows must remain safe on a finite self-hosted Docker host. The
policy is a default budget, not a replacement for measuring a larger runner.

## Defaults

- Container image builds use `max_parallel: 1` by default and reject values
  outside `1..8`.
- Python integration services are bounded per job: PostgreSQL 512 MiB/0.50
  CPU/128 PIDs, Redis 256 MiB/0.25 CPU/64 PIDs, and RabbitMQ 1 GiB/0.50
  CPU/128 PIDs. RabbitMQ keeps its proven 1 GiB compatibility floor.
- Callers may opt into more parallelism only after proving that their runner
  has enough CPU, memory, and isolated Docker capacity.

The notebook runner does not invoke the host-wide prune action. Its cleanup is
performed by the host runner guard and by each caller's scoped Compose teardown.
The two trusted VPS deploy reusables invoke the canonical prune action with
`allow_global_prune: true` explicitly because that daemon is shared; any other
consumer gets workspace cleanup only unless it makes the same reviewed opt-in.

## Actions cache on persistent self-hosted runners

The local self-hosted pool keeps tool caches on the host: `UV_CACHE_DIR` and
the npm cache directory point to persistent paths. On those runners the
GitHub Actions cache only adds work. Saving it compresses the whole persistent
directory, and restoring it downloads and extracts a copy of data already on
disk. On 2026-11-12, `setup-uv` spent 12.5 minutes in `tar -z` over the
persistent uv cache before the job was cancelled. In another job, `setup-node`
restored a 346 MB npm cache into the persistent `~/.npm` at 1.5-3 MB/s. The
network itself was healthy (25 MB/s down, 11 MB/s up); the saturated host CPU
made compression and extraction the bottleneck.

Rules:

- `astral-sh/setup-uv` uses `enable-cache: auto` (GitHub-hosted only) or
  `false`. Never `true`.
- `actions/setup-node` steps without a job-local store set
  `package-manager-cache: ${{ runner.environment == 'github-hosted' }}`. An
  explicit npm cache uses
  `cache: ${{ runner.environment == 'github-hosted' && 'npm' || '' }}`.
- Steps that restore a job-local pnpm store (`runner.temp`) keep `cache: pnpm`.
  That store is not persistent, so the cache still saves downloads.

`tests/test_self_hosted_cache_contract.py` enforces these rules.

## Migration

Callers that consume `_container-build-publish.yml` may set `max_parallel`.
Callers that consume `_python-uv-test.yml` may keep the existing default or
choose a bounded `max_parallel` no greater than their shard count. Start at
`1` on the notebook Docker Desktop/WSL runner.
