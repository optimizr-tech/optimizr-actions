# Deploy snapshot security

The VPS deploy reusables create rollback archives under
`/opt/optimizr/backups/<service>/deploys`.

- The snapshot directory is mode `0750` and each archive is mode `0600`.
- Archives exclude `.env`, `.env.*`, and private key formats (`.pem`, `.key`,
  `.p12`, `.pfx`).
- Snapshots are only created when the deploy `rsync --dry-run --checksum`
  reports a real change to apply.
- The VPS deploy reusable uses content checksums for both change detection and
  synchronization, then performs a checksum-based post-sync parity check
  before rollout. Any differing entry fails the deploy closed; only the
  sanitized difference count is logged.
- Deployments are serialized per service, regardless of the triggering ref, so
  two refs cannot race while synchronizing the same host directory.
- Retention is automatic and defaults to `count=10`, `days=30`, and
  `max_total_bytes=2147483648` unless a consumer overrides the additive
  deploy-snapshot inputs.
- The retention helper only touches direct `*.tar.gz` files in the expected
  snapshot root and always preserves the newest snapshot.
- A successful backup message is emitted only after the archive is written and
  its mode is restricted.

Snapshots are for non-sensitive code and configuration rollback. Runtime
secrets remain on the host and must not be archived by deploy workflows.
