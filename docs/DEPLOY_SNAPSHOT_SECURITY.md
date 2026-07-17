# Deploy snapshot security

The VPS deploy reusables create rollback archives under
`/opt/optimizr/backups/<service>/deploys`.

- The snapshot directory is mode `0750` and each archive is mode `0600`.
- Archives exclude `.env`, `.env.*`, and private key formats (`.pem`, `.key`,
  `.p12`, `.pfx`).
- A successful backup message is emitted only after the archive is written and
  its mode is restricted.

Snapshots are for non-sensitive code and configuration rollback. Runtime
secrets remain on the host and must not be archived by deploy workflows.
