# Controlled action and tool pins

`optimizr-actions` owns the portable defaults for the tools its reusable
workflows install. Third-party GitHub Actions remain pinned to immutable commit
SHAs; a tool version input controls the installed binary, not the action pin.

For `_container-build-publish.yml`, `security_trivy_version` defaults to
`v0.74.0`. Callers may pass `${{ vars.TRIVY_VERSION || 'v0.74.0' }}` explicitly
when they follow the organization variable. A missing organization variable must
not produce an empty version in forks or pull requests. An explicit caller input
continues to override the reusable default.

Changing the Trivy binary can change vulnerability findings and exception
fingerprints. Before adopting this default in a consumer, run its real image
publish/security gate on the runner, review the raw and blocking reports, and
revalidate any exact exceptions. A green contract test here is not consumer
publish evidence. If a regression requires rollback, pass the previously
validated version explicitly from the consumer while investigating; do not
weaken the gate or move the floating `v1` tag without release validation.
