# Provider-neutral delivery request

The first delivery-executor slice defines a small, provider-neutral request
contract. It is deliberately separate from GitHub Actions context and from
the current VPS deploy workflows. It validates identity and source inputs but
does not checkout code, sync files, invoke Docker, mutate a host, or deploy.

## Request schema

```json
{
  "repository": "owner/service",
  "service": "service",
  "candidate_sha": "0123456789abcdef0123456789abcdef01234567",
  "trusted_ref": "refs/heads/main",
  "compose_file": "docker-compose.yml",
  "container_name": "service",
  "adapter": "github-actions",
  "reason": "reviewed main promotion"
}
```

The request is secret-free and accepts only:

- a bounded `owner/service` repository identity;
- a lowercase, complete 40-character commit SHA;
- a trusted `refs/heads/...` or `refs/tags/...` ref, never a pull-request ref;
- a relative POSIX Compose YAML path without traversal;
- bounded service/container identifiers;
- one of the protected adapter identities: `github-actions`, `gitlab-ci`,
  `ansible`, or `manual`;
- an optional bounded reason with no secret-like assignments.

Unknown fields are rejected so a later adapter cannot silently introduce
authorization or credential inputs into the shared contract.

## CLI

Validate a request file below an explicit root and emit its canonical JSON:

```bash
python -m scripts.delivery.request --request artifacts/delivery-request.json --root artifacts
```

The CLI prints only the canonical request. Errors are written to stderr and
return a non-zero status. Adapters can consume this interface without relying
on `${{ github.* }}`, `GITHUB_WORKSPACE`, or GitHub APIs.

## Exact-SHA checkout

The checkout primitive is adapter-neutral and receives a network Git remote
resolved from an allowlisted repository identity. It creates a new destination
only below an explicit root, initializes a clean repository, fetches the
trusted ref without tags, verifies that the candidate is a commit reachable
from `FETCH_HEAD`, checks it out detached, and confirms `git rev-parse HEAD`
equals the requested SHA.

Git is invoked with an argument array and captured output; no shell is used and
Git output or remote credentials are not returned in `CheckoutResult`. Unsafe
remotes, existing destinations, symlink components, root escapes, fetch
failures, ancestry failures and HEAD mismatches fail closed. A destination
created by a failed attempt is removed when cleanup is possible.

This primitive prepares source only. It does not synchronize into a deploy
directory, preserve runtime state, run security gates or change a service.

## Next slices

This contract is not a deploy implementation and must not be wired to
production execution by itself. Follow-up PRs must separately add and verify:

1. snapshot and dry-run synchronization that preserves runtime state;
2. security/Compose/health gates and sanitized manifest output;
3. GitHub, GitLab, Ansible, and manual adapters;
4. canary and rollback evidence before any consumer migration.

Each slice must preserve the existing VPS reusable behavior until a reviewed
adapter proves parity.
