# Repository Validation Routing Design

## Goal

Make repository-owned validation execute reliably for reusable calls originating from `push`, `pull_request`, or `workflow_dispatch`, while keeping protected billing-emergency dispatch in the private consumer repository.

## Decisions

- `_repository-validation.yml` is a call-only reusable workflow. It never checks `github.event_name` because the called workflow inherits the caller event name.
- Manual emergency dispatch is split into a consumer caller template and `_repository-validation-emergency.yml`.
- The emergency reusable owns the protected Environment and requires a self-hosted runner plus trusted-ref validation.
- Both reusables expose `result`, `validated_sha`, and `evidence_path` outputs.
- Consumers continue referencing the floating `@v1` compatibility tag. Exact SHAs identify the validated consumer commit and the resolved workflow implementation in evidence; they do not freeze `v1`.
- The public `optimizr-actions` repository does not interpret `[skip-tests]`.

## Security boundaries

- No `pull_request_target` execution.
- No inherited secrets.
- Candidate checkout uses an exact SHA and `persist-credentials: false`.
- Persistent self-hosted runners cannot disable trusted-ref validation.
- The manual template accepts only bounded typed inputs, never arbitrary shell source.

## Failure behavior

A missing, skipped, or failing repository command cannot produce a successful reusable result. Evidence upload remains `always()` and missing evidence is an error.

## Testing

Static contract tests prove trigger separation, absence of event-name filters, protected emergency execution, exact-SHA outputs, read-only permissions, and argv-safe execution.
