# Recovering the `v1` compatibility tag

The normal `move-v1` path remains on the restricted `local-docker-owner` runner
group. It validates the trusted `main` revision before moving the tag. A runner
outage never triggers an automatic fallback.

## Manual GitHub-hosted recovery

Use this only when the most recent InfraOps queue-watch run or the organization
runner inventory confirms that `local-docker-owner` has no online runner that
can accept this workflow. Other `local-docker` runners are not automatically
eligible for this restricted workflow.

1. Inspect the current evidence and confirm that the owner group is unavailable.
   Do not use a stale queue-watch result as proof of a current outage.
2. Use a manual `workflow_dispatch` to run **Validate and move v1 compatibility tag** from `main`.
3. Select `github-hosted-recovery`, confirm the owner-runner outage, and provide
   either the InfraOps queue-watch run URL or organization runner-inventory URL
   as `outage_evidence_url`.
4. Review the run summary and all three jobs. The validation job must pass before
   the tag job can run. The tag job independently checks that `main` still
   equals the validated SHA; if `main` advanced, it fails closed.

The workflow validates the evidence URL's host and InfraOps Actions-run path, but
does not fetch or verify the linked private run. The operator making the manual
dispatch is attesting that the linked queue-watch or runner-inventory evidence
shows the restricted owner group is offline. This avoids adding a cross-repository
token or permission. The supplied URL is visible in the workflow log.

The fallback runs the same trusted-main validation and tag-move jobs on
`ubuntu-latest`. It does not check out PR code and does not use
`vps-org-release` or `container-build`: the former is on the production VPS, and
the latter shares the local WSL/Docker host failure domain and has a separate
publishing purpose. The fallback does not change secrets, tokens, permissions,
runner groups, or the normal push route.

## Cost and rollback

As of 2026-10-21, `optimizr-actions` is public, so standard GitHub-hosted runners
are free for this workflow. If the repository becomes private, `ubuntu-latest`
uses included minutes first; beyond the allowance the current standard Linux
rate is $0.006 per minute. The three serialized jobs have timeout caps of 5, 10,
and 5 minutes, so one fully timed-out recovery run would cost at most $0.12
beyond included minutes, with actual usage normally lower.

To roll back this capability, revert the workflow and this document. Until that
revert is merged, the default `local-docker` route remains unchanged. A failed
recovery run must not be followed by a manual tag move; diagnose it and use a
new reviewed dispatch only after confirming the current `main` state.
