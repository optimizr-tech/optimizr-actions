# Owner metadata runner authorization

The repository PR caller uses `_pr-metadata.yml@v1`, matching the reusable
reference authorized by the restricted `local-docker-owner` group. The `v1`
contract supports `metadata-pr` on `pull_request_target`. A relative reusable
reference resolves with the caller revision; it does not become the authorized
`refs/tags/v1` reference merely because both revisions contain the same code.

This fixes routing without adding a runner or expanding group/repository
permissions. The workflow retains a read-only token, no checkout of candidate
code and no inherited secrets. Full candidate tests run locally; the existing
trusted-main publication pipeline validates the exact merged SHA.

The group is available only to this repository. Consumers of portable Actions
contracts use runners available in their own caller context, not this owner
runner. Group access is scheduling policy, not host or Docker isolation.

## Precheck and validation

Before merging, verify the published `v1` metadata contract accepts
`pull_request_target` and that the administrator still authorizes its full
workflow path at `refs/tags/v1`. Test the caller contract, event guards and
absence of candidate execution locally. Check the group and queue read-only;
an online idle runner alone does not establish workflow eligibility.

The current base caller controls PR checks. This source correction cannot
repair its own queued check before it is present on the trusted default
branch. The owner must review that bootstrap blocker explicitly; do not
disable protections, use hosted, or widen the group to arbitrary workflows.
After an approved merge, verify the next natural metadata event completes on
the authorized group. No rerun or runtime change is part of this source patch.

## Rollback

Revert only to a previously authorized and compatible reference. Restoring the
relative main reference without corresponding reviewed authorization restores
the queue failure. If the published contract loses compatibility, stop and
review its publication/authorization rather than falling back to hosted or a
production runner. Merging this repository can trigger the existing `v1`
publication pipeline; merge/publication requires separate owner approval.
