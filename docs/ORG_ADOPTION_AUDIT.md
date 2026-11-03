# Organization Actions adoption audit

The scheduled public-repository workflow audits an explicit repository allowlist stored in `ORG_AUDIT_REPOSITORIES`. Access is limited by the installation/PAT behind `ORG_AUDIT_TOKEN`; repositories are queried through metadata and contents APIs and are never cloned.

The workflow runs `scripts/org_audit/combined.py`, which preserves every existing workflow rule and adds source-backed security-automation adoption signals.

Rules detect:

- portable callers still hosted by `optimizr-infra-ops`;
- the temporary semantic-release SHA;
- first-party executable references not using governed `@v1` (internal SHA
  pins are rejected);
- third-party actions not pinned to a 40-character SHA;
- write permissions requiring least-privilege review;
- CI/deploy triggers without path filters;
- potential self-hosted pull-request execution without a governed
  `self_hosted_mode` (`metadata-pr`/`ephemeral-pr`/`trusted-main`);
- duplicated badge, commitlint and PR-validation workflows;
- prohibited caller-level `[skip-tests]` guards (directive #159);
- hosted pull-request code validation in repositories that already run
  governed self-hosted jobs (directive #159);
- missing `.github/dependabot.yml` organization configuration;
- missing governed Dependabot native auto-merge caller;
- deployment-like workflows that do not call an approved VPS deploy reusable.

The event rule reads only direct event keys under the top-level `on:` block;
event names embedded in input descriptions or expressions are not triggers.
The permission rule reports root-level write grants and write grants on local
step jobs. A job-level grant on a reusable-workflow caller is part of that
caller contract and is not classified as a broad workflow permission. The PR
metadata validator detects byte sequences consistent with common mojibake,
while allowing valid Portuguese characters such as `ÃO` in explanatory text.

`combined.py` also runs `audit_functional_duplication`, which compares the
repository surface against the canonical capability catalog and detects
avoidable local reimplementation when the canonical reusable is not called
anywhere in the repository:

- local Compose model validation (`docker compose config`) without
  `_docker-compose-validate.yml@v1`;
- local Trivy/gitleaks/SBOM/dependency audit without `_security-gate.yml`,
  `_trivy-scan.yml`, `_sast-gate.yml`, `_dependency-policy.yml` or
  `_supply-chain-evidence.yml` at `@v1`;
- local Python uv/pytest/coverage runner without `_python-uv-test.yml@v1`;
- local ShellCheck/actionlint/Ruff/mypy without `_static-lint.yml@v1`;
- local quality gate without `_quality-gate.yml@v1` or
  `_quality-gate-pr.yml@v1`;
- permanent `skip: true` on mandatory canonical validation;
- direct execution of `optimizr-actions/scripts/**` from a checkout instead
  of calling reusables (loses reusable outputs and evidence);
- canonical reusables that support self-hosted runners called only from
  hosted jobs in a repository that already runs self-hosted jobs, using the
  runner matrix published in `catalog/capabilities.json`.

A local implementation is treated as an avoidable reimplementation only when
the canonical reusable exists and is not called by the repository. A
product-specific extension is legitimate; consumers declare it in their
`docs/adoption.md` with a reason, and the auditor does not parse or guess it.

The Dependabot file itself is optional to GitHub security updates, but Optimizr-managed repositories use it as a source-controlled adoption marker and to declare supported package ecosystems. Repository security settings that the contents API cannot prove remain manual organization controls and are not guessed by the auditor.

The artifact created in the public repository replaces private repository names with deterministic aliases and stores no source snippets, secret names, environment values, hosts or deployment paths. The private issue job runs only after the public job succeeds, including successful upload of the redacted artifact; it then reruns the audit and updates a marker-delimited report in a private repository using `ORG_AUDIT_ISSUE_REF` and a separately scoped issue token. The private report includes the current GitHub Actions run link so the issue is traceable to the run and its sanitized artifact. Both jobs validate their configuration before making API calls; a missing value fails the workflow and is never reported as a successful or skipped audit.

Required secrets:

- `ORG_AUDIT_REPOSITORIES`: newline/comma-separated `owner/name` allowlist;
- `ORG_AUDIT_TOKEN`: read-only metadata/contents access to those repositories;
- `ORG_AUDIT_ISSUE_REF`: `owner/private-repo#123`;
- `ORG_AUDIT_ISSUE_TOKEN`: issue-write access only to the private report repository.

All four values are required for a successful scheduled or manual run. A human owner must choose the approved organization or repository secret scope, populate the allowlist and tokens, and grant only the documented repository and issue permissions. This code change does not configure secrets or validate their live availability. Never print secret values in logs; rotate the tokens without changing the allowlist format.

The workflow rejects blank or whitespace-only configuration before making API calls. The combined CLI independently rejects an empty normalized repository list, blank tokens, and a missing issue reference/token when an issue update was requested. It also fails if either public report file is absent or empty, if the upload action finds no files, or if the uploaded artifact ID or digest is missing. The private issue job is gated on the public job succeeding, so any of those failures prevents the issue update.

Keep issue #167 open until a human-authorized `workflow_dispatch` run completes, the sanitized public artifact is downloadable, and the private issue shows the corresponding run link. A local test or configured secret alone is not operational recovery evidence.

The auditor never edits consumer repositories, enables Dependabot settings, creates pull requests, merges changes or receives production secrets.
