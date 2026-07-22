# Organization Actions adoption audit

The scheduled public-repository workflow audits an explicit repository allowlist stored in `ORG_AUDIT_REPOSITORIES`. Access is limited by the installation/PAT behind `ORG_AUDIT_TOKEN`; repositories are queried through metadata and contents APIs and are never cloned.

The workflow runs `scripts/org_audit/combined.py`, which preserves every existing workflow rule and adds source-backed security-automation adoption signals.

Rules detect:

- portable callers still hosted by `optimizr-infra-ops`;
- the temporary semantic-release SHA;
- first-party references not using governed `@v1`;
- third-party actions not pinned to a 40-character SHA;
- write permissions requiring least-privilege review;
- CI/deploy triggers without path filters;
- potential self-hosted pull-request execution;
- duplicated badge, commitlint and PR-validation workflows;
- canonical PR-validation callers missing the caller-level `[skip-tests]`
  billing guard;
- missing `.github/dependabot.yml` organization configuration;
- missing governed Dependabot native auto-merge caller;
- deployment-like workflows that do not call an approved VPS deploy reusable.

The Dependabot file itself is optional to GitHub security updates, but Optimizr-managed repositories use it as a source-controlled adoption marker and to declare supported package ecosystems. Repository security settings that the contents API cannot prove remain manual organization controls and are not guessed by the auditor.

The artifact created in the public repository replaces private repository names with deterministic aliases and stores no source snippets, secret names, environment values, hosts or deployment paths. An optional second job reruns the audit and updates a marker-delimited report in a private repository using `ORG_AUDIT_ISSUE_REF` and a separately scoped issue token.

Required secrets:

- `ORG_AUDIT_REPOSITORIES`: newline/comma-separated `owner/name` allowlist;
- `ORG_AUDIT_TOKEN`: read-only metadata/contents access to those repositories;
- optional `ORG_AUDIT_ISSUE_REF`: `owner/private-repo#123`;
- optional `ORG_AUDIT_ISSUE_TOKEN`: issue-write access only to the private report repository.

The auditor never edits consumer repositories, enables Dependabot settings, creates pull requests, merges changes or receives production secrets.
