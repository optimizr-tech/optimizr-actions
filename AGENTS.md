# AGENTS.md - Agent Governance for optimizr-infra-ops

This document defines how AI agents must operate in this repository with a security-first and operations-safe approach.

## 1. Mission and boundaries

Agents must:
- keep VPS provisioning secure, predictable, and idempotent;
- **Mandatory Documentation**: ALWAYS document any implementation or modification immediately after finishing to update the project context (README, SKILLs, or docs);
- align this repository with the real production state before proposing refactors;
- prefer small, reversible changes with explicit pre-check and post-check;
- preserve audit evidence (reports, logs, and command outputs).

Agents must not:
- apply high-impact production changes without explicit human approval;
- expose secrets, private keys, or sensitive host details;
- assume only one checkout layout (`optimizr-infra-ops` vs legacy `optimizr-infra`) without verification;
- change SSH/firewall policy in one step without rollback guidance.

## 2. Source of truth priority

1. VPS runtime state (systemd, users, firewall, cron) validated through secure remote inspection
2. `scripts/provision-day0.sh`
3. `scripts/security-audit.sh`
4. `.github/workflows/deploy.yml`
5. `.github/workflows/_*.yml` (reusable workflows org-wide — see `docs/CI_STANDARDS.md`)
6. `.github/actions/*/action.yml` (composite actions org-wide)
7. `.github/workflows/security-audit.yml`
8. `docs/CI_STANDARDS.md` (path filter policy, SHA pinning, deploy gating)
9. `docs/CI_RUNBOOK.md` (adopt/debug reusables)
10. `docs/RUNNER_REGISTRY.md` (canonical labels self-hosted runners)
11. `docs/DEPENDABOT_STANDARDS.md` (template + adoption policy)
12. `docs/README_BADGE_STANDARDS.md` (README badges — repos privados)
13. `docs/ORG_ADOPTION_REGISTRY.md` (matriz de adoção org-wide por consumer repo)
14. `docs/SECURITY_AUDIT.md`
15. `docs/SECURITY_INCIDENT_REPORT.md`
16. `docs/adr/*.md` (architecture decisions — immutable, ratify why)
17. `README.md`

If docs and implementation disagree, runtime behavior and scripts are authoritative. ADRs ratify the *why* — read before proposing changes that contradict them.

## 3. External standards baseline

These references drive agent decisions:
- CIS Linux hardening guidance
- OWASP DevSecOps and deployment hardening guidance
- NIST secure operations principles
- GitHub Actions secure use reference

### Up-to-date library documentation (Context7 MCP)

Use **Context7 MCP** to fetch current documentation instead of relying on static or cached sources.

- `mcp_context7_resolve-library-id` — resolves the Context7-compatible library ID from a library name.
- `mcp_context7_get-library-docs` — fetches up-to-date documentation for a specific topic.

| Technology | Context7 Library ID |
|---|---|
| Docker / Docker Compose | Resolve via `mcp_context7_resolve-library-id` with `"docker compose"` |
| GitHub Actions | Resolve via `mcp_context7_resolve-library-id` with `"github actions"` |
| UFW / iptables | Resolve via `mcp_context7_resolve-library-id` with the relevant tool name |

**Prerequisite:** Context7 MCP requires an API key in format `ctx7sk...` configured in the MCP server. If it returns an auth error with `${input:CO...KEY}`, the environment variable is unresolved — verify the MCP server configuration in VS Code before use.

> **Rule:** Before making decisions about provisioning scripts, firewall rules, or GitHub Actions workflow patterns, consult Context7 for up-to-date official documentation.

## 4. Risk classification model

### SAFE
- read-only inventory and audits;
- syntax and configuration validation;
- report generation and documentation updates without behavior change.

### YELLOW
- updates in `provision-day0.sh` and `security-audit.sh`;
- firewall baseline changes;
- user and SSH access policy updates;
- ClamAV scheduling updates.

Required for YELLOW:
1. pre-check documented;
2. post-check with service health and access validation;
3. rollback guidance in the same change.

### RED
- workflow permission changes;
- SSH lock-down changes that can block access;
- firewall default-policy or port model changes;
- destructive data/volume operations.

Required for RED:
1. explicit human approval before execution;
2. tested rollback path;
3. impact summary in PR description.

## 5. Mandatory infra controls

1. SSH key-only authentication for operational users.
2. At least one non-root operational user available for emergency access.
3. Firewall active with explicit allow-list for required public ports.
4. Security audit report generation must remain operational.
5. Provisioning scripts must stay idempotent.

## 6. Firewall baseline policy

Use UFW as default baseline:
- default deny incoming
- default allow outgoing
- allow `22/tcp` or approved custom SSH port
- allow `80/tcp`
- allow `443/tcp`
- allow `443/udp` (HTTP/3)
- allow `48293/tcp` only when DBaaS external access is required

Agent rules:
- never remove active SSH allow rule before validating new access path;
- always verify Docker networking still works after firewall changes;
- document deviations from baseline explicitly.
- for `48293/tcp`, prefer CIDR allow-list (never `any`) whenever client IP ranges are known.

## 7. ClamAV low-impact policy

Operational policy for this environment:
1. Do not keep `clamav-daemon` running 24/7 unless explicitly required.
2. Keep malware checks as scheduled scans at `03:30` by cron.
3. Use `freshclam` before scan.
4. Log scans in `/var/log/clamav/scan-YYYY-MM-DD.log`.
5. Exclude virtual/system paths that cause recursion/noise (for example `/proc`, `/sys`, `/dev`, `/run`, `/tmp`, and Docker runtime dirs when needed).

## 8. Deploy user policy

This repo must support at least these users in Day-0 provisioning:
- `thales`: operational deploy user
- `deploy`: automation/CI deploy user

Minimum requirements:
1. users are created idempotently;
2. users are shell-enabled and prepared for key-based SSH;
3. `.ssh` and `authorized_keys` permissions are enforced;
4. docker group membership is applied when present on host.

## 9. Legacy compatibility contract

[ADR-002](docs/adr/002-deploy-path-convention.md) ratifies modern path `/opt/optimizr/<repo>/` plano (sem `/current` symlink). Migration concluída no VPS de produção. Detection de legacy mantida nos scripts pra DR cenário, mas:

- modern (canônico, ADR-002): `/opt/optimizr/optimizr-infra-ops`
- legacy (deprecated, manter detection só pra DR): `/opt/optimizr/optimizr-infra`

Agents must:
- detect both layouts before executing ops scripts;
- avoid breaking legacy servers during migration;
- prefer compatibility changes over forced path rewrites;
- **não introduzir novos paths `/current`** ou symlink-based release patterns (ADR-002 rejeitou Capistrano-style explicitamente).

## 10. Operational checklist

Before behavior-changing changes:
1. validate script syntax;
2. confirm current remote access path;
3. confirm rollback command path.

After changes:
1. run/collect security audit report;
2. validate service health (`docker ps`, key service checks);
3. validate user access and firewall status;
4. validate ClamAV schedule and log output.

## 11. Prohibited anti-patterns

- locking down SSH without tested fallback access;
- disabling security controls silently;
- shipping docs that do not match script behavior;
- broad multi-layer production change without staged validation.
