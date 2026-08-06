# Governed Docker access implementation plan

**Goal:** Make reusable Compose configuration validation work on direct-access and sudo-only governed runners without misrepresenting Buildx support.

**Architecture:** Resolve one Docker access mode before checkout. Shell-based Compose validation calls a small local wrapper. Buildx remains direct-only.

## Tasks

- [x] Add a failing workflow contract for access resolution, command routing, and the Buildx boundary.
- [ ] Add `docker_mode: auto | direct | sudo` with a backward-compatible default.
- [ ] Probe direct access and then `sudo -n` in auto mode.
- [ ] Route standalone and merged-stack Compose validation through the resolved mode.
- [ ] Fail when `build_image=true` resolves to sudo.
- [ ] Refresh the capability catalog digest.
- [ ] Run the focused contract, YAML parse, catalog check, full repository tests, and actionlint.
- [ ] Open a draft PR linked to #145 without moving `v1`.

## Constraints

- No interactive sudo.
- No consumer-specific runner assumptions.
- No change to runner trust validation or event restrictions.
- No consumer, tag, release, deployment, or runner mutation.
