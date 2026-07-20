# Dependency and license policy gate design

## Goal

Provide a common Python/Node lock integrity, vulnerability advisory and license policy contract.

## Design

A standard-library policy engine detects supported ecosystems, requires one unambiguous lockfile, performs structural npm lock comparison, validates expiring exceptions, and evaluates Trivy JSON. The composite action invokes controlled native package-manager frozen checks before a Trivy `vuln,license` filesystem scan. A reusable workflow exposes equivalent hosted and self-hosted behavior with read-only permissions.

## Security model

Missing manifests, ambiguous locks, stale locks, unavailable tools/advisory data, malformed policy, expired exceptions, denied licenses and blocking vulnerabilities fail closed. Reports contain hashes and finding metadata, not environment values.
