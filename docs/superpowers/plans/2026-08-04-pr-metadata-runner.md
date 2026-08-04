# Persistent PR Metadata Runner Implementation Plan

- [x] Add a trusted composite action that validates PR metadata via the GitHub API.
- [x] Add a reusable metadata-only workflow with read-only permissions.
- [x] Permit persistent self-hosted Linux execution only under `metadata-pr`.
- [x] Prohibit checkout, dependency installation, Docker, sudo and consumer scripts.
- [x] Add unit and static trust-contract tests.
- [ ] Publish through the managed `v1` tag after complete repository validation.
- [ ] Migrate the CDN PR checks and verify execution on its persistent runner.
