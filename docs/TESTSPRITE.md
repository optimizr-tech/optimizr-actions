# TestSprite reusable contract

`_testsprite.yml` is the portable execution contract for hosted TestSprite
checks. It standardizes the trust boundary; it does not deploy a service,
create a preview stack, provision DNS/TLS, or own service fixtures.

## Caller contract

Each consumer owns a thin caller workflow and must provide:

- an isolated HTTPS non-production target and its reviewed exact URL;
- a protected GitHub Environment whose name identifies staging, preview, test,
  QA, homologation, or sandbox;
- `TESTSPRITE_API_KEY` only in that protected Environment;
- a self-hosted Linux runner label set;
- a reviewed `testsprite_tests/` suite committed in the trusted main revision;
- consumer-owned production host patterns in `forbidden_hosts_json`.

Both the secret-free preflight and the secret-bearing TestSprite job use the
caller's `runner_json` labels. The caller must therefore provide a governed
self-hosted Linux runner that is approved for trusted `main`/dispatch work.
The reusable workflow rejects pull-request and non-`main` execution, HTTP,
local/private target literals, URL mismatches, production-like environments,
unsafe suite paths, and runners without both `self-hosted` and `Linux` labels. The
secret-bearing job checks out the exact trusted revision and runs the blocking
official TestSprite action pinned to an immutable commit SHA.

Example caller:

```yaml
name: TestSprite

on:
  push:
    branches: [main]
  workflow_dispatch:

jobs:
  testsprite:
    uses: optimizr-tech/optimizr-actions/.github/workflows/_testsprite.yml@v1
    with:
      base_url: ${{ vars.TESTSPRITE_BASE_URL }}
      expected_base_url: https://service-testsprite.example.com/preview
      environment_name: staging-testsprite
      runner_json: '["self-hosted", "Linux", "service"]'
      forbidden_hosts_json: '["service.example.com", "*.optimizr.site"]'
      suite_path: testsprite_tests
    secrets:
      TESTSPRITE_API_KEY: ${{ secrets.TESTSPRITE_API_KEY }}
```

The caller should keep this check manual/protected or non-required until the
isolated target, real suite, and exact-SHA staging deployment evidence exist.
Once it becomes required, an unavailable staging target or failed TestSprite
check must block promotion rather than being converted into a dummy success.

## Ownership boundary

`optimizr-actions` owns this reusable contract, validation helper, and
compatibility tests. Consumers own product scenarios, fixtures, and the
caller. Infrastructure owns the isolated runtime prerequisites. No production
credentials, host inventories, or service-specific allowlists belong in this
repository.

The action interface and inputs follow the official
[TestSprite GitHub integration](https://docs.testsprite.com/mcp/integrations/github-integration).
