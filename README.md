# Optimizr Actions

Reusable GitHub Actions workflows and composite actions for Optimizr projects.

## Public boundary

This repository contains only generic automation. It must never contain
credentials, private keys, host addresses, customer data, production
configuration, or private-repository dependencies. Consumer repositories own
their secrets, service lifecycle, and product-specific checks.

Optimizr-managed consumers should use the floating `v1` tag so compatible
automation fixes propagate without repository-by-repository pin updates. The
tag moves only after this repository's release validation succeeds, and every
change published within `v1` must preserve existing caller contracts. Use an
immutable commit SHA only where a consumer's threat model requires independent
review and explicit upgrades.

## Validation

Run the repository regression suite with:

```powershell
python -m unittest discover -v
```

The portable local validation contract and Fiscal preset are documented in
[`docs/LOCAL_VALIDATION.md`](docs/LOCAL_VALIDATION.md) once released.

## Security

Report vulnerabilities privately as described in
[`SECURITY.md`](SECURITY.md). Do not open public issues containing secrets,
host details, customer data, or proof-of-concept material that could expose
production systems.

## License status

The project is publicly visible, but an open-source license has not yet been
selected. No permission to reproduce, distribute, modify, or sublicense the
code is granted beyond rights that GitHub's Terms of Service provide for
viewing and forking. This status will be replaced only after the copyright and
licensing decision is reviewed.
