"""Tiny package used by the executable reusable-workflow canary."""


def normalize(value: str) -> str:
    """Return the canary input in a stable, observable form."""
    return value.strip().upper()
