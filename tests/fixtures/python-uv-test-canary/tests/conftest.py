import os


def pytest_configure(config) -> None:
    """Expose the sharding option to the intentional failure test."""
    config._canary_shard_group = config.getoption("group", default=None)


def canary_failure_enabled() -> bool:
    return os.environ.get("CANARY_FAILURE_MODE") == "1"
