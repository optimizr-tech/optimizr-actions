import pytest

from canary_app import normalize

from conftest import canary_failure_enabled


def test_000_failure_path_is_assigned_to_first_shard(pytestconfig) -> None:
    if canary_failure_enabled() and pytestconfig.getoption("group", default=None) == 1:
        pytest.fail("intentional canary failure: aggregate must reject a failed shard")


def test_normalize_strips_and_uppercases() -> None:
    assert normalize("  canary  ") == "CANARY"


def test_normalize_preserves_internal_spacing() -> None:
    assert normalize("a canary") == "A CANARY"


def test_normalize_handles_empty_input() -> None:
    assert normalize("  ") == ""
