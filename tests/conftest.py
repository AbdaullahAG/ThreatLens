"""
pytest configuration — adds --run-e2e CLI flag.

Tests decorated with @pytest.mark.e2e are skipped unless --run-e2e is passed.
"""

import pytest


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--run-e2e",
        action="store_true",
        default=False,
        help="Run end-to-end tests that make real network requests",
    )


def pytest_collection_modifyitems(
    config: pytest.Config, items: list[pytest.Item]
) -> None:
    if not config.getoption("--run-e2e"):
        skip_e2e = pytest.mark.skip(reason="pass --run-e2e to enable e2e tests")
        for item in items:
            if "e2e" in item.keywords:
                item.add_marker(skip_e2e)
