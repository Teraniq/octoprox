from __future__ import annotations

import os

import pytest


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--live-deployment",
        action="store_true",
        default=False,
        help="Run tests against live deployment",
    )
    parser.addoption(
        "--base-url",
        action="store",
        default="http://localhost:8080",
        help="Base URL for deployment tests",
    )
    parser.addoption(
        "--admin-user",
        action="store",
        default="admin",
        help="Admin username",
    )
    parser.addoption(
        "--admin-pass",
        action="store",
        default="changeme",
        help="Admin password",
    )


def pytest_configure(config: pytest.Config) -> None:
    if config.getoption("--live-deployment"):
        os.environ["TEST_BASE_URL"] = config.getoption("--base-url")
        os.environ["TEST_ADMIN_USER"] = config.getoption("--admin-user")
        os.environ["TEST_ADMIN_PASS"] = config.getoption("--admin-pass")


def pytest_collection_modifyitems(
    config: pytest.Config, items: list[pytest.Item]
) -> None:
    if config.getoption("--live-deployment"):
        return

    skip_deployment = pytest.mark.skip(reason="Need --live-deployment option to run")
    for item in items:
        if "test_deployment_verification.py" in item.nodeid:
            item.add_marker(skip_deployment)
