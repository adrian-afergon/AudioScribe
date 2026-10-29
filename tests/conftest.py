"""Shared test collection guards.

The upload service is qualified for Linux only (sealed validator, POSIX
mailbox permissions); its test suites are skipped on other platforms
instead of failing on platform-specific APIs.
"""

from __future__ import annotations

import sys

import pytest


def pytest_collection_modifyitems(config, items):
    if sys.platform == "linux":
        return
    skip = pytest.mark.skip(reason="the upload service is qualified for Linux only")
    for item in items:
        if "upload" in item.nodeid or "lq04" in item.nodeid:
            item.add_marker(skip)
