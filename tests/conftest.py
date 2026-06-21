"""Pytest configuration: enable asyncio mode for async tests."""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# pytest-asyncio auto mode: any `async def test_...` runs in an event loop.
import pytest_asyncio  # noqa: F401  (fails fast if not installed)


def pytest_collection_modifyitems(config, items):
    """Mark all async tests with asyncio automatically."""
    for item in items:
        if "asyncio" in item.keywords:
            continue
        # pytest-asyncio in auto mode handles this; nothing to do.
