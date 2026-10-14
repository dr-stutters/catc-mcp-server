"""Live tests run against the lab in .env: `uv run pytest tests/live -m live`."""

from collections.abc import AsyncIterator
from typing import Any

import pytest
from fastmcp import Client, FastMCP
from stutters_mcp_core.testing import live_settings

from catc_mcp.config import Settings
from catc_mcp.server import create_server


@pytest.fixture
def lab_settings() -> Settings:
    return live_settings(Settings, "CATC_", mcp_cache_dir="")


@pytest.fixture
def lab_rw_settings() -> Settings:
    return live_settings(Settings, "CATC_", mcp_cache_dir="", mcp_enable_writes=True, mcp_enable_dangerous=True)


@pytest.fixture
async def lab(lab_settings: Settings) -> AsyncIterator[Client[Any]]:
    server: FastMCP[Any] = create_server(lab_settings)
    async with Client(server) as c:
        yield c


@pytest.fixture
async def lab_rw(lab_rw_settings: Settings) -> AsyncIterator[Client[Any]]:
    server: FastMCP[Any] = create_server(lab_rw_settings)
    async with Client(server) as c:
        yield c
