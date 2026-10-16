"""Live tests run against the Catalyst Center in .env: `uv run pytest tests/live -m live`.

Lab-specific inputs (device addresses, site paths, ISE, WLC, fabric, PnP) come from the CATC_LIVE_*
variables documented in docs/live-tests.md (environment or .env); a test that needs one skips naming it."""

import os
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest
from dotenv import dotenv_values
from fastmcp import Client, FastMCP

from catc_mcp._core.testing import live_settings
from catc_mcp.config import Settings
from catc_mcp.server import create_server

_DOTENV = {k: v for k, v in dotenv_values(Path(__file__).resolve().parents[2] / ".env").items() if v}


def live_env(name: str, default: str = "") -> str:
    """A live-test input from the environment or .env ('' when unset)."""
    return os.environ.get(name) or _DOTENV.get(name) or default


def need(*names: str) -> list[str]:
    """The values of these CATC_LIVE_* (or other) variables; pytest.skip naming the unset ones."""
    missing = [n for n in names if not live_env(n)]
    if missing:
        pytest.skip(f"set {', '.join(missing)} (docs/live-tests.md)")
    return [live_env(n) for n in names]


def parent_site(path: str) -> str:
    """'Global/a/b' -> 'Global/a'."""
    return path.rsplit("/", 1)[0]


# Shared lab inputs ('' when unset; the tests that need them call need()).
ROUTER1, ROUTER2 = live_env("CATC_LIVE_ROUTER1"), live_env("CATC_LIVE_ROUTER2")
BUILDING, FLOOR = live_env("CATC_LIVE_BUILDING"), live_env("CATC_LIVE_FLOOR")


@pytest.fixture
def lab_settings() -> Settings:
    return live_settings(Settings, "CATC_", mcp_cache_dir="")


@pytest.fixture
def lab_rw_settings() -> Settings:
    return live_settings(
        Settings, "CATC_", mcp_cache_dir="", mcp_enable_writes=True, mcp_enable_dangerous=True
    )


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


def require_reachable(ip: str, what: str, port: int = 22) -> None:
    """Skip when a lab device isn't reachable (powered off, lab stopped) instead of failing mid-test."""
    import socket

    try:
        with socket.create_connection((ip, port), timeout=5):
            return
    except OSError:
        pytest.skip(f"{what} ({ip}) is not reachable on port {port}: start it first")
