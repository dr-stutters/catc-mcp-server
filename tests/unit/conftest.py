"""Shared fixtures: settings without .env, and a respx router on the fake appliance."""

from collections.abc import Iterator
from typing import Any

import pytest
import respx
from fastmcp import FastMCP

from catc_mcp.config import Settings
from catc_mcp.server import create_server

BASE = "https://catc.test"


def make_settings(**kw: Any) -> Settings:
    base: dict[str, Any] = {
        "url": BASE,
        "username": "admin",
        "password": "pw",
        "retries": 0,
        "mcp_cache_dir": "",
        "mcp_task_timeout": 5,
    }
    base.update(kw)
    return Settings(_env_file=None, **base)  # type: ignore[call-arg]


def make_server(**kw: Any) -> FastMCP[Any]:
    return create_server(make_settings(**kw))


@pytest.fixture
def settings() -> Settings:
    return make_settings()


@pytest.fixture
def rw_settings() -> Settings:
    return make_settings(mcp_enable_writes=True, mcp_enable_dangerous=True)


@pytest.fixture
def api() -> Iterator[respx.MockRouter]:
    with respx.mock(base_url=BASE, assert_all_called=False) as router:
        router.post("/dna/system/api/v1/auth/token").respond(json={"Token": "tok-123"})
        # Startup status check (server lifespan) - routes added by tests come after these.
        router.get("/dna/intent/api/v1/dnac-release").respond(
            json={"response": {"installedVersion": "3.2.2-75131"}}
        )
        router.get("/dna/system/api/v1/installedRelease").respond(
            json={"response": {"packages": [{"name": n, "status": "DEPLOYED"} for n in ("sda", "aca")]}}
        )
        router.get("/dna/intent/api/v1/network-device/count").respond(json={"response": 0})
        router.get("/dna/intent/api/v1/sites/count").respond(json={"response": {"count": 1}})
        router.get("/dna/intent/api/v1/networkDeviceConfigFiles").respond(json={"response": []})
        router.get("/dna/system/api/v1/user").respond(
            json={"response": {"users": [{"username": "admin", "roleList": ["SUPER-ADMIN-ROLE"]}]}}
        )
        yield router
