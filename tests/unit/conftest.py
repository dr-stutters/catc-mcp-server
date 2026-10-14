"""Shared fixtures: settings without .env, and a respx router on the fake appliance."""

from collections.abc import Iterator
from typing import Any

import pytest
import respx

from catc_mcp.config import Settings

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
        yield router
