"""Shared fixtures: settings without .env, and a respx router on the fake appliance.

D52: every request the suite sends is recorded and checked against the bundled spec at session end
(tests/unit/spec_conformance.py; exceptions with reasons in tests/unit/spec_allowlist.py).
"""

import os
from collections.abc import Iterator
from typing import Any

import httpx
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
        # Gated previews (catc_deploy_template, provisioning, SWIM) read the provisioning settings; tests that
        # care add their own route, which replaces this one.
        router.get("/dna/intent/api/v1/provisioningSettings").respond(
            json={"response": {"requirePreview": False, "requireItsmApproval": False}, "version": "1.0"}
        )
        router.get("/dna/system/api/v1/user").respond(
            json={"response": {"users": [{"username": "admin", "roleList": ["SUPER-ADMIN-ROLE"]}]}}
        )
        yield router


# --- D52 spec-conformance recorder ------------------------------------------------------------

_RECORDED: list[Any] = []
_CURRENT_TEST = [""]
_ORIGINAL_SEND = httpx.AsyncClient.send


async def _recording_send(self: httpx.AsyncClient, request: httpx.Request, **kw: Any) -> httpx.Response:
    from .spec_conformance import record

    if (r := record(request, _CURRENT_TEST[0])) is not None:
        _RECORDED.append(r)
    return await _ORIGINAL_SEND(self, request, **kw)


def pytest_configure(config: pytest.Config) -> None:
    httpx.AsyncClient.send = _recording_send  # type: ignore[method-assign]


def pytest_unconfigure(config: pytest.Config) -> None:
    httpx.AsyncClient.send = _ORIGINAL_SEND  # type: ignore[method-assign]


def pytest_runtest_setup(item: pytest.Item) -> None:
    _CURRENT_TEST[0] = item.nodeid


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    """Fail the run when a recorded request doesn't conform to the spec (and isn't allowlisted)."""
    if not _RECORDED:
        return
    from .spec_conformance import check

    report = check(_RECORDED)
    if out := os.environ.get("CATC_SPEC_AUDIT_OUT"):  # scripts/spec_audit.py
        import json

        with open(out, "w") as f:
            json.dump([[r.method, r.path, sorted(r.query), sorted(r.body), r.test] for r in _RECORDED], f)
    tr = session.config.pluginmanager.get_plugin("terminalreporter")
    if report.findings:
        if tr is not None:
            tr.write_sep("=", "spec conformance (D52)", red=True)
            tr.write_line(report.text())
            tr.write_line("Fix the request, or add an entry with a reason to tests/unit/spec_allowlist.py.")
        if session.exitstatus == pytest.ExitCode.OK:
            session.exitstatus = pytest.ExitCode.TESTS_FAILED
    elif tr is not None:
        tr.write_line(report.text().splitlines()[0])
