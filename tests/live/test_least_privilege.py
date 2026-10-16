"""Least-privilege live tests (roadmap D17, docs/least-privilege.md).

Needs the accounts from `scripts/seed_access.py` in .env:
- CATC_RO_USERNAME / CATC_RO_PASSWORD (role mcp-catc-ro): every read tool runs as an MCP `ro` caller.
- CATC_RW_USERNAME / CATC_RW_PASSWORD (role mcp-catc-rw): a write round trip works; a dangerous-tier change
  (ISE/policy-server settings) is refused by Catalyst Center itself.
The whole live suite can also be run as one of these users: `CATC_USERNAME=mcp-catc-rw CATC_PASSWORD=...`.
"""

from __future__ import annotations

import json
import os
import uuid
from typing import Any

import pytest
from dotenv import dotenv_values
from fastmcp import Client
from fastmcp.exceptions import ToolError

from catc_mcp._core.testing import as_caller, live_settings
from catc_mcp._core.testing.least_privilege import (
    RO_CALLER,
    assert_read_tier_works,
    readonly_live_settings,
)
from catc_mcp.config import Settings
from catc_mcp.server import create_server

pytestmark = pytest.mark.live

R1 = "198.18.128.152"
BLDG = "Global/mcp-test-lab/mcp-test-bldg"
FLOOR = f"{BLDG}/mcp-test-floor1"
# Objects the lab seed (scripts/lab_state.py seed) creates; device tools use r1 of the catc-routers recipe.
SAMPLES: dict[str, dict[str, Any]] = {
    "catc_get_site_settings": {"site": "Global/mcp-test-lab"},
    "catc_get_device": {"device": R1},
    "catc_list_device_interfaces": {"device": R1},
    "catc_get_device_config": {"device": R1},
    "catc_list_device_modules": {"device": R1},
    "catc_get_device_hardware": {"device": R1},
    "catc_device_360": {"device": R1},
    "catc_get_client": {"mac": "52:54:00:c8:ef:06"},
    "catc_client_360": {"mac": "52:54:00:c8:ef:06"},
    "catc_run_show_commands": {"devices": [R1], "commands": ["show clock"]},
    "catc_get_compliance_detail": {"device": R1},
    "catc_list_config_archive": {"device": R1},
    "catc_compare_device_configs": {"device": R1},
    "catc_get_template": {"template": "mcp-test-dayn/mcp-test-cdp"},
    "catc_preview_template": {"template": "mcp-test-dayn/mcp-test-cdp", "device": R1},
    "catc_get_network_profile": {"profile": "mcp-test-sw-profile"},
    "catc_list_discovery_devices": {"discovery": "mcp-test-disc-routers"},
    "catc_list_tag_members": {"tag": "WAN"},
    "catc_get_site": {"site": FLOOR},
    "catc_search_spec": {"query": "site health"},
    "catc_get_definition": {"name": "/dna/intent/api/v1/site-health"},
    "catc_path_trace": {"source_ip": R1, "dest_ip": "198.18.128.153"},
}
# Tools that need an id only a previous call returns (issue, deployment, task) or an object the lab may lack.
SKIP = {
    "catc_api_call",
    "catc_get_issue",
    "catc_get_template_deployment",
    "catc_get_task",
    "catc_get_compliance_policy",
}
# Expected denial, documented in docs/least-privilege.md: the template preview API (a PUT) needs
# "Network Design.Profiles & Settings" Write, which the read-only role doesn't get.
NEEDS_RW = {"catc_preview_template"}
SAMPLES["catc_list_compliance_violations"] = {"device": R1}
SAMPLES["catc_list_events"] = {"device_family": "Routers"}


def _env(name: str) -> str | None:
    return os.environ.get(name) or dotenv_values(".env").get(name)


async def test_read_tier_as_readonly_user() -> None:
    settings = readonly_live_settings(Settings, "CATC_", mcp_cache_dir="")
    server = create_server(settings)
    report = await assert_read_tier_works(server, SAMPLES, skip=SKIP | NEEDS_RW)
    print(report.summary())
    assert not report.errors, report.summary()
    async with Client(server) as c:
        with as_caller(RO_CALLER):
            for tool in NEEDS_RW:
                with pytest.raises(ToolError, match=r"denied access \(403\)"):
                    await c.call_tool(tool, SAMPLES[tool])
    assert "catc_list_devices" in report.ok
    assert "catc_create_site" in report.hidden_writes  # write tools hidden from the `ro` caller


def _rw_settings(**overrides: Any) -> Settings:
    user, password = _env("CATC_RW_USERNAME"), _env("CATC_RW_PASSWORD")
    if not user or not password:
        pytest.skip("CATC_RW_USERNAME / CATC_RW_PASSWORD not configured (scripts/seed_access.py)")
    return live_settings(
        Settings,
        "CATC_",
        username=user,
        password=password,
        mcp_cache_dir="",
        mcp_enable_writes=True,
        **overrides,
    )


async def _confirm(c: Client[Any], tool: str, args: dict[str, Any]) -> Any:
    res = await c.call_tool(tool, args)
    preview = res.structured_content or json.loads(res.content[0].text)  # type: ignore[union-attr]
    assert preview.get("status") == "preview", preview
    res = await c.call_tool(tool, {**args, "confirm": preview["confirm"]})
    return res.structured_content or json.loads(res.content[0].text)  # type: ignore[union-attr]


async def test_write_tier_as_rw_user() -> None:
    """mcp-catc-rw can create/delete a tag and a site (Inventory + Hierarchy Write)."""
    run = uuid.uuid4().hex[:6]
    async with Client(create_server(_rw_settings())) as c:
        tag = f"mcp-test-lp-{run}"
        await _confirm(c, "catc_create_tag", {"name": tag, "description": "least-privilege check"})
        await _confirm(c, "catc_delete_tag", {"tag": tag})
        area = f"mcp-test-lp-{run}"
        await _confirm(c, "catc_create_site", {"site_type": "area", "name": area, "parent": "Global"})
        tools = {t.name for t in await c.list_tools()}
        assert "catc_delete_site" not in tools  # dangerous tier off for this server
    # Catalyst Center itself refuses the dangerous-only permissions to mcp-catc-rw (Device Provision is Read):
    # re-provisioning r1 where it already is would be harmless, and is denied.
    dangerous = _rw_settings(mcp_enable_dangerous=True)
    async with Client(create_server(dangerous)) as c:
        try:
            with pytest.raises(
                ToolError, match=r"(?i)denied|forbidden|403|401|not authori|permission|access"
            ):
                await _confirm(c, "catc_provision_devices", {"devices": [R1], "site": BLDG})
        finally:
            await _confirm(
                c, "catc_delete_site", {"site": f"Global/{area}"}
            )  # Hierarchy Write covers deletes
