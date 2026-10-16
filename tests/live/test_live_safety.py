"""Live safety-rail tests (D19, D20) on r1/r2 of the CML `catc-routers` recipe (provisioned at
mcp-test-bldg by scripts/lab_state.py seed).

- D19: a template deploy to r1+r2 is blocked at CATC_MAX_DEVICES_PER_CHANGE=1 and allowed for r1 alone;
  a tag target expands to its members; MCP_MAX_BLAST_RADIUS blocks too; outside MCP_CHANGE_WINDOW the
  confirm is refused.
- D20: deleting (un-provisioning) r2 with clean_config=false states every effect, removes r2 from the
  inventory but leaves its configuration; r2 is then re-onboarded (discovery -> assign -> provision).
"""

from __future__ import annotations

import asyncio
import contextlib
from typing import Any

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError

from catc_mcp._core.testing import live_settings
from catc_mcp.config import Settings
from catc_mcp.server import create_server

from .test_live_phase2 import R1, R2, routers  # noqa: F401 - routers is a fixture
from .test_live_writes import RUN, apply, call

pytestmark = pytest.mark.live

BLDG = "Global/mcp-test-lab/mcp-test-bldg"
TEMPLATE = "mcp-test-dayn/mcp-test-loopback"
PARAMS = {"loop_id": 78, "desc": "mcp-test-d19", "ip": "10.255.78.1"}


def server(**overrides: Any) -> Client[Any]:
    s = live_settings(
        Settings, "CATC_", mcp_cache_dir="", mcp_enable_writes=True, mcp_enable_dangerous=True, **overrides
    )
    return Client(create_server(s))


async def test_deploy_device_limit(routers: dict[str, Any]) -> None:  # noqa: F811
    args = {"template": TEMPLATE, "devices": [R1, R2], "params": PARAMS}
    async with server(max_devices_per_change=1) as c:
        out = await call(c, "catc_deploy_template", args)
        assert out["status"] == "blocked" and "CATC_MAX_DEVICES_PER_CHANGE=1" in out["blockers"][0]
        one = await call(c, "catc_deploy_template", {**args, "devices": [R1]})
        assert one["status"] == "preview" and one["blast_radius"] == 1
        assert one["preview"]["template_version"]["version"]
    async with server(mcp_max_blast_radius=1) as c:
        assert (await call(c, "catc_deploy_template", args))["status"] == "blocked"
    async with server() as c:
        tag = f"mcp-test-d19-{RUN}"
        await apply(c, "catc_create_tag", {"name": tag})
        try:
            await apply(c, "catc_update_tag_members", {"tag": tag, "add": [R1, R2]})
            out = await call(c, "catc_deploy_template", {"template": TEMPLATE, "tag": tag, "params": PARAMS})
            assert out["status"] == "preview" and out["blast_radius"] == 2
            assert out["preview"]["targets"] == {"by": "tag", "tag": tag}
            out = await call(
                c, "catc_deploy_template", {"template": TEMPLATE, "site": BLDG, "params": PARAMS}
            )
            assert out["blast_radius"] == 2 and out["preview"]["targets"]["site"] == BLDG
        finally:
            await apply(c, "catc_delete_tag", {"tag": tag, "remove_members": True})


async def test_change_window_refuses_deploy(routers: dict[str, Any]) -> None:  # noqa: F811
    # A one-minute window that is never "now" (a different weekday from today, any time zone works).
    import datetime as dt

    other = (dt.datetime.now(dt.UTC) + dt.timedelta(days=3)).strftime("%a")
    async with server(mcp_change_window=f"{other} 03:00-03:01 UTC") as c:
        args = {"template": TEMPLATE, "devices": [R1], "params": PARAMS}
        out = await call(c, "catc_deploy_template", args)
        assert out["policy"]["change_window"]["open"] is False
        with pytest.raises(ToolError, match="(?i)change window"):
            await call(c, "catc_deploy_template", {**args, "confirm": out["confirm"]})


async def test_unprovision_deletes_device_then_reonboard(routers: dict[str, Any]) -> None:  # noqa: F811
    async with server() as c:
        with pytest.raises(ToolError, match="clean_config"):
            await call(c, "catc_delete_device", {"device": R2})
        preview = await call(c, "catc_delete_device", {"device": R2, "clean_config": False})
        assert preview["action"].startswith("Un-provision and delete"), preview
        effects = " ".join(preview["side_effects"])
        assert "no longer managed" in effects and "Leaves the device's configuration" in effects
        assert preview["preview"]["config_archive_lost"]["versions"] >= 1
        assert preview["blast_radius"] == 1
        await apply(c, "catc_delete_device", {"device": R2, "clean_config": False})
        with pytest.raises(ToolError, match="No network device"):
            await call(c, "catc_get_device", {"device": R2})

        # Re-onboard: discovery -> Managed -> assign -> provision (as scripts/lab_state.py seed leaves it).
        disc = f"mcp-test-d20-{RUN}"
        try:
            await apply(
                c,
                "catc_create_discovery",
                {
                    "name": disc,
                    "ip_ranges": [R2],
                    "global_credentials": ["mcp-test-cli", "mcp-test-snmp-ro", "mcp-test-snmp-rw"],
                    "netconf_port": 830,
                    "wait": True,
                },
            )
            for _ in range(45):
                with contextlib.suppress(ToolError):
                    d = await call(c, "catc_get_device", {"device": R2})
                    if d.get("collectionStatus") == "Managed":
                        break
                await asyncio.sleep(20)
            else:
                pytest.fail("r2 did not become Managed after rediscovery")
            # The config was left on the device: the archive of the new inventory entry shows the
            # Catalyst Center-pushed lines (e.g. the logging host) still there after the delete.
            res = await c.call_tool("catc_get_device_config", {"device": R2})
            cfg = res.structured_content or " ".join(getattr(x, "text", "") for x in res.content)
            assert "logging host" in str(cfg)
            await apply(c, "catc_assign_devices_to_site", {"devices": [R2], "site": BLDG})
            await apply(c, "catc_provision_devices", {"devices": [R2], "site": BLDG})
        finally:
            with contextlib.suppress(Exception):
                await apply(c, "catc_delete_discovery", {"discovery": disc})
