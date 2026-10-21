"""D21: long-running tools as MCP background tasks (core C12), off unless MCP_TASKS=true."""

import pytest
import respx
from fastmcp import Client
from fastmcp.exceptions import ToolError
from fastmcp_tasks import call_tool_task

from catc_mcp.server import create_server

from .conftest import make_settings
from .test_read_tools import AREA, BLDG, GLOBAL
from .test_write_tools import mock_sites

LONG = {
    "catc_create_discovery",
    "catc_provision_devices",
    "catc_deploy_template",
    "catc_distribute_image",
    "catc_activate_image",
    "catc_provision_wireless_controller",
    "catc_deploy_wlc_config",
    "catc_claim_pnp_device",
    "catc_replace_device",
    "catc_add_fabric_device",
    "catc_add_anycast_gateway",
    "catc_update_fabric_site",
    "catc_anchor_virtual_network",
    "catc_set_extranet_policy",
    "catc_set_fabric_port_channel",
    "catc_set_fabric_multicast",
    "catc_add_l3_handoff",
    "catc_delete_l3_handoff",
    "catc_set_l2_virtual_network",
    "catc_set_l2_handoff",
    "catc_delete_fabric_site",
    "catc_delete_fabric_device",
    "catc_update_anycast_gateway",
    "catc_apply_pending_fabric_events",
    "catc_export_config",
    "catc_diff_config",
    "catc_import_config",
}


async def test_long_tools_are_tasks(api: respx.MockRouter) -> None:
    s = make_settings(mcp_tasks=True, mcp_enable_writes=True, mcp_enable_dangerous=True)
    async with Client(create_server(s)) as c:
        status = (await c.call_tool("catc_status", {})).structured_content
    assert set(status["server"]["tasks"]["tools"]) == LONG


async def test_task_preview_runs_in_background(api: respx.MockRouter) -> None:
    mock_sites(api, [GLOBAL, AREA, BLDG])
    api.get("/dna/intent/api/v1/network-device").respond(json={"response": []})
    s = make_settings(mcp_tasks=True, mcp_enable_writes=True, mcp_enable_dangerous=True)
    async with Client(create_server(s)) as c:
        handle = await call_tool_task(
            c, "catc_provision_devices", {"devices": ["nonexistent-device"], "site": "Global/AU/SYD-1"}
        )
        with pytest.raises(ToolError, match="No network device"):  # raised inside the task, reported back
            await handle.result()
