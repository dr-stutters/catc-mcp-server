"""Server assembly: SPEC, INSTRUCTIONS and create_server()."""

from typing import Any

import httpx
from fastmcp import FastMCP
from fastmcp.server.auth import AuthProvider
from stutters_mcp_core import ServerSpec, build_server

from catc_mcp.client import CatcApp
from catc_mcp.config import Settings
from catc_mcp.tools import system

INSTRUCTIONS = """
Tools for Cisco Catalyst Center (formerly DNA Center): inventory, sites, assurance health and issues,
topology, compliance, templates, software images (SWIM), discovery, path trace and read-only CLI.

Object model: sites form a hierarchy Global/<area>/<building>/<floor>; network devices are assigned
to sites; ids are UUIDs. Most tools accept a name, IP, serial or site path and resolve the id.
Start with catc_status, then catc_list_devices or catc_get_site_hierarchy.
Smart tools: catc_device_360 (everything about one device), catc_client_360 (one client by MAC),
catc_path_trace (source -> destination path), catc_run_show_commands (read-only show commands).
Asynchronous operations return a task id; check it with catc_get_task.
Anything not covered: catc_search_spec -> catc_get_definition -> catc_api_call.
""".strip()

SPEC = ServerSpec(
    name="catc-mcp-server",
    prefix="catc",
    product="Cisco Catalyst Center",
    env_prefix="CATC_",
    instructions=INSTRUCTIONS,
)

REGISTER = [system.register]


def create_server(
    settings: Settings,
    *,
    auth: AuthProvider | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> FastMCP[Any]:
    return build_server(
        SPEC,
        settings,
        client_factory=lambda s: CatcApp(s, transport=transport),
        register=REGISTER,
        status=CatcApp.status,
        auth=auth,
    )
