"""Server assembly: SPEC, INSTRUCTIONS and create_server()."""

from typing import Any

import httpx
from fastmcp import FastMCP
from fastmcp.server.auth import AuthProvider
from stutters_mcp_core import ServerSpec, build_server
from stutters_mcp_core.spec import SpecSource, bundled

from catc_mcp.client import CatcApp
from catc_mcp.config import Settings
from catc_mcp.tools import (
    activity,
    archive,
    assurance,
    compliance,
    compliance_policies,
    credentials,
    dangerous,
    discovery,
    inventory,
    ipam,
    ops_writes,
    platform,
    profiles,
    prompts,
    settings_writes,
    site_writes,
    sites,
    smart,
    swim,
    system,
    tags,
    template_writes,
    templates,
    topology,
)

INSTRUCTIONS = """
Tools for Cisco Catalyst Center (formerly DNA Center): inventory, sites and network settings,
credentials and discovery, provisioning, templates, compliance and config drift, assurance (health,
issues, events, clients), path trace, read-only CLI, software images (SWIM) and IP pools.

Object model: sites form a hierarchy Global/<area>/<building>/<floor>; network devices are assigned
to sites; ids are UUIDs. Most tools accept a name, IP, serial or site path and resolve the id.
Start with catc_status, then catc_list_devices or catc_get_site_hierarchy.
Workflows:
- Onboard: catc_create_global_credential -> catc_create_discovery (wait=true) -> catc_create_site ->
  catc_update_site_settings -> catc_assign_devices_to_site -> catc_provision_devices.
- Day-N change: catc_create_template -> catc_commit_template -> catc_preview_template ->
  catc_deploy_template -> verify with catc_run_show_commands -> catc_run_compliance /
  catc_compare_device_configs.
- Troubleshoot: catc_device_360 / catc_client_360 -> catc_list_issues -> catc_get_issue (suggested
  commands) -> catc_run_show_commands; catc_path_trace; catc_list_events.
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

REGISTER = [
    system.register,
    activity.register,
    sites.register,
    inventory.register,
    assurance.register,
    smart.register,
    topology.register,
    compliance.register,
    compliance_policies.register,
    templates.register,
    swim.register,
    discovery.register,
    tags.register,
    credentials.register,
    archive.register,
    ipam.register,
    platform.register,
    profiles.register,
    prompts.register,
    site_writes.register,
    settings_writes.register,
    template_writes.register,
    ops_writes.register,
    dangerous.register,
]

# The appliance doesn't serve its OpenAPI document over the API, so a copy ships in the wheel
# (exported from a 3.2.2-75131 Developer Toolkit; see scripts/bundle_spec.py and the README).
SPEC_VERSION = "3.2.2-75131"
SPEC_RESOURCE = "specs/catc-3.2.2.json.gz"


def spec_sources(app: CatcApp) -> list[SpecSource]:
    async def version(_app: CatcApp) -> str:
        return SPEC_VERSION

    return [
        SpecSource(
            "intent",
            bundled("catc_mcp", SPEC_RESOURCE),
            client=lambda a: a.api,
            version=version,
            description=f"Catalyst Center {SPEC_VERSION} Intent/System/Data API (bundled)",
        )
    ]


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
        spec_sources=spec_sources,
        auth=auth,
    )
