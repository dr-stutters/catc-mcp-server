"""Server assembly: SPEC, INSTRUCTIONS and create_server()."""

from typing import Any

import httpx
from fastmcp import FastMCP
from fastmcp.server.auth import AuthProvider

from catc_mcp._core import ServerSpec, build_server, suite
from catc_mcp._core.spec import SpecSource, bundled
from catc_mcp.client import CatcApp
from catc_mcp.config import Settings
from catc_mcp.tools import (
    aaa,
    activity,
    archive,
    assurance,
    assurance_analytics,
    backups,
    compliance,
    compliance_policies,
    config_import,
    config_io,
    credentials,
    dangerous,
    discovery,
    external_auth,
    group_policy,
    inventory,
    ipam,
    network_services,
    ops_writes,
    platform,
    pnp,
    profiles,
    prompts,
    reports,
    sda,
    sda_aaa,
    sda_anchor,
    sda_auth,
    sda_device_update,
    sda_discovery,
    sda_events,
    sda_extranet,
    sda_health,
    sda_layer2,
    sda_multicast,
    sda_port_channels,
    sda_site_update,
    sda_ssi,
    sda_transits,
    sda_updates,
    sda_zones,
    settings_writes,
    site_writes,
    sites,
    smart,
    snapshot,
    swim,
    system,
    tags,
    template_writes,
    templates,
    topology,
    wireless,
    wireless_config,
    wireless_writes,
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
- SD-Access: provision the devices -> catc_create_fabric_site -> catc_add_fabric_device (control plane/
  border first, then edges) -> catc_create_virtual_network -> catc_create_ip_pool (reserve at the site) ->
  catc_add_anycast_gateway -> catc_assign_fabric_port; check with catc_get_sda_fabric, and AAA to ISE from
  the RLOCs (RADIUS state, ISE NAD, TrustSec environment data) with catc_check_fabric_aaa. Tear down:
  catc_delete_fabric_device / catc_delete_fabric_site (cascade=true removes everything in reverse order).
  Way out of the fabric: catc_create_transit_network -> catc_add_l3_handoff (border, per VN VLAN + eBGP).
- Wireless: catc_create_ssid -> catc_create_wireless_profile -> catc_assign_profile_to_sites (AP
  locations) -> catc_assign_devices_to_site (WLC to a building) -> catc_provision_wireless_controller ->
  catc_get_wireless_controller -> catc_get_wlc_config (feature config, intended vs deployed, diff=true).
- Wireless per-device (a 9800 with Per-Device Configuration enabled, not site-based): catc_set_wlan_security /
  catc_set_wlan_vlan / catc_set_rf_profile stage the change -> catc_get_wlc_config(diff=true) ->
  catc_deploy_wlc_config -> catc_get_wlc_deployments.
- Network settings vs templates: DNS, NTP, syslog/SNMP servers, banner, time zone and AAA are site
  settings: change them with catc_update_site_settings (or catc_update_site_aaa_settings), then
  re-provision (catc_provision_devices). Use templates for everything else.
- Admin login through ISE (external authentication): catc_get_external_authentication -> ISE NAD + an
  authorization profile returning 'Role=<role>' -> catc_set_external_authentication -> catc_test_login (local
  admin first: lockout risk).
- Troubleshoot: catc_device_360 / catc_client_360 -> catc_list_issues -> catc_get_issue (suggested
  commands) -> catc_run_show_commands; catc_path_trace; catc_list_events. Issues stay 'active' for
  hours after the problem clears: check last_seen and the live state before calling one current.
- What changed / who did it: catc_recent_activity (device or site, merged issues, syslog, notifications,
  audit), catc_list_audit_logs(changes_only=true), catc_compare_device_configs (config diff; the
  archive lags a few minutes behind a change).
- Pre/post change check: catc_snapshot(site) before the change (keep the blob), catc_compare_snapshot(before)
  after it: what got unhealthy (device reachability/health, site health, compliance, new P1/P2 issues).
  Across products: prompt suite_change_check.
- Roll back a template deploy: catc_get_template_deployment shows the CLI pushed per device; write a
  negation template ('no ...' lines), commit, preview and deploy it (prompt catc_change_window).
- Clients: catc_list_clients (by switch/WLC/AP, site, SSID, VLAN), then catc_client_360 for one.
- Health: catc_get_network_health -> catc_list_device_health (health='POOR'); software per device:
  catc_list_devices or catc_list_device_images.
- "Is it the network or ISE/DHCP/DNS?": catc_network_services_health(service='aaa'|'dhcp'|'dns'|'all', site)
  (per-server success %, latency, EAP/MAB split, the failing NADs, a verdict line; Assurance lags by minutes).
- Over time ("is this site getting worse?", "what keeps breaking?"): catc_site_health_report, or
  catc_health_trend (dips), catc_top_problems, catc_issue_recurrence, catc_ai_insights.
- Backups (before the group-based policy migration or an upgrade): catc_get_backup_status (target configured?,
  ready?, last backup, running jobs) -> catc_create_backup (dangerous, SUPER-ADMIN-ROLE) ->
  catc_get_backup_status(execution=...) -> catc_list_backups. Restores are GUI-only.
Asynchronous operations return a task id; check it with catc_get_task.
Anything not covered: catc_search_spec -> catc_get_definition -> catc_api_call.
""".strip()

SPEC = ServerSpec(
    name="catc-mcp-server",
    prefix="catc",
    product="Cisco Catalyst Center",
    env_prefix="CATC_",
    instructions=INSTRUCTIONS,
    spec_search_example="network device",
    spec_path_example="/dna/intent/api/v1/network-device/{id}",
)

REGISTER = [
    system.register,
    activity.register,
    sites.register,
    inventory.register,
    assurance.register,
    assurance_analytics.register,
    network_services.register,
    smart.register,
    snapshot.register,
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
    backups.register,
    profiles.register,
    prompts.register,
    site_writes.register,
    settings_writes.register,
    aaa.register,
    external_auth.register,
    group_policy.register,
    pnp.register,
    template_writes.register,
    ops_writes.register,
    sda.register,
    sda_site_update.register,
    sda_ssi.register,
    sda_anchor.register,
    sda_device_update.register,
    sda_extranet.register,
    sda_discovery.register,
    sda_health.register,
    sda_aaa.register,
    sda_updates.register,
    sda_events.register,
    sda_zones.register,
    sda_port_channels.register,
    sda_multicast.register,
    sda_transits.register,
    sda_layer2.register,
    sda_auth.register,
    wireless.register,
    wireless_config.register,
    wireless_writes.register,
    reports.register,
    config_io.register,
    config_import.register,
    dangerous.register,
    suite.register,
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
