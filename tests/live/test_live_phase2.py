"""Phase 2 live tests: onboarding objects (credentials, network settings, IP pools) on throwaway
mcp-test-* sites, and device workflows against two managed IOS-XE routers CATC_LIVE_ROUTER1 /
CATC_LIVE_ROUTER2 (OSPF neighbours over GigabitEthernet2; docs/live-tests.md). The device tests skip
themselves when those are unset or not Managed and Reachable. The path trace runs between
CATC_LIVE_PATH_TRACE ('source,dest'; default the two routers)."""

import contextlib
import json
import uuid
from typing import Any

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError

from catc_mcp.client import CatcApp

from .conftest import ROUTER1, ROUTER2, live_env, need
from .test_live_writes import apply, call, raw  # noqa: F401 - raw is a fixture

pytestmark = pytest.mark.live
RUN = uuid.uuid4().hex[:6]
R1, R2 = ROUTER1, ROUTER2
TRACE_SRC, _, TRACE_DST = live_env("CATC_LIVE_PATH_TRACE", f"{R1},{R2}").partition(",")


@pytest.fixture
async def routers(lab_rw: Client) -> dict[str, Any]:  # type: ignore[type-arg]
    """The two routers' inventory records, by management IP (skips unless both are Reachable)."""
    need("CATC_LIVE_ROUTER1", "CATC_LIVE_ROUTER2")
    found: dict[str, Any] = {}
    for ip in (R1, R2):
        try:
            found[ip] = await call(lab_rw, "catc_get_device", {"device": ip})
        except ToolError:
            pytest.skip(f"{ip} is not in the Catalyst Center inventory")
        if found[ip].get("reachabilityStatus") != "Reachable":
            pytest.skip(f"{ip} is not Reachable in Catalyst Center")
    return found


@pytest.fixture
async def area(lab_rw: Client, raw: CatcApp) -> Any:  # type: ignore[type-arg]  # noqa: F811
    name = f"mcp-test-p2-{RUN}"
    r = await apply(lab_rw, "catc_create_site", {"site_type": "area", "name": name})
    yield f"Global/{name}"
    with contextlib.suppress(Exception):
        await raw.run_job("DELETE", f"/dna/intent/api/v1/areas/{r['site_id']}")


async def test_credentials_and_site_assignment(lab_rw: Client, area: str, raw: CatcApp) -> None:  # type: ignore[type-arg]  # noqa: F811
    cli, ro = f"mcp-test-cli-{RUN}", f"mcp-test-ro-{RUN}"
    secret = f"Live-{RUN}-S3cret"
    preview = await call(
        lab_rw,
        "catc_create_global_credential",
        {"credential_type": "CLI", "description": cli, "username": "mcp", "password": secret},
    )
    assert secret not in json.dumps(preview)
    created = await apply(
        lab_rw,
        "catc_create_global_credential",
        {"credential_type": "CLI", "description": cli, "username": "mcp", "password": secret},
    )
    assert created["credential_id"]
    await apply(
        lab_rw,
        "catc_create_global_credential",
        {"credential_type": "SNMPV2_READ_COMMUNITY", "description": ro, "community": secret},
    )
    try:
        listed = await call(lab_rw, "catc_list_global_credentials", {"response_format": "json"})
        mine = {r["description"]: r for r in listed["results"] if RUN in r["description"]}
        assert set(mine) == {cli, ro} and secret not in json.dumps(listed)
        dup = await call(
            lab_rw,
            "catc_create_global_credential",
            {"credential_type": "CLI", "description": cli, "username": "x", "password": "y"},
        )
        assert dup["status"] == "blocked"
        await apply(lab_rw, "catc_assign_site_credentials", {"site": area, "credentials": [cli, ro]})
        settings = await call(lab_rw, "catc_get_site_settings", {"site": area, "categories": ["credentials"]})
        assert settings["settings"]["credentials"]["cliCredentialsId"]["credential"] == f"CLI:{cli}"
        again = await call(lab_rw, "catc_assign_site_credentials", {"site": area, "credentials": [cli]})
        assert again["status"] == "blocked"
    finally:
        # Remove the site first: Catalyst Center may refuse to delete credentials a site uses.
        with contextlib.suppress(Exception):
            site = await call(lab_rw, "catc_get_site", {"site": area})
            await raw.run_job("DELETE", f"/dna/intent/api/v1/areas/{site['id']}")
        for c in (cli, ro):
            with contextlib.suppress(Exception):
                await apply(lab_rw, "catc_delete_global_credential", {"credential": c})


async def test_site_settings_update(lab_rw: Client, area: str) -> None:  # type: ignore[type-arg]
    args = {
        "site": area,
        "dns_servers": ["192.0.2.53"],
        "domain_name": "mcp-test.lab",
        "ntp_servers": ["192.0.2.123"],
        "banner": f"mcp-test {RUN}",
        "syslog_servers": ["192.0.2.55"],
    }
    preview = await call(lab_rw, "catc_update_site_settings", args)
    assert set(preview["preview"]["changes"]) >= {"dns", "ntp", "banner", "telemetry"}
    done = await apply(lab_rw, "catc_update_site_settings", args)
    assert set(done["updated"].values()) == {"SUCCESS"}
    got = await call(
        lab_rw,
        "catc_get_site_settings",
        {"site": area, "categories": ["dns", "ntp", "banner"], "inherited": False},
    )
    assert got["settings"]["dns"]["dns"]["dnsServers"] == ["192.0.2.53"]
    assert got["settings"]["banner"]["banner"]["message"] == f"mcp-test {RUN}"
    again = await call(lab_rw, "catc_update_site_settings", args)
    assert again["status"] == "blocked"


async def test_ip_pool_lifecycle(lab_rw: Client, area: str) -> None:  # type: ignore[type-arg]
    gname, rname = f"mcp-test-gp-{RUN}", f"mcp-test-rp-{RUN}"
    octet = 200 + int(RUN, 16) % 50
    await apply(lab_rw, "catc_create_ip_pool", {"name": gname, "subnet": f"10.{octet}.0.0/16"})
    try:
        overlap = await call(lab_rw, "catc_create_ip_pool", {"name": "x", "subnet": f"10.{octet}.8.0/24"})
        assert overlap["status"] == "blocked"
        await apply(
            lab_rw,
            "catc_create_ip_pool",
            {
                "name": rname,
                "subnet": f"10.{octet}.1.0/24",
                "site": area,
                "global_pool": gname,
                "pool_type": "LAN",
            },
        )
        pools = await call(lab_rw, "catc_list_ip_pools", {"name": RUN, "response_format": "json"})
        assert {(p["name"], p["scope"]) for p in pools["results"]} == {(gname, "global"), (rname, "reserved")}
        blocked = await call(lab_rw, "catc_delete_ip_pool", {"pool": gname, "reserved": False})
        assert blocked["status"] == "blocked"
        await apply(lab_rw, "catc_delete_ip_pool", {"pool": rname})
    finally:
        with contextlib.suppress(Exception):
            await apply(lab_rw, "catc_delete_ip_pool", {"pool": rname})
        await apply(lab_rw, "catc_delete_ip_pool", {"pool": gname, "reserved": False})


async def test_platform_reads(lab_rw: Client) -> None:  # type: ignore[type-arg]
    health = await call(lab_rw, "catc_get_system_health", {})
    assert health["release"]["installedVersion"] and "by_state" in health["services"]
    for tool in ("catc_list_network_profiles", "catc_list_pnp_devices", "catc_list_ssids"):
        res = await lab_rw.call_tool(tool, {})
        assert not res.is_error
    fabric = await call(lab_rw, "catc_get_sda_fabric", {})
    assert "fabric_sites" in fabric


# --- device workflows (CATC_LIVE_ROUTER1/2) ----------------------------------------------------


async def test_device_troubleshooting_reads(lab_rw: Client, routers: dict[str, Any]) -> None:  # type: ignore[type-arg]
    d360 = await call(lab_rw, "catc_device_360", {"device": R1})
    assert d360["device"]["managementIpAddress"] == R1 and d360["interfaces"]["total"] >= 2
    hw = await call(lab_rw, "catc_get_device_hardware", {"device": R1})
    assert hw["module_count"] >= 1
    ifaces = await call(
        lab_rw, "catc_list_device_interfaces", {"device": R1, "name": "Gigabit", "response_format": "json"}
    )
    assert any(i["portName"] == "GigabitEthernet2" for i in ifaces["results"])
    cli = await call(
        lab_rw,
        "catc_run_show_commands",
        {"devices": [R1, R2], "commands": ["show ip ospf neighbor", "show version | include Version|uptime"]},
    )
    outputs = {r["device"]: r["output"] for r in cli["results"]}
    assert len(outputs) == 2
    for out in outputs.values():
        assert not out["show ip ospf neighbor"].startswith("show ")  # echo stripped
    trace = await call(lab_rw, "catc_path_trace", {"source_ip": TRACE_SRC, "dest_ip": TRACE_DST})
    assert trace["status"] in ("COMPLETED", "FAILED")
    if trace["status"] == "COMPLETED":
        assert trace["hops"][0]["ip"] == R1
    archive = await call(lab_rw, "catc_list_config_archive", {"device": R1, "response_format": "json"})
    assert archive["results"]
    diff = await call(lab_rw, "catc_compare_device_configs", {"device": R1, "compare": "startup"})
    assert "identical" in diff
    images = await call(lab_rw, "catc_list_device_images", {"response_format": "json"})
    assert any(i["managementAddress"] == R1 for i in images["results"])
    events = await call(lab_rw, "catc_list_events", {"device": R1, "hours": 24, "response_format": "json"})
    assert "results" in events


async def test_dayn_template_deploy_and_verify(lab_rw: Client, routers: dict[str, Any]) -> None:  # type: ignore[type-arg]
    proj, tpl = f"mcp-test-p2-{RUN}", "mcp-test-loopback"
    loop = 200 + int(RUN, 16) % 50
    params = {"loop_id": loop, "ip": f"10.99.{loop}.1"}
    await apply(lab_rw, "catc_create_template_project", {"name": proj})
    try:
        await apply(
            lab_rw,
            "catc_create_template",
            {
                "project": proj,
                "name": tpl,
                "device_families": ["Routers"],
                "content": "interface Loopback{{ loop_id }}\n ip address {{ ip }} 255.255.255.255\n",
            },
        )
        ref = f"{proj}/{tpl}"
        uncommitted = await call(
            lab_rw, "catc_deploy_template", {"template": ref, "devices": [R1], "params": params}
        )
        assert uncommitted["status"] == "blocked"
        await apply(lab_rw, "catc_commit_template", {"template": ref, "comment": "mcp live test"})
        prev = await call(lab_rw, "catc_preview_template", {"template": ref, "params": params, "device": R1})
        assert f"interface Loopback{loop}" in prev["cliPreview"]
        done = await apply(
            lab_rw, "catc_deploy_template", {"template": ref, "devices": [R1], "params": params}
        )
        assert done["deployment"]["status"] == "SUCCESS", done
        status = await call(lab_rw, "catc_get_template_deployment", {"deployment_id": done["deployment_id"]})
        assert status["devices"][0]["status"] == "SUCCESS"
        cli = await call(
            lab_rw,
            "catc_run_show_commands",
            {"devices": [R1], "commands": [f"show running-config interface Loopback{loop}"]},
        )
        assert params["ip"] in cli["results"][0]["output"][f"show running-config interface Loopback{loop}"]
        comp = await apply(lab_rw, "catc_run_compliance", {"devices": [R1], "categories": ["RUNNING_CONFIG"]})
        assert comp["status"] == "SUCCESS"
        detail = await call(
            lab_rw, "catc_get_compliance_detail", {"device": R1, "category": "RUNNING_CONFIG"}
        )
        assert detail["compliance"]
    finally:
        # Take the loopback off again with a second template, then remove the project.
        with contextlib.suppress(Exception):
            await apply(
                lab_rw,
                "catc_create_template",
                {
                    "project": proj,
                    "name": "mcp-test-undo",
                    "device_families": ["Routers"],
                    "content": f"no interface Loopback{loop}\n",
                },
            )
            await apply(
                lab_rw, "catc_commit_template", {"template": f"{proj}/mcp-test-undo", "comment": "undo"}
            )
            await apply(
                lab_rw, "catc_deploy_template", {"template": f"{proj}/mcp-test-undo", "devices": [R1]}
            )
        await apply(lab_rw, "catc_delete_template_project", {"project": proj})


async def test_tag_members_and_resync(lab_rw: Client, routers: dict[str, Any]) -> None:  # type: ignore[type-arg]
    name = f"mcp-test-tagdev-{RUN}"
    await apply(lab_rw, "catc_create_tag", {"name": name})
    try:
        await apply(lab_rw, "catc_update_tag_members", {"tag": name, "add": [R1, R2]})
        members = await call(lab_rw, "catc_list_tag_members", {"tag": name, "response_format": "json"})
        assert {m["managementIpAddress"] for m in members["results"]} == {R1, R2}
        noop = await call(lab_rw, "catc_update_tag_members", {"tag": name, "add": [R1]})
        assert noop["status"] == "blocked"
        await apply(lab_rw, "catc_update_tag_members", {"tag": name, "remove": [R2]})
        in_use = await call(lab_rw, "catc_delete_tag", {"tag": name})
        assert in_use["status"] == "blocked" and "remove_members" in in_use["blockers"][0]
    finally:
        await apply(lab_rw, "catc_delete_tag", {"tag": name, "remove_members": True})
    done = await apply(lab_rw, "catc_resync_devices", {"devices": [R2]})
    assert done["status"] == "SUCCESS"


async def test_provisioning_previews(lab_rw: Client, routers: dict[str, Any]) -> None:  # type: ignore[type-arg]
    """Preview only: the routers stay as they are (provisioning and delete were exercised by hand)."""
    with pytest.raises(ToolError, match="No site"):
        await lab_rw.call_tool(
            "catc_provision_devices", {"devices": [R1], "site": f"Global/mcp-test-none-{RUN}"}
        )
    prov = await call(lab_rw, "catc_provision_devices", {"devices": [R1], "site": "Global"})
    assert prov["status"] == "blocked"
    delete = await call(lab_rw, "catc_delete_device", {"device": R1, "clean_config": False})
    assert delete["status"] == "preview"  # not confirmed: r1 stays
