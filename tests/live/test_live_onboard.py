"""D3 + D6 live: onboard a fresh CML switch through the `catc_onboard_device` prompt's steps, with a
switching profile whose Day-N template provisioning must apply.

Needs the `mcp-catc-onboard` CML lab (one cat9000v-uadp, mcp-catc-sw2 198.18.128.170, CLI
netadmin, SNMP mcp-ro/mcp-rw like catc-routers) and the mcp-test-cli / mcp-test-snmp-ro global
credentials. Skips when the switch can't be reached. Leaves nothing behind: the switch is deleted
from the inventory (with its pushed config), and the profile, template project and discovery are
removed."""

import asyncio
import contextlib
from typing import Any

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError

from catc_mcp.client import CatcApp

from .test_live_writes import RUN, apply, call, raw  # noqa: F401 - raw is a fixture

pytestmark = pytest.mark.live

SW = "198.18.128.170"
SITE = "Global/mcp-test-lab/mcp-test-bldg"
LOOP = "Loopback88"


async def _creds_present(c: Client) -> bool:  # type: ignore[type-arg]
    out = await call(c, "catc_list_global_credentials", {"response_format": "json"})
    names = {str(r.get("description")) for r in out.get("results", [])}
    return {"mcp-test-cli", "mcp-test-snmp-ro"} <= names


async def test_onboard_switch_with_profile_template(lab_rw: Client, raw: CatcApp) -> None:  # type: ignore[type-arg]  # noqa: F811
    if not await _creds_present(lab_rw):
        pytest.skip("mcp-test-cli / mcp-test-snmp-ro global credentials missing (scripts/lab_state.py seed)")
    with contextlib.suppress(ToolError):
        await call(lab_rw, "catc_get_device", {"device": SW})
        pytest.skip(f"{SW} is already in the inventory; delete it first")

    prompt = await lab_rw.get_prompt(
        "catc_onboard_device",
        {
            "ip_or_range": SW,
            "site_path": SITE,
            "cli_credential": "mcp-test-cli",
            "snmp_credential": "mcp-test-snmp-ro",
        },
    )
    text = prompt.messages[0].content.text  # type: ignore[union-attr]
    assert "`catc_create_discovery`" in text and "`catc_provision_devices`" in text

    profile, proj, tpl = f"mcp-test-sw-{RUN}", f"mcp-test-d3-{RUN}", "mcp-test-d3-loop"
    disc = f"mcp-test-onboard-{RUN}"
    profile_id = None
    try:
        # D3: a switching profile with a Day-N template, assigned to the building.
        created = await apply(lab_rw, "catc_create_switching_profile", {"name": profile})
        profile_id = created["profile_id"]
        await apply(lab_rw, "catc_create_template_project", {"name": proj})
        await apply(
            lab_rw,
            "catc_create_template",
            {
                "project": proj,
                "name": tpl,
                "device_families": ["Switches and Hubs"],
                "content": f"interface {LOOP}\n description mcp-test-d3 profile template\n"
                " ip address 10.88.88.1 255.255.255.255\n",
            },
        )
        await apply(lab_rw, "catc_commit_template", {"template": f"{proj}/{tpl}", "comment": "d3"})
        await apply(
            lab_rw, "catc_attach_template_to_profile", {"template": f"{proj}/{tpl}", "profiles": [profile]}
        )
        await apply(lab_rw, "catc_assign_profile_to_sites", {"profile": profile, "sites": [SITE]})
        got = await call(lab_rw, "catc_get_network_profile", {"profile": profile})
        assert [t["name"] for t in got["templates"]] == [tpl] and SITE in got["sites"]

        # D6: the prompt's steps.
        found = await apply(
            lab_rw,
            "catc_create_discovery",
            {
                "name": disc,
                "ip_ranges": [SW],
                "discovery_type": "Range",
                "global_credentials": ["mcp-test-cli", "mcp-test-snmp-ro"],
                "wait": True,
            },
        )
        # Discovery ends before the inventory sync: wait for Reachable + Managed (a few minutes).
        dev: dict[str, Any] = {}
        for _ in range(40):
            dev = await call(lab_rw, "catc_get_device", {"device": SW})
            if dev.get("reachabilityStatus") == "Reachable" and dev.get("collectionStatus") == "Managed":
                break
            await asyncio.sleep(15)
        assert dev.get("collectionStatus") == "Managed", (found, dev)
        site = await call(lab_rw, "catc_get_site", {"site": SITE})
        assert site.get("type") == "building"
        await call(lab_rw, "catc_get_site_settings", {"site": SITE})
        await apply(lab_rw, "catc_assign_devices_to_site", {"devices": [SW], "site": SITE})
        prov = await apply(lab_rw, "catc_provision_devices", {"devices": [SW], "site": SITE})
        assert "SUCCESS" in str(prov).upper(), prov
        d360 = await call(lab_rw, "catc_device_360", {"device": SW})
        assert d360
        await apply(lab_rw, "catc_run_compliance", {"devices": [SW], "categories": ["NETWORK_SETTINGS"]})
        # 3.2.2: the provisioning API doesn't apply the profile's Day-N templates; deploy it.
        dep = await apply(lab_rw, "catc_deploy_template", {"template": f"{proj}/{tpl}", "devices": [SW]})
        assert dep["deployment"]["status"] == "SUCCESS", dep
        cli = await call(
            lab_rw,
            "catc_run_show_commands",
            {
                "devices": [SW],
                "commands": [
                    f"show running-config interface {LOOP}",
                    "show running-config | include ntp server",
                ],
            },
        )
        text = str(cli)
        assert "10.88.88.1" in text, cli  # the profile's Day-N template was applied
        assert "ntp server" in text, cli  # the site's NTP setting was pushed
        act = await call(
            lab_rw, "catc_recent_activity", {"device": SW, "hours": 1, "response_format": "json"}
        )
        assert act["counts"]
    finally:
        with contextlib.suppress(Exception):
            await apply(lab_rw, "catc_delete_device", {"device": SW, "clean_config": True})
        with contextlib.suppress(Exception):
            await apply(lab_rw, "catc_unassign_profile_from_sites", {"profile": profile, "sites": [SITE]})
        with contextlib.suppress(Exception):
            await apply(
                lab_rw,
                "catc_detach_template_from_profile",
                {"template": f"{proj}/{tpl}", "profiles": [profile]},
            )
        with contextlib.suppress(Exception):
            await apply(lab_rw, "catc_delete_template_project", {"project": proj})
        if profile_id:
            with contextlib.suppress(Exception):
                await raw.run_job("DELETE", f"/dna/intent/api/v1/networkProfilesForSites/{profile_id}")
        with contextlib.suppress(Exception):
            await apply(lab_rw, "catc_delete_discovery", {"discovery": disc})
