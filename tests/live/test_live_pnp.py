"""D11 live: claim a factory-fresh cat8000v from Plug and Play with a day-0 template, and RMA.

Lab: CML `mcp-catc-pnp` (ext + mgmt-sw + `dhcp` alpine 198.18.128.171 running udhcpd for pnp1's MAC
only, with option 43 '5A1D;B2;K4;I198.18.128.11;J80' + `pnp1` cat8000v with an empty day-0 config).
See notes: on CML the c8000v's DHCP autoinstall is suppressed (CML attaches a day-0 CD), so pnp1 is
pointed at Catalyst Center with `pnp profile pnp-zero-touch` + `ip address dhcp` on its console.

test_claim_with_day0_template: claims the Unclaimed C8000V to mcp-test-floor1 with an onboarding
template giving it the lab CLI/SNMP credentials, waits for Provisioned, checks the inventory, then
removes the device, the PnP entry and the template.

test_rma_replace (CATC_LIVE_RMA=1 and the claimed state from the lab): mark r2 (stopped in CML, so
Unreachable) for replacement and replace it with the Unclaimed pnp1."""

import asyncio
import contextlib
import os
from pathlib import Path
from typing import Any

import pytest
from dotenv import dotenv_values
from fastmcp import Client
from fastmcp.exceptions import ToolError

from .test_live_writes import RUN, apply, call

pytestmark = pytest.mark.live

ENV = {**dotenv_values(Path(__file__).resolve().parents[2] / ".env"), **os.environ}
FLOOR = "Global/mcp-test-lab/mcp-test-bldg/mcp-test-floor1"
PROJECT = "Onboarding Configuration"
DAY0 = """ip domain name mcp.lab
username {{ cli_user }} privilege 15 secret {{ cli_password }}
enable secret {{ cli_password }}
aaa new-model
aaa authentication login default local
aaa authorization exec default local
ip ssh version 2
snmp-server community {{ snmp_ro }} RO
snmp-server community {{ snmp_rw }} RW
line vty 0 4
 transport input ssh
"""


async def unclaimed_c8kv(c: Client) -> dict[str, Any] | None:  # type: ignore[type-arg]
    out = await call(c, "catc_list_pnp_devices", {"state": "Unclaimed", "response_format": "json"})
    for r in out.get("results", []):
        if r.get("pid") == "C8000V":
            return dict(r)
    return None


async def test_claim_with_day0_template(lab_rw: Client) -> None:  # type: ignore[type-arg]
    for v in ("LAB_CLI_USERNAME", "LAB_CLI_PASSWORD", "LAB_SNMP_RO", "LAB_SNMP_RW"):
        if not ENV.get(v):
            pytest.skip(f"{v} missing in .env")
    dev = await unclaimed_c8kv(lab_rw)
    if not dev:
        pytest.skip("no Unclaimed C8000V in PnP (start mcp-catc-pnp, see the module docstring)")
    serial = str(dev["serial"])
    name = f"mcp-test-day0-{RUN}"
    tpl = f"{PROJECT}/{name}"
    hostname = f"mcp-catc-pnp-{RUN}"
    claimed_ip = None
    await apply(
        lab_rw,
        "catc_create_template",
        {"project": PROJECT, "name": name, "content": DAY0, "device_families": ["Routers"]},
    )
    try:
        await apply(lab_rw, "catc_commit_template", {"template": tpl, "comment": "mcp day-0"})
        params = {
            "cli_user": ENV["LAB_CLI_USERNAME"],
            "cli_password": ENV["LAB_CLI_PASSWORD"],
            "snmp_ro": ENV["LAB_SNMP_RO"],
            "snmp_rw": ENV["LAB_SNMP_RW"],
        }
        missing = await call(
            lab_rw, "catc_claim_pnp_device", {"device": serial, "site": FLOOR, "template": tpl}
        )
        assert missing["status"] == "blocked" and "cli_password" in str(missing["blockers"])
        done = await apply(
            lab_rw,
            "catc_claim_pnp_device",
            {"device": serial, "site": FLOOR, "template": tpl, "params": params, "hostname": hostname},
        )
        assert done["device"]["state"] == "Provisioned", done
        inv: dict[str, Any] = {}
        for _ in range(40):
            with contextlib.suppress(ToolError):
                inv = await call(lab_rw, "catc_get_device", {"device": serial})
                if inv.get("collectionStatus") == "Managed":
                    break
            await asyncio.sleep(15)
        claimed_ip = inv.get("managementIpAddress")
        assert inv.get("hostname", "").startswith(hostname), inv
        assert inv.get("collectionStatus") == "Managed", inv
        at_site = await call(lab_rw, "catc_list_devices", {"site": FLOOR, "response_format": "json"})
        assert serial in str(at_site), at_site
    finally:
        if claimed_ip:
            with contextlib.suppress(Exception):
                await apply(lab_rw, "catc_delete_device", {"device": serial, "clean_config": False})
        # Deleting the device also removes its PnP entry; this only matters if the claim failed.
        with contextlib.suppress(Exception):
            await apply(lab_rw, "catc_delete_pnp_device", {"device": serial})
        with contextlib.suppress(Exception):
            await apply(lab_rw, "catc_delete_template", {"template": tpl})


async def test_rma_replace(lab_rw: Client) -> None:  # type: ignore[type-arg]
    if ENV.get("CATC_LIVE_RMA") != "1":
        pytest.skip("set CATC_LIVE_RMA=1 (r2 stopped in CML, pnp1 Unclaimed)")
    new = await unclaimed_c8kv(lab_rw)
    r2 = await call(lab_rw, "catc_get_device", {"device": "r2.mcp.lab"})
    if not new or r2.get("reachabilityStatus") == "Reachable":
        pytest.skip("needs r2 Unreachable and an Unclaimed C8000V")
    await apply(lab_rw, "catc_mark_device_for_replacement", {"device": "r2.mcp.lab"})
    listed = await call(lab_rw, "catc_list_device_replacements", {"response_format": "json"})
    assert any(r.get("faultyDeviceName", "").startswith("r2") for r in listed["results"])
    done = await apply(
        lab_rw, "catc_replace_device", {"faulty": "r2.mcp.lab", "replacement_serial": new["serial"]}
    )
    assert any(r.get("replacementStatus") == "REPLACED" for r in done["replacement"]), done
