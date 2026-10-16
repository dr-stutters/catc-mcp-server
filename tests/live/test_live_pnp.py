"""D11 live: claim a factory-fresh router from Plug and Play with a day-0 template, and RMA.

Needs an Unclaimed device in PnP: CATC_LIVE_PNP_SERIAL is its serial, or `auto` for the first Unclaimed
C8000V. docs/pnp.md describes the lab behind it (DHCP option 43 -> Catalyst Center, and the CML day-0
workaround that points a cat8000v at Catalyst Center from its console).

test_claim_with_day0_template: claims it to CATC_LIVE_FLOOR with an onboarding template giving it the
CLI/SNMP credentials CATC_LIVE_DEVICE_USERNAME / CATC_LIVE_DEVICE_PASSWORD / CATC_LIVE_SNMP_RO /
CATC_LIVE_SNMP_RW, waits for Provisioned, checks the inventory, then removes the device, the PnP entry and
the template.

test_rma_replace (CATC_LIVE_RMA=1): mark CATC_LIVE_RMA_DEVICE (default CATC_LIVE_ROUTER2; it must be
Unreachable, e.g. stopped) for replacement and replace it with the Unclaimed PnP device."""

import asyncio
import contextlib
from typing import Any

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError

from .conftest import FLOOR, ROUTER2, live_env, need
from .test_live_writes import RUN, apply, call

pytestmark = pytest.mark.live

DAY0_VARS = (
    "CATC_LIVE_DEVICE_USERNAME",
    "CATC_LIVE_DEVICE_PASSWORD",
    "CATC_LIVE_SNMP_RO",
    "CATC_LIVE_SNMP_RW",
)
PROJECT = "Onboarding Configuration"
DAY0 = """ip domain name example.com
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


async def unclaimed(c: Client) -> dict[str, Any] | None:  # type: ignore[type-arg]
    """The Unclaimed PnP device CATC_LIVE_PNP_SERIAL names (`auto`: the first C8000V), else None."""
    (want,) = need("CATC_LIVE_PNP_SERIAL")
    out = await call(c, "catc_list_pnp_devices", {"state": "Unclaimed", "response_format": "json"})
    for r in out.get("results", []):
        if r.get("serial") == want or (want == "auto" and r.get("pid") == "C8000V"):
            return dict(r)
    return None


async def test_claim_with_day0_template(lab_rw: Client) -> None:  # type: ignore[type-arg]
    need(*DAY0_VARS, "CATC_LIVE_FLOOR")
    dev = await unclaimed(lab_rw)
    if not dev:
        pytest.skip("CATC_LIVE_PNP_SERIAL is not an Unclaimed device in PnP (see the module docstring)")
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
            "cli_user": live_env("CATC_LIVE_DEVICE_USERNAME"),
            "cli_password": live_env("CATC_LIVE_DEVICE_PASSWORD"),
            "snmp_ro": live_env("CATC_LIVE_SNMP_RO"),
            "snmp_rw": live_env("CATC_LIVE_SNMP_RW"),
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
    if live_env("CATC_LIVE_RMA") != "1":
        pytest.skip("set CATC_LIVE_RMA=1 (CATC_LIVE_RMA_DEVICE Unreachable, CATC_LIVE_PNP_SERIAL Unclaimed)")
    faulty = live_env("CATC_LIVE_RMA_DEVICE", ROUTER2)
    if not faulty:
        need("CATC_LIVE_RMA_DEVICE")
    new = await unclaimed(lab_rw)
    old = await call(lab_rw, "catc_get_device", {"device": faulty})
    if not new or old.get("reachabilityStatus") == "Reachable":
        pytest.skip(f"needs {faulty} Unreachable and an Unclaimed PnP device")
    name = str(old.get("hostname") or faulty).split(".")[0]
    await apply(lab_rw, "catc_mark_device_for_replacement", {"device": faulty})
    listed = await call(lab_rw, "catc_list_device_replacements", {"response_format": "json"})
    assert any(r.get("faultyDeviceName", "").startswith(name) for r in listed["results"])
    done = await apply(lab_rw, "catc_replace_device", {"faulty": faulty, "replacement_serial": new["serial"]})
    assert any(r.get("replacementStatus") == "REPLACED" for r in done["replacement"]), done
