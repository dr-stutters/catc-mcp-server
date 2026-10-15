"""D8 live: Catalyst Center <-> ISE integration and per-site AAA, proven on a provisioned switch.

- ISE (198.18.134.35, pxGrid persona on) must be reachable. With CATC_LIVE_ISE_CYCLE=1 an existing
  integration is removed and rebuilt through the tools (add -> certificate -> COMPLETE); otherwise an
  existing integration is reused and only the add tool's 'already integrated' block is checked.
- The switch test needs the `mcp-catc-onboard` CML lab (cat9000v sw2 198.18.128.170) and the
  seeded mcp-test-cli / mcp-test-snmp-ro credentials. It creates building
  Global/mcp-test-lab/mcp-test-nac with client AAA -> ISE, discovers + provisions sw2 there, checks
  the pushed aaa/radius config and the NAD Catalyst Center created in ISE (ERS), then removes the
  device (with its config and the NAD), the building and the discovery.

ISE credentials: LAB_ISE_USERNAME / LAB_ISE_PASSWORD; RADIUS secret LAB_RADIUS_SECRET (.env)."""

import asyncio
import contextlib
import os
from pathlib import Path
from typing import Any

import httpx
import pytest
from dotenv import dotenv_values
from fastmcp import Client
from fastmcp.exceptions import ToolError

from .test_live_writes import RUN, apply, call

pytestmark = pytest.mark.live

ENV = {**dotenv_values(Path(__file__).resolve().parents[2] / ".env"), **os.environ}
ISE_IP, ISE_FQDN = "198.18.134.35", "ise.demo.dcloud.cisco.com"
SW = "198.18.128.170"
AREA = "Global/mcp-test-lab"
NAC_BLDG = f"{AREA}/mcp-test-nac"


def _need(*names: str) -> None:
    missing = [n for n in names if not ENV.get(n)]
    if missing:
        pytest.skip(f"set {', '.join(missing)} in .env")


async def ise_nads(ip: str) -> list[dict[str, Any]]:
    """NADs in ISE whose IP is `ip` (ERS), with the CatC-created ones."""
    async with httpx.AsyncClient(
        verify=False, auth=(str(ENV["LAB_ISE_USERNAME"]), str(ENV["LAB_ISE_PASSWORD"])), timeout=30
    ) as h:
        r = await h.get(
            f"https://{ISE_IP}/ers/config/networkdevice",
            params={"filter": f"ipaddress.EQ.{ip}"},
            headers={"Accept": "application/json"},
        )
        r.raise_for_status()
        return list(r.json().get("SearchResult", {}).get("resources", []))


async def delete_ise_nads(ip: str) -> None:
    async with httpx.AsyncClient(
        verify=False, auth=(str(ENV["LAB_ISE_USERNAME"]), str(ENV["LAB_ISE_PASSWORD"])), timeout=30
    ) as h:
        for nad in await ise_nads(ip):
            r = await h.delete(f"https://{ISE_IP}/ers/config/networkdevice/{nad['id']}")
            r.raise_for_status()


async def _ise_integrated(c: Client) -> dict[str, Any] | None:  # type: ignore[type-arg]
    out = await call(c, "catc_get_policy_servers", {})
    for s in out["servers"]:
        if s.get("isIseEnabled"):
            return s
    return None


async def test_ise_integration(lab_rw: Client) -> None:  # type: ignore[type-arg]
    _need("LAB_ISE_USERNAME", "LAB_ISE_PASSWORD", "LAB_RADIUS_SECRET")
    add_args = {
        "ip": ISE_IP,
        "fqdn": ISE_FQDN,
        "username": ENV["LAB_ISE_USERNAME"],
        "password": ENV["LAB_ISE_PASSWORD"],
        "shared_secret": ENV["LAB_RADIUS_SECRET"],
        "protocol": "RADIUS_TACACS",
        "description": "mcp-test-catc ISE integration",
    }
    existing = await _ise_integrated(lab_rw)
    if existing and ENV.get("CATC_LIVE_ISE_CYCLE") != "1":
        blocked = await call(lab_rw, "catc_add_ise_server", add_args)
        assert blocked["status"] == "blocked"
        assert existing["ise_nodes"][0]["trustState"] == "TRUSTED"
        return
    if existing:
        await apply(lab_rw, "catc_delete_policy_server", {"server": ISE_IP})
        for _ in range(20):
            if not await _ise_integrated(lab_rw):
                break
            await asyncio.sleep(6)
    added = await apply(lab_rw, "catc_add_ise_server", add_args)
    secrets = (str(ENV["LAB_ISE_PASSWORD"]), str(ENV["LAB_RADIUS_SECRET"]))
    leaked = any(s in str(added) for s in secrets)
    assert not leaked, "a secret appeared in the result"
    integ = added["integration"]
    if integ["status"] == "WAITING_USER_INPUT":
        assert integ["certificate_to_accept"][0]["fingerPrints"]
        done = await apply(lab_rw, "catc_accept_ise_certificate", {})
        integ = done["integration"]
    assert integ["status"] == "COMPLETE", integ
    srv = await _ise_integrated(lab_rw)
    assert srv and {n["role"] for n in srv["ise_nodes"]} >= {"PRIMARY"}


async def test_site_aaa_pushes_radius_and_creates_nad(lab_rw: Client) -> None:  # type: ignore[type-arg]
    _need("LAB_ISE_USERNAME", "LAB_ISE_PASSWORD", "LAB_RADIUS_SECRET")
    if not await _ise_integrated(lab_rw):
        pytest.skip("ISE is not integrated (run test_ise_integration first)")
    with contextlib.suppress(ToolError):
        await call(lab_rw, "catc_get_device", {"device": SW})
        pytest.skip(f"{SW} is already in the inventory; delete it first")
    disc = f"mcp-test-nac-{RUN}"
    created_bldg = False
    inherit_blocked = None
    try:
        try:
            await call(lab_rw, "catc_get_site", {"site": NAC_BLDG})
        except ToolError:
            await apply(
                lab_rw,
                "catc_create_site",
                {
                    "site_type": "building",
                    "name": "mcp-test-nac",
                    "parent": AREA,
                    "address": "1 Martin Place, Sydney NSW 2000",
                    "latitude": -33.8675,
                    "longitude": 151.2070,
                    "country": "Australia",
                },
            )
            created_bldg = True
        ise = {"server_type": "ISE", "protocol": "RADIUS", "primary": ISE_IP}
        preview = await call(
            lab_rw,
            "catc_update_site_aaa_settings",
            {"site": NAC_BLDG, "client": ise, "client_shared_secret": ENV["LAB_RADIUS_SECRET"]},
        )
        leaked = str(ENV["LAB_RADIUS_SECRET"]) in str(preview)
        assert not leaked, "the RADIUS secret appeared in the preview"
        await apply(
            lab_rw,
            "catc_update_site_aaa_settings",
            {"site": NAC_BLDG, "client": ise, "client_shared_secret": ENV["LAB_RADIUS_SECRET"]},
        )
        got = await call(lab_rw, "catc_get_site_settings", {"site": NAC_BLDG, "categories": ["aaa"]})
        assert ISE_IP in str(got)

        await apply(
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
        dev: dict[str, Any] = {}
        for _ in range(40):
            dev = await call(lab_rw, "catc_get_device", {"device": SW})
            if dev.get("reachabilityStatus") == "Reachable" and dev.get("collectionStatus") == "Managed":
                break
            await asyncio.sleep(15)
        assert dev.get("collectionStatus") == "Managed", dev
        await apply(lab_rw, "catc_assign_devices_to_site", {"devices": [SW], "site": NAC_BLDG})
        prov = await apply(lab_rw, "catc_provision_devices", {"devices": [SW], "site": NAC_BLDG})
        assert "SUCCESS" in str(prov).upper(), prov
        cli = await call(
            lab_rw,
            "catc_run_show_commands",
            {"devices": [SW], "commands": ["show running-config | section aaa|radius"]},
        )
        text = str(cli)
        assert ISE_IP in text and "radius server" in text, cli
        nads: list[dict[str, Any]] = []
        for _ in range(12):
            nads = await ise_nads(SW)
            if nads:
                break
            await asyncio.sleep(10)
        assert nads, "Catalyst Center did not create the NAD in ISE"
    finally:
        with contextlib.suppress(Exception):
            await apply(lab_rw, "catc_delete_device", {"device": SW, "clean_config": True})
        # No parent sets client AAA, so Catalyst Center can't clear it (NCND00070): the tool blocks.
        with contextlib.suppress(Exception):
            blocked = await call(
                lab_rw, "catc_update_site_aaa_settings", {"site": NAC_BLDG, "inherit": ["client"]}
            )
            inherit_blocked = blocked["status"] == "blocked"
        if created_bldg:
            with contextlib.suppress(Exception):
                await apply(lab_rw, "catc_delete_site", {"site": NAC_BLDG})
        with contextlib.suppress(Exception):
            await apply(lab_rw, "catc_delete_discovery", {"discovery": disc})
    # Deleting the device does NOT remove the NAD Catalyst Center created in ISE (3.2.2 + ISE 3.5):
    # remove it here so the run leaves nothing behind.
    await delete_ise_nads(SW)
    assert not await ise_nads(SW)
    assert inherit_blocked in (True, None)
