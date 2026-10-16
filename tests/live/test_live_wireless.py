"""Live wireless flow (D14) on a Catalyst 9800 WLC (CATC_LIVE_WLC, its management IP; a 9800-CL is
enough), discovered into Catalyst Center (the test assigns it to CATC_LIVE_BUILDING).

SSIDs mcp-test-catc-psk (WPA2-PSK) and mcp-test-catc-dot1x (WPA2-Enterprise) -> wireless profile ->
assigned to CATC_LIVE_FLOOR -> WLC provisioned with that floor as its managed AP location -> `show wlan
summary` on the WLC lists both WLANs -> profile and SSIDs removed again. The WLANs stay on the WLC
(Catalyst Center doesn't remove them when the design objects go; fixed names keep re-runs from piling
up). No APs needed.
"""

from __future__ import annotations

import contextlib
from typing import Any

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError

from .conftest import BUILDING, FLOOR, live_env, need, require_reachable
from .test_live_writes import apply, call

pytestmark = pytest.mark.live

WLC = live_env("CATC_LIVE_WLC")
BLDG = BUILDING
PSK, DOT1X, PROFILE = "mcp-test-catc-psk", "mcp-test-catc-dot1x", "mcp-test-wl-profile"


async def test_wireless_design_and_wlc_provisioning(lab_rw: Client[Any]) -> None:
    need("CATC_LIVE_WLC", "CATC_LIVE_BUILDING", "CATC_LIVE_FLOOR")
    require_reachable(WLC, "CATC_LIVE_WLC")
    try:
        await call(lab_rw, "catc_get_device", {"device": WLC})
    except ToolError:
        pytest.skip(f"the WLC is not in the inventory (catc_create_discovery for {WLC})")
    try:
        out = await call(
            lab_rw,
            "catc_create_ssid",
            {"ssid": PSK, "security": "WPA2_PERSONAL", "passphrase": "mcp-test-psk-1234"},
        )
        assert "mcp-test-psk-1234" not in str(out)
        await apply(
            lab_rw,
            "catc_create_ssid",
            {"ssid": PSK, "security": "WPA2_PERSONAL", "passphrase": "mcp-test-psk-1234"},
        )
        await apply(lab_rw, "catc_create_ssid", {"ssid": DOT1X, "security": "WPA2_ENTERPRISE"})
        blocked = await call(
            lab_rw, "catc_create_wireless_profile", {"name": PROFILE, "ssids": [PSK, "mcp-test-none"]}
        )
        assert blocked["status"] == "blocked"
        await apply(lab_rw, "catc_create_wireless_profile", {"name": PROFILE, "ssids": [PSK, DOT1X]})
        refused = await call(lab_rw, "catc_delete_ssid", {"ssid": PSK})
        assert refused["status"] == "blocked"  # still in the profile
        await apply(lab_rw, "catc_assign_profile_to_sites", {"profile": PROFILE, "sites": [FLOOR]})
        with contextlib.suppress(AssertionError):  # already there on re-runs
            await apply(lab_rw, "catc_assign_devices_to_site", {"devices": [WLC], "site": BLDG})
        prov = await call(
            lab_rw, "catc_provision_wireless_controller", {"device": WLC, "managed_ap_locations": [FLOOR]}
        )
        assert sorted(prov["preview"]["wireless_profiles_pushed"][PROFILE]) == sorted([PSK, DOT1X])
        await apply(
            lab_rw, "catc_provision_wireless_controller", {"device": WLC, "managed_ap_locations": [FLOOR]}
        )
        state = await call(lab_rw, "catc_get_wireless_controller", {"device": WLC})
        assert state["provision_status"]["networkIntentProvisionStatus"] == "SUCCESS"
        assert {s["ssidName"] for s in state["ssids"]} >= {PSK, DOT1X}
        cli = await call(
            lab_rw, "catc_run_show_commands", {"devices": [WLC], "commands": ["show wlan summary"]}
        )
        text = str(cli)
        assert PSK in text and DOT1X in text and "[PSK]" in text and "[802.1x]" in text
    finally:
        with contextlib.suppress(Exception):
            await apply(lab_rw, "catc_unassign_profile_from_sites", {"profile": PROFILE, "sites": [FLOOR]})
        with contextlib.suppress(Exception):
            await apply(lab_rw, "catc_delete_wireless_profile", {"name": PROFILE})
        for ssid in (PSK, DOT1X):
            with contextlib.suppress(Exception):
                await apply(lab_rw, "catc_delete_ssid", {"ssid": ssid})
