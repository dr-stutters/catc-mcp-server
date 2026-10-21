"""D102: LAN automation and fabric wireless reads (respx). Shapes follow the 3.2.2 lab appliance's live
answers (2026-10-21: no sessions, maxSupportedCount "5", status limit 1-10) and the spec."""

from typing import Any

import httpx
import pytest
import respx
from fastmcp.exceptions import ToolError

from .test_read_tools import AREA, BLDG, GLOBAL, call
from .test_sda import FABRIC, FID
from .test_write_tools import mock_sites

LAN = "/dna/intent/api/v1/lan-automation"
SDA = "/dna/intent/api/v1/sda"


def status_rows(n: int) -> list[dict[str, Any]]:
    return [
        {
            "id": f"la-{i}",
            "name": f"session-{i}",
            "status": "COMPLETED",
            "discoveredDeviceList": [{"serialNumber": "x"}],
            "ipPools": [{"ipPoolName": "mcp-underlay", "ipPoolRole": "MAIN_POOL"}],
            "discoveryLevel": 2,
        }
        for i in range(n)
    ]


async def test_lan_automation_pages_by_ten(api: respx.MockRouter) -> None:
    rows = status_rows(13)
    api.get(f"{LAN}/sessions").respond(
        json={"response": {"activeSessionIds": ["la-0"], "maxSupportedCount": "5"}}
    )

    def status(request: httpx.Request) -> httpx.Response:
        off, lim = int(request.url.params["offset"]), int(request.url.params["limit"])
        assert lim <= 10
        return httpx.Response(200, json={"response": rows[off - 1 : off - 1 + lim]})

    route = api.get(f"{LAN}/status").mock(side_effect=status)
    out = await call("catc_get_lan_automation")
    assert route.call_count == 2 and len(out["sessions"]) == 13
    assert out["sessions"][0] == {
        "id": "la-0",
        "name": "session-0",
        "status": "COMPLETED",
        "discoveryLevel": 2,
        "discovered_devices": 1,
        "ip_pools": ["mcp-underlay"],
    }
    assert out["active_sessions"] == ["la-0"] and out["max_sessions"] == "5" and "note" not in out


async def test_lan_automation_403_names_the_permission(api: respx.MockRouter) -> None:
    api.get(f"{LAN}/sessions").respond(
        403, json={"message": "Role does not have valid permissions to access the API"}
    )
    with pytest.raises(ToolError, match="Network Operations.LAN Automation Read"):
        await call("catc_get_lan_automation")


async def test_fabric_wireless(api: respx.MockRouter) -> None:
    mock_sites(api, [GLOBAL, AREA, BLDG])
    api.get(f"/dna/intent/api/v1/sites/{BLDG['id']}").respond(json={"response": BLDG})
    api.get(f"{SDA}/fabricSites").respond(json={"response": [FABRIC]})
    api.get(f"{SDA}/fabrics/vlanToSsids").respond(
        json={
            "response": [
                {
                    "fabricId": FID,
                    "vlanDetails": [
                        {
                            "vlanName": "MCP_WIFI",
                            "ssidDetails": [{"name": "mcp-ssid", "securityGroupTag": "Employees"}],
                        }
                    ],
                },
                {"fabricId": "other", "vlanDetails": []},
            ]
        }
    )
    api.get(f"{SDA}/fabrics/{FID}/switchWirelessSetting").respond(
        json={"response": [{"id": "d1", "enableRollingApUpgrade": False}]}
    )
    api.get(f"{SDA}/fabrics/{FID}/wirelessMulticast").respond(json={"response": {"multicastEnabled": False}})
    out = await call("catc_get_fabric_wireless")
    assert len(out["vlan_to_ssids"]) == 2 and "switch_wireless" not in out
    out = await call("catc_get_fabric_wireless", {"fabric_site": "Global/AU/SYD-1"})
    assert out["fabric_site"] == "Global/AU/SYD-1" and [r["fabricId"] for r in out["vlan_to_ssids"]] == [FID]
    assert out["switch_wireless"] == [{"id": "d1", "enableRollingApUpgrade": False}]
    assert out["wireless_multicast"] == {"multicastEnabled": False}


async def test_nothing_configured(api: respx.MockRouter) -> None:
    api.get(f"{LAN}/sessions").respond(json={"response": {"activeSessionIds": [], "maxSupportedCount": "5"}})
    api.get(f"{LAN}/status").respond(json={"response": []})
    api.get(f"{SDA}/fabrics/vlanToSsids").respond(json={"response": []})
    assert (await call("catc_get_lan_automation"))["note"].startswith("No LAN automation sessions")
    assert (await call("catc_get_fabric_wireless"))["note"].startswith("No fabric-enabled wireless")
