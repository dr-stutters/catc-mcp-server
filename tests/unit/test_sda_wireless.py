"""D124: SD-Access fabric wireless writes (respx); payloads follow the 3.2.2 spec's
business/sda/wireless-controller, sda/fabrics/{fabricId}/vlanToSsids and wirelessMulticast."""

import json
from typing import Any

import httpx
import pytest
import respx
from fastmcp.exceptions import ToolError

from .test_read_tools import AREA, BLDG, DEVICE, GLOBAL
from .test_sda import FABRIC, FID, flow
from .test_write_tools import mock_sites, task_ok

SDA = "/dna/intent/api/v1/sda"
BIZ = "/dna/intent/api/v1/business/sda/wireless-controller"
EXEC = "/dna/platform/management/business-api/v1/execution-status"
WLC_ID = "22222222-3333-4444-5555-666666666666"
WLC = {
    **DEVICE,
    "id": WLC_ID,
    "hostname": "mcp-wlc1",
    "managementIpAddress": "192.0.2.50",
    "family": "Wireless Controller",
}
CP = {
    "id": "fd-cp",
    "networkDeviceId": "d-cp",
    "fabricId": FID,
    "deviceRoles": ["CONTROL_PLANE_NODE", "BORDER_NODE"],
}
WLC_FD = {
    "id": "fd-w",
    "networkDeviceId": WLC_ID,
    "fabricId": FID,
    "deviceRoles": ["WIRELESS_CONTROLLER_NODE"],
}
GW_USERS = {
    "id": "gw-1",
    "fabricId": FID,
    "virtualNetworkName": "MCP_VN",
    "ipPoolName": "mcp-wifi-users",
    "vlanName": "MCP_WIFI",
    "vlanId": 1031,
    "isWirelessPool": True,
}
GW_WIRED = {
    **GW_USERS,
    "id": "gw-2",
    "ipPoolName": "mcp-wired",
    "vlanName": "MCP_WIRED",
    "vlanId": 1032,
    "isWirelessPool": False,
}
GW_INFRA = {
    **GW_USERS,
    "id": "gw-3",
    "virtualNetworkName": "INFRA_VN",
    "ipPoolName": "mcp-ap",
    "vlanName": "AP_VLAN",
    "vlanId": 2045,
}


class Lab:
    def __init__(
        self,
        api: respx.MockRouter,
        *,
        fabric_devices: list[dict[str, Any]] | None = None,
        mapping: list[dict[str, Any]] | None = None,
        wlc_site: str | None = "Global/AU/SYD-1",
        multicast: bool = False,
    ) -> None:
        self.devices = list(fabric_devices if fabric_devices is not None else [CP])
        self.mapping = list(mapping or [])
        self.multicast = multicast
        self.sent: list[tuple[str, str, Any, dict[str, str]]] = []
        api.get("/dna/intent/api/v1/network-device").respond(json={"response": [WLC]})
        api.get(f"/dna/intent/api/v1/network-device/{WLC_ID}").respond(json={"response": WLC})
        api.get(f"/dna/intent/api/v1/networkDevices/{WLC_ID}/assignedToSite").respond(
            json={"response": {"siteNameHierarchy": wlc_site} if wlc_site else {}}
        )
        mock_sites(api, [GLOBAL, AREA, BLDG])
        api.get(f"/dna/intent/api/v1/sites/{BLDG['id']}").respond(json={"response": BLDG})
        api.get(f"{SDA}/fabricSites").respond(json={"response": [FABRIC]})
        api.get(f"{SDA}/fabricDevices").mock(
            side_effect=lambda r: httpx.Response(200, json={"response": self.devices})
        )
        api.get(f"{SDA}/anycastGateways").respond(json={"response": [GW_USERS, GW_WIRED, GW_INFRA]})
        api.get(f"{SDA}/fabrics/{FID}/vlanToSsids").mock(
            side_effect=lambda r: httpx.Response(200, json={"response": self.mapping})
        )
        api.get(f"{SDA}/fabrics/{FID}/wirelessMulticast").mock(
            side_effect=lambda r: httpx.Response(200, json={"response": {"multicastEnabled": self.multicast}})
        )
        api.get(f"/dna/intent/api/v1/sites/{GLOBAL['id']}/wirelessSettings/ssids").respond(
            json={"response": [{"ssid": "mcp-corp"}, {"ssid": "mcp-guest"}]}
        )
        api.get(f"/dna/intent/api/v1/sites/{BLDG['id']}/wirelessSettings/ssids").respond(
            json={"response": []}
        )
        api.route(path=BIZ, method__in=["POST", "DELETE"]).mock(side_effect=self.wlc_write)
        api.get(f"{EXEC}/e1").respond(json={"status": "SUCCESS"})
        api.route(path__startswith=f"{SDA}/fabrics/{FID}/", method="PUT").mock(side_effect=self.put)
        task_ok(api, "tw")

    def wlc_write(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content) if request.content else None
        self.sent.append((request.method, request.url.path, body, dict(request.url.params)))
        if request.method == "POST":
            self.devices.append(WLC_FD)
        else:
            self.devices = [d for d in self.devices if d is not WLC_FD]
        return httpx.Response(200, json={"executionId": "e1", "executionStatusUrl": f"{EXEC}/e1"})

    def put(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        self.sent.append(("PUT", request.url.path, body, {}))
        if request.url.path.endswith("/vlanToSsids"):
            self.mapping = [r for r in body if r["ssidDetails"]]
        else:
            self.multicast = body["multicastEnabled"]
        return httpx.Response(202, json={"response": {"taskId": "tw", "url": "/task/tw"}})


async def test_add_wlc_preview_and_apply(api: respx.MockRouter) -> None:
    lab = Lab(api)
    preview, done = await flow("catc_add_fabric_wlc", {"wlc": "mcp-wlc1", "fabric_site": "Global/AU/SYD-1"})
    assert preview["status"] == "preview" and "mcp-wlc1 (192.0.2.50)" in preview["action"]
    assert preview["preview"]["request"]["body"] == {
        "deviceName": "mcp-wlc1",
        "siteNameHierarchy": "Global/AU/SYD-1",
    }
    assert preview["blast_radius"] == 2
    assert done is not None and done["result"]["fabric_wlc"]["id"] == "fd-w"
    assert lab.sent == [("POST", BIZ, {"deviceName": "mcp-wlc1", "siteNameHierarchy": "Global/AU/SYD-1"}, {})]


async def test_add_wlc_already_in_fabric_is_noop(api: respx.MockRouter) -> None:
    Lab(api, fabric_devices=[CP, WLC_FD])
    preview, _ = await flow("catc_add_fabric_wlc", {"wlc": "mcp-wlc1", "fabric_site": FID})
    assert preview["status"] == "no_change"


async def test_add_wlc_blockers(api: respx.MockRouter) -> None:
    Lab(api, fabric_devices=[], wlc_site="Global/AU/MEL-1")
    out, _ = await flow("catc_add_fabric_wlc", {"wlc": "mcp-wlc1", "fabric_site": FID})
    msg = " ".join(out["blockers"])
    assert out["status"] == "blocked" and "outside the fabric site" in msg and "no control plane node" in msg


async def test_remove_wlc(api: respx.MockRouter) -> None:
    lab = Lab(api, fabric_devices=[CP, WLC_FD])
    preview, done = await flow(
        "catc_add_fabric_wlc", {"wlc": "192.0.2.50", "fabric_site": FID, "remove": True}
    )
    assert preview["action"].startswith("Remove WLC") and "stop working" in preview["side_effects"][0]
    assert done is not None and done["result"]["fabric_wlc"] is None
    assert lab.sent == [("DELETE", BIZ, None, {"deviceIPAddress": "192.0.2.50"})]


async def test_map_ssid_preview_and_apply(api: respx.MockRouter) -> None:
    lab = Lab(api, fabric_devices=[CP, WLC_FD])
    args = {
        "fabric_site": FID,
        "rows": [{"vlan": "mcp-wifi-users", "ssids": ["mcp-corp"], "security_group": "Employees"}],
    }
    preview, done = await flow("catc_set_fabric_ssid_mapping", args)
    d = preview["preview"]
    assert d["before"] == {} and d["after"] == {
        "MCP_WIFI": [{"name": "mcp-corp", "securityGroupTag": "Employees"}]
    }
    assert "warnings" not in d and d["fabric_wlcs"]
    assert done is not None and done["result"]["vlan_to_ssids"][0]["vlanName"] == "MCP_WIFI"
    assert lab.sent == [
        (
            "PUT",
            f"{SDA}/fabrics/{FID}/vlanToSsids",
            [
                {
                    "vlanName": "MCP_WIFI",
                    "ssidDetails": [{"name": "mcp-corp", "securityGroupTag": "Employees"}],
                }
            ],
            {},
        )
    ]


async def test_move_and_remove_keep_other_vlans(api: respx.MockRouter) -> None:
    current = [
        {"vlanName": "MCP_WIRED", "ssidDetails": [{"name": "mcp-corp", "securityGroupTag": "Employees"}]},
        {"vlanName": "OTHER", "ssidDetails": [{"name": "mcp-guest", "securityGroupTag": "Guests"}]},
    ]
    lab = Lab(api, fabric_devices=[CP, WLC_FD], mapping=current)
    preview, _ = await flow(
        "catc_set_fabric_ssid_mapping",
        {"fabric_site": FID, "rows": [{"vlan": "1031", "ssids": ["mcp-corp"]}]},
    )
    d = preview["preview"]
    assert d["moved"] == {"mcp-corp": {"from": "MCP_WIRED", "to": "MCP_WIFI"}}
    # The SGT follows the SSID when the row gives none; the untouched VLAN stays.
    assert d["after"] == {
        "MCP_WIFI": [{"name": "mcp-corp", "securityGroupTag": "Employees"}],
        "OTHER": [{"name": "mcp-guest", "securityGroupTag": "Guests"}],
    }
    assert {r["vlanName"]: r["ssidDetails"] for r in d["requests"][0]["body"]}["MCP_WIRED"] == []
    lab.mapping = current
    preview, done = await flow("catc_set_fabric_ssid_mapping", {"fabric_site": FID, "remove": ["OTHER"]})
    assert preview["preview"]["changes"] == {
        "OTHER": {"from": [{"name": "mcp-guest", "securityGroupTag": "Guests"}], "to": []}
    }
    assert done is not None and [r["vlanName"] for r in done["result"]["vlan_to_ssids"]] == ["MCP_WIRED"]


async def test_not_wireless_pool_warns(api: respx.MockRouter) -> None:
    Lab(api, fabric_devices=[CP])
    preview, _ = await flow(
        "catc_set_fabric_ssid_mapping",
        {"fabric_site": FID, "rows": [{"vlan": "MCP_WIRED", "ssids": ["mcp-guest"]}]},
    )
    w = " ".join(preview["preview"]["warnings"])
    assert "not flagged as a wireless pool" in w and "wireless_pool=true" in w and "no fabric WLC" in w


async def test_mapping_blockers(api: respx.MockRouter) -> None:
    lab = Lab(api)
    rows = [
        {"vlan": "AP_VLAN", "ssids": ["mcp-corp"]},
        {"vlan": "nope", "ssids": ["mcp-corp"]},
        {"vlan": "MCP_WIFI", "ssids": ["unknown-ssid"]},
    ]
    out, _ = await flow(
        "catc_set_fabric_ssid_mapping", {"fabric_site": FID, "rows": rows, "remove": ["MCP_WIFI"]}
    )
    msg = " ".join(out["blockers"])
    assert out["status"] == "blocked" and not lab.sent
    assert "INFRA_VN" in msg and "No anycast gateway 'nope'" in msg and "No SSID unknown-ssid" in msg
    assert "MCP_WIFI has no SSID mapping" in msg


async def test_wireless_multicast_and_noop(api: respx.MockRouter) -> None:
    current = [
        {"vlanName": "MCP_WIFI", "ssidDetails": [{"name": "mcp-corp", "securityGroupTag": "Employees"}]}
    ]
    lab = Lab(api, fabric_devices=[CP, WLC_FD], mapping=current)
    same = {
        "fabric_site": FID,
        "rows": [{"vlan": "MCP_WIFI", "ssids": ["mcp-corp"]}],
        "wireless_multicast": False,
    }
    preview, _ = await flow("catc_set_fabric_ssid_mapping", same)
    assert preview["status"] == "no_change"
    preview, done = await flow(
        "catc_set_fabric_ssid_mapping", {"fabric_site": FID, "wireless_multicast": True}
    )
    assert preview["preview"]["wireless_multicast"] == {"from": False, "to": True}
    assert done is not None and lab.sent == [
        ("PUT", f"{SDA}/fabrics/{FID}/wirelessMulticast", {"multicastEnabled": True}, {})
    ]


async def test_mapping_needs_something(api: respx.MockRouter) -> None:
    with pytest.raises(ToolError, match="Give rows"):
        await flow("catc_set_fabric_ssid_mapping", {"fabric_site": FID})
