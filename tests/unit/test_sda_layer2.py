"""D94: SD-Access layer 2 VNs and layer 2 handoffs (respx); payloads follow the 3.2.2 spec."""

import json
from typing import Any

import httpx
import pytest
import respx
from fastmcp.exceptions import ToolError

from .test_read_tools import AREA, BLDG, DEV_ID, GLOBAL
from .test_safety import mock_inventory
from .test_sda import FABRIC, FID, flow
from .test_write_tools import mock_sites, task_ok

SDA = "/dna/intent/api/v1/sda"
L2 = {
    "id": "a0000000-0000-0000-0000-0000000000b1",
    "fabricId": FID,
    "vlanName": "MCP_PRINTERS",
    "vlanId": 1031,
    "trafficType": "DATA",
    "isMultipleIpToMacAddresses": False,
}
H = {
    "id": "a0000000-0000-0000-0000-0000000000b2",
    "fabricId": FID,
    "networkDeviceId": DEV_ID,
    "interfaceName": "GigabitEthernet1/0/6",
    "internalVlanId": 1031,
    "externalVlanId": 1031,
}


class Lab:
    def __init__(
        self,
        api: respx.MockRouter,
        *,
        l2: list[dict[str, Any]],
        handoffs: list[dict[str, Any]],
        ports: list[dict[str, Any]] | None = None,
        roles: list[str] | None = None,
    ) -> None:
        self.sent: list[tuple[str, str, Any]] = []
        mock_inventory(api)
        mock_sites(api, [GLOBAL, AREA, BLDG])
        api.get(f"/dna/intent/api/v1/sites/{BLDG['id']}").respond(json={"response": BLDG})
        api.get(f"{SDA}/fabricSites").respond(json={"response": [FABRIC]})
        dev = {
            "id": "fd",
            "networkDeviceId": DEV_ID,
            "fabricId": FID,
            "deviceRoles": roles or ["BORDER_NODE", "EDGE_NODE"],
        }
        api.get(f"{SDA}/fabricDevices").respond(json={"response": [dev]})
        api.get(f"{SDA}/layer2VirtualNetworks").respond(json={"response": l2})
        api.get(f"{SDA}/layer3VirtualNetworks").respond(
            json={"response": [{"virtualNetworkName": "MCP_VN", "fabricIds": [FID]}]}
        )
        api.get(f"{SDA}/anycastGateways").respond(
            json={"response": [{"vlanName": "MCP_CLIENTS", "vlanId": 1021}]}
        )
        api.get(f"{SDA}/portAssignments").respond(json={"response": ports or []})
        api.get(f"{SDA}/fabricDevices/layer2Handoffs").respond(json={"response": handoffs})
        for path in ("/layer2VirtualNetworks", "/fabricDevices/layer2Handoffs"):
            api.route(path__startswith=SDA + path, method__in=["POST", "PUT", "DELETE"]).mock(
                side_effect=self.write
            )
        task_ok(api, "tl")

    def write(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content) if request.content else None
        self.sent.append((request.method, request.url.path.removeprefix(SDA), body))
        return httpx.Response(202, json={"response": {"taskId": "tl"}})


async def test_create_l2_vn(api: respx.MockRouter) -> None:
    lab = Lab(api, l2=[], handoffs=[])
    args = {
        "fabric_site": FID,
        "vlan_name": "MCP_PRINTERS",
        "vlan_id": 1031,
        "flooding_address": "239.1.1.31",
    }
    preview, done = await flow("catc_set_l2_virtual_network", args)
    assert (
        preview["action"] == "Create layer 2 VN MCP_PRINTERS at Global/AU/SYD-1"
        and preview["blast_radius"] == 1
    )
    assert done and lab.sent == [
        (
            "POST",
            "/layer2VirtualNetworks",
            [
                {
                    "fabricId": FID,
                    "vlanName": "MCP_PRINTERS",
                    "vlanId": 1031,
                    "trafficType": "DATA",
                    "layer2FloodingAddressAssignment": "USER",
                    "layer2FloodingAddress": "239.1.1.31",
                }
            ],
        )
    ]


async def test_update_and_delete_l2_vn(api: respx.MockRouter) -> None:
    lab = Lab(api, l2=[L2], handoffs=[])
    preview, done = await flow(
        "catc_set_l2_virtual_network",
        {"fabric_site": FID, "vlan_name": "MCP_PRINTERS", "multiple_ip_to_mac": True},
    )
    assert preview["preview"]["changes"] == {"isMultipleIpToMacAddresses": {"from": False, "to": True}}
    assert done and lab.sent[0][0] == "PUT" and lab.sent[0][2] == [{**L2, "isMultipleIpToMacAddresses": True}]
    _, done = await flow(
        "catc_set_l2_virtual_network", {"fabric_site": FID, "vlan_name": "MCP_PRINTERS", "delete": True}
    )
    assert done and lab.sent[-1] == ("DELETE", f"/layer2VirtualNetworks/{L2['id']}", None)


@pytest.mark.parametrize(
    ("args", "needle"),
    [
        ({"vlan_name": "NEW", "vlan_id": 1002}, "VLAN 1002 is reserved"),
        ({"vlan_name": "NEW", "layer3_vn": "NOPE"}, "NOPE is not a layer 3 VN"),
        ({"vlan_name": "MCP_PRINTERS", "vlan_id": 1040}, "can't change"),
        ({"vlan_name": "MCP_PRINTERS"}, "Nothing to change"),
        (
            {"vlan_name": "MCP_PRINTERS", "delete": True},
            "still used by 1 edge port(s) and 1 layer 2 handoff(s)",
        ),
    ],
)
async def test_l2_vn_blockers(api: respx.MockRouter, args: dict[str, Any], needle: str) -> None:
    lab = Lab(api, l2=[L2], handoffs=[H], ports=[{"dataVlanName": "MCP_PRINTERS"}])
    out, _ = await flow("catc_set_l2_virtual_network", {"fabric_site": FID, **args})
    assert out["status"] == "blocked" and needle in " ".join(out["blockers"]) and not lab.sent


async def test_l2_handoff(api: respx.MockRouter) -> None:
    lab = Lab(api, l2=[L2], handoffs=[])
    preview, done = await flow(
        "catc_set_l2_handoff",
        {
            "border": "edge-sw1",
            "interface": "GigabitEthernet1/0/6",
            "vlan": "MCP_PRINTERS",
            "external_vlan": 31,
        },
    )
    assert preview["action"].endswith("as external VLAN 31")
    assert done and lab.sent == [
        (
            "POST",
            "/fabricDevices/layer2Handoffs",
            [
                {
                    "networkDeviceId": DEV_ID,
                    "fabricId": FID,
                    "interfaceName": "GigabitEthernet1/0/6",
                    "internalVlanId": 1031,
                    "externalVlanId": 31,
                }
            ],
        )
    ]


async def test_l2_handoff_gateway_vlan_dup_and_delete(api: respx.MockRouter) -> None:
    lab = Lab(api, l2=[L2], handoffs=[H])
    out, _ = await flow(
        "catc_set_l2_handoff", {"border": "edge-sw1", "interface": "GigabitEthernet1/0/6", "vlan": "1031"}
    )
    assert out["status"] == "blocked" and "already handed off" in out["blockers"][0]
    out, _ = await flow(
        "catc_set_l2_handoff",
        {"border": "edge-sw1", "interface": "GigabitEthernet1/0/7", "vlan": "MCP_CLIENTS"},
    )
    assert out["status"] == "preview" and out["preview"]["body"][0]["internalVlanId"] == 1021
    _, done = await flow(
        "catc_set_l2_handoff",
        {"border": "edge-sw1", "interface": "GigabitEthernet1/0/6", "vlan": "MCP_PRINTERS", "delete": True},
    )
    assert done and lab.sent[-1] == ("DELETE", f"/fabricDevices/layer2Handoffs/{H['id']}", None)
    with pytest.raises(ToolError, match="No fabric VLAN 'NOPE'"):
        await flow("catc_set_l2_handoff", {"border": "edge-sw1", "interface": "Gi1/0/6", "vlan": "NOPE"})


async def test_l2_handoff_needs_border(api: respx.MockRouter) -> None:
    Lab(api, l2=[L2], handoffs=[], roles=["EDGE_NODE"])
    with pytest.raises(ToolError, match="is not a border node"):
        await flow(
            "catc_set_l2_handoff", {"border": "edge-sw1", "interface": "Gi1/0/6", "vlan": "MCP_PRINTERS"}
        )
