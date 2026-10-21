"""D99: SD-Access day-N edits (respx); records follow the 3.2.2 spec's anycastGateways / portAssignments."""

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
GW = {
    "id": "gw-1",
    "fabricId": FID,
    "virtualNetworkName": "MCP_VN",
    "ipPoolName": "mcp-test-fab-clients",
    "vlanName": "MCP_CLIENTS",
    "vlanId": 1021,
    "trafficType": "DATA",
    "isCriticalPool": False,
    "isLayer2FloodingEnabled": False,
    "isWirelessPool": False,
    "isIpDirectedBroadcast": False,
    "isIntraSubnetRoutingEnabled": False,
    "isMultipleIpToMacAddresses": False,
    "isGroupBasedPolicyEnforcementEnabled": True,
}
GW2 = {**GW, "id": "gw-2", "ipPoolName": "mcp-test-fab-servers", "vlanName": "MCP_SERVERS", "vlanId": 1022}
PORT = {
    "id": "pa-1",
    "fabricId": FID,
    "networkDeviceId": DEV_ID,
    "interfaceName": "GigabitEthernet1/0/4",
    "connectedDeviceType": "USER_DEVICE",
    "dataVlanName": "MCP_CLIENTS",
    "authenticateTemplateName": "Closed Authentication",
}


class Fabric:
    def __init__(self, api: respx.MockRouter) -> None:
        self.puts: list[tuple[str, Any]] = []
        self.gws = [dict(GW), dict(GW2)]
        mock_inventory(api)
        mock_sites(api, [GLOBAL, AREA, BLDG])
        api.get(f"/dna/intent/api/v1/sites/{BLDG['id']}").respond(json={"response": BLDG})
        api.get(f"{SDA}/fabricSites").respond(json={"response": [FABRIC]})
        api.get(f"{SDA}/fabricDevices").respond(
            json={
                "response": [
                    {"id": "fd-e", "networkDeviceId": DEV_ID, "fabricId": FID, "deviceRoles": ["EDGE_NODE"]},
                    {"id": "fd-b", "networkDeviceId": "d-b", "fabricId": FID, "deviceRoles": ["BORDER_NODE"]},
                ]
            }
        )
        api.get(f"{SDA}/anycastGateways").mock(
            side_effect=lambda r: httpx.Response(200, json={"response": self.gws})
        )
        api.get(f"{SDA}/portAssignments").respond(json={"response": [PORT]})
        api.put(f"{SDA}/anycastGateways").mock(side_effect=self.put("anycastGateways"))
        api.put(f"{SDA}/portAssignments").mock(side_effect=self.put("portAssignments"))
        task_ok(api, "tu")

    def put(self, what: str) -> Any:
        def handler(request: httpx.Request) -> httpx.Response:
            body = json.loads(request.content)
            self.puts.append((what, body))
            if what == "anycastGateways":
                self.gws = [body[0] if g["id"] == body[0]["id"] else g for g in self.gws]
            return httpx.Response(202, json={"response": {"taskId": "tu"}})

        return handler


async def test_gateway_flooding_and_sgt(api: respx.MockRouter) -> None:
    fab = Fabric(api)
    args = {
        "fabric_site": FID,
        "ip_pool": "MCP_CLIENTS",
        "layer2_flooding": True,
        "flooding_address": "239.1.1.10",
        "security_group": "Employees",
    }
    preview, done = await flow("catc_update_anycast_gateway", args)
    assert (
        preview["status"] == "preview" and preview["blast_radius"] == 1
    )  # one edge, the border doesn't count
    assert preview["preview"]["changes"] == {
        "isLayer2FloodingEnabled": {"from": False, "to": True},
        "layer2FloodingAddressAssignment": {"from": None, "to": "USER"},
        "layer2FloodingAddress": {"from": None, "to": "239.1.1.10"},
        "securityGroupName": {"from": None, "to": "Employees"},
    }
    assert done and done["status"] == "applied"
    body = fab.puts[0][1][0]
    assert body["id"] == "gw-1" and body["vlanId"] == 1021 and body["isIntraSubnetRoutingEnabled"] is False
    assert done["result"]["gateway"]["securityGroupName"] == "Employees"


@pytest.mark.parametrize(
    ("args", "needle"),
    [
        ({"flooding_address": "239.1.1.10"}, "needs layer 2 flooding on"),
        ({"layer2_flooding": False}, "Nothing to change"),
    ],
)
async def test_gateway_blockers(api: respx.MockRouter, args: dict[str, Any], needle: str) -> None:
    fab = Fabric(api)
    out, _ = await flow(
        "catc_update_anycast_gateway", {"fabric_site": FID, "ip_pool": "mcp-test-fab-clients", **args}
    )
    assert out["status"] == "blocked" and needle in " ".join(out["blockers"]) and not fab.puts


async def test_gateway_not_found(api: respx.MockRouter) -> None:
    Fabric(api)
    with pytest.raises(ToolError, match="No anycast gateway for 'nope'.*have: mcp-test-fab-clients"):
        await flow(
            "catc_update_anycast_gateway", {"fabric_site": FID, "ip_pool": "nope", "layer2_flooding": True}
        )


async def test_port_moves_vlan_and_template(api: respx.MockRouter) -> None:
    fab = Fabric(api)
    args = {
        "device": "edge-sw1",
        "interface": "GigabitEthernet1/0/4",
        "data_vlan": "mcp-test-fab-servers",
        "authentication": "Open Authentication",
    }
    preview, done = await flow("catc_update_port_assignment", args)
    assert preview["preview"]["changes"] == {
        "dataVlanName": {"from": "MCP_CLIENTS", "to": "MCP_SERVERS"},
        "authenticateTemplateName": {"from": "Closed Authentication", "to": "Open Authentication"},
    }
    assert done and fab.puts[0][1] == [
        {**PORT, "dataVlanName": "MCP_SERVERS", "authenticateTemplateName": "Open Authentication"}
    ]


@pytest.mark.parametrize(
    ("args", "needle"),
    [
        ({"data_vlan": "nope"}, "No anycast gateway with VLAN or pool 'nope'"),
        ({"native_vlan": 10}, "apply to TRUNKING_DEVICE ports"),
        ({"data_vlan": ""}, "needs a data or voice VLAN"),
        ({"data_vlan": "MCP_CLIENTS"}, "Nothing to change"),
    ],
)
async def test_port_blockers(api: respx.MockRouter, args: dict[str, Any], needle: str) -> None:
    fab = Fabric(api)
    out, _ = await flow(
        "catc_update_port_assignment", {"device": "edge-sw1", "interface": "GigabitEthernet1/0/4", **args}
    )
    assert out["status"] == "blocked" and needle in " ".join(out["blockers"]) and not fab.puts


async def test_port_without_assignment(api: respx.MockRouter) -> None:
    Fabric(api)
    with pytest.raises(ToolError, match="GigabitEthernet1/0/9 on .* has no port assignment"):
        await flow(
            "catc_update_port_assignment",
            {"device": "edge-sw1", "interface": "GigabitEthernet1/0/9", "description": "x"},
        )
