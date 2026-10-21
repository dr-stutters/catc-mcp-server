"""D98: SD-Access port channels (respx); payloads follow the 3.2.2 spec's sda/portChannels."""

import json
from typing import Any

import httpx
import pytest
import respx
from fastmcp.exceptions import ToolError

from .test_read_tools import DEV_ID
from .test_safety import mock_inventory
from .test_sda import FID, flow
from .test_write_tools import task_ok

SDA = "/dna/intent/api/v1/sda"
PC = {
    "id": "a0000000-0000-0000-0000-0000000000c1",
    "fabricId": FID,
    "networkDeviceId": DEV_ID,
    "portChannelName": "Port-channel1",
    "interfaceNames": ["GigabitEthernet1/0/7", "GigabitEthernet1/0/8"],
    "connectedDeviceType": "TRUNK",
    "protocol": "LACP",
    "allowedVlanRanges": "all",
}


class Lab:
    def __init__(
        self, api: respx.MockRouter, channels: list[dict[str, Any]], *, ports: list[str] | None = None
    ) -> None:
        self.channels = list(channels)
        self.sent: list[tuple[str, str, Any]] = []
        mock_inventory(api)
        api.get(f"{SDA}/fabricSites").respond(json={"response": [{"id": FID}]})
        api.get(f"{SDA}/fabricDevices").respond(
            json={
                "response": [
                    {"id": "fd", "networkDeviceId": DEV_ID, "fabricId": FID, "deviceRoles": ["EDGE_NODE"]}
                ]
            }
        )
        api.get(f"{SDA}/portAssignments").respond(
            json={"response": [{"interfaceName": p, "networkDeviceId": DEV_ID} for p in ports or []]}
        )
        api.get(f"{SDA}/portChannels").mock(
            side_effect=lambda r: httpx.Response(200, json={"response": self.channels})
        )
        api.route(path__startswith=f"{SDA}/portChannels", method__in=["POST", "PUT", "DELETE"]).mock(
            side_effect=self.write
        )
        task_ok(api, "tc")

    def write(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content) if request.content else None
        self.sent.append((request.method, request.url.path.removeprefix(SDA), body))
        return httpx.Response(202, json={"response": {"taskId": "tc"}})


async def test_create(api: respx.MockRouter) -> None:
    lab = Lab(api, [])
    args = {
        "device": "edge-sw1",
        "interfaces": ["GigabitEthernet1/0/7", "GigabitEthernet1/0/8"],
        "allowed_vlans": "1021-1022",
    }
    preview, done = await flow("catc_set_fabric_port_channel", args)
    assert (
        preview["action"].startswith("Create a LACP port channel on edge-sw1")
        and preview["blast_radius"] == 1
    )
    assert done and lab.sent == [
        (
            "POST",
            "/portChannels",
            [
                {
                    "fabricId": FID,
                    "networkDeviceId": DEV_ID,
                    "interfaceNames": ["GigabitEthernet1/0/7", "GigabitEthernet1/0/8"],
                    "connectedDeviceType": "TRUNK",
                    "protocol": "LACP",
                    "allowedVlanRanges": "1021-1022",
                }
            ],
        )
    ]


async def test_update_and_delete(api: respx.MockRouter) -> None:
    lab = Lab(api, [PC])
    args = {
        "device": "edge-sw1",
        "port_channel": "port-channel1",
        "native_vlan": 1021,
        "description": "to srv1",
    }
    preview, done = await flow("catc_set_fabric_port_channel", args)
    assert preview["preview"]["changes"] == {
        "description": {"from": None, "to": "to srv1"},
        "nativeVlanId": {"from": None, "to": 1021},
    }
    assert (
        done
        and lab.sent[0][0] == "PUT"
        and lab.sent[0][2][0] == {**PC, "description": "to srv1", "nativeVlanId": 1021}
    )
    _, done = await flow(
        "catc_set_fabric_port_channel",
        {"device": "edge-sw1", "port_channel": "Port-channel1", "delete": True},
    )
    assert done and lab.sent[-1] == ("DELETE", f"/portChannels/{PC['id']}", None)


@pytest.mark.parametrize(
    ("args", "needle"),
    [
        ({"interfaces": ["GigabitEthernet1/0/3"]}, "has a port assignment"),
        ({"interfaces": ["GigabitEthernet1/0/8", "GigabitEthernet1/0/9"]}, "already in another port channel"),
        ({"interfaces": ["GigabitEthernet1/0/9"], "connected_device_type": "EXTENDED_NODE"}, "uses PAgP"),
        ({}, "Give the member interfaces"),
        ({"port_channel": "Port-channel1", "allowed_vlans": "all"}, "Nothing to change"),
    ],
)
async def test_blockers(api: respx.MockRouter, args: dict[str, Any], needle: str) -> None:
    lab = Lab(api, [PC], ports=["GigabitEthernet1/0/3"])
    out, _ = await flow("catc_set_fabric_port_channel", {"device": "edge-sw1", **args})
    assert out["status"] == "blocked" and needle in " ".join(out["blockers"]) and not lab.sent


async def test_unknown_channel(api: respx.MockRouter) -> None:
    Lab(api, [PC])
    with pytest.raises(ToolError, match="No Port-channel9 on .*has: Port-channel1"):
        await flow(
            "catc_set_fabric_port_channel",
            {"device": "edge-sw1", "port_channel": "Port-channel9", "delete": True},
        )
