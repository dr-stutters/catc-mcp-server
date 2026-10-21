"""D103: SD-Access fabric device changes (respx); payloads follow the 3.2.2 spec's PUT sda/fabricDevices."""

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
BORDER = {
    "id": "fd-b",
    "networkDeviceId": DEV_ID,
    "fabricId": FID,
    "deviceRoles": ["BORDER_NODE", "CONTROL_PLANE_NODE"],
    "borderDeviceSettings": {
        "borderTypes": ["LAYER_3"],
        "layer3Settings": {
            "localAutonomousSystemNumber": "65001",
            "isDefaultExit": True,
            "importExternalRoutes": True,
        },
    },
}
EDGE = {"id": "fd-e", "networkDeviceId": DEV_ID, "fabricId": FID, "deviceRoles": ["EDGE_NODE"]}
OTHER_EDGE = {"id": "fd-x", "networkDeviceId": "d-x", "fabricId": FID, "deviceRoles": ["EDGE_NODE"]}


class Lab:
    def __init__(
        self, api: respx.MockRouter, me: dict[str, Any], peers: list[dict[str, Any]], ports: int = 0
    ) -> None:
        self.me, self.puts = me, []
        devices = [me, *peers]
        mock_inventory(api)
        api.get(f"{SDA}/fabricSites").respond(json={"response": [{"id": FID}]})
        api.get(f"{SDA}/fabricDevices").mock(
            side_effect=lambda r: httpx.Response(
                200,
                json={
                    "response": [
                        d
                        for d in devices
                        if r.url.params.get("networkDeviceId") in (None, d["networkDeviceId"])
                    ]
                },
            )
        )
        api.get(f"{SDA}/portAssignments").respond(json={"response": [{"id": f"p{i}"} for i in range(ports)]})
        api.put(f"{SDA}/fabricDevices").mock(side_effect=self.put)
        task_ok(api, "tu")

    def put(self, request: httpx.Request) -> httpx.Response:
        self.puts.append(json.loads(request.content))
        return httpx.Response(202, json={"response": {"taskId": "tu"}})


async def test_border_priority_and_l2(api: respx.MockRouter) -> None:
    lab = Lab(api, BORDER, [OTHER_EDGE])
    preview, done = await flow(
        "catc_update_fabric_device",
        {"device": "edge-sw1", "border_priority": 2, "default_exit": False, "layer2_border": True},
    )
    change = preview["preview"]["changes"]["borderDeviceSettings"]["to"]
    assert change["borderTypes"] == ["LAYER_2", "LAYER_3"]
    assert change["layer3Settings"] == {
        "localAutonomousSystemNumber": "65001",
        "isDefaultExit": False,
        "importExternalRoutes": True,
        "borderPriority": 2,
    }
    assert (
        done
        and lab.puts[0][0]["id"] == "fd-b"
        and lab.puts[0][0]["deviceRoles"] == ["BORDER_NODE", "CONTROL_PLANE_NODE"]
    )


async def test_edge_becomes_border(api: respx.MockRouter) -> None:
    lab = Lab(api, EDGE, [{**BORDER, "id": "fd-other", "networkDeviceId": "d-b"}])
    out, _ = await flow(
        "catc_update_fabric_device", {"device": "edge-sw1", "roles": ["EDGE_NODE", "BORDER_NODE"]}
    )
    assert out["status"] == "blocked" and "needs border_asn" in out["blockers"][0]
    _, done = await flow(
        "catc_update_fabric_device",
        {"device": "edge-sw1", "roles": ["EDGE_NODE", "BORDER_NODE"], "border_asn": "65003"},
    )
    body = lab.puts[0][0]
    assert done and body["deviceRoles"] == ["BORDER_NODE", "EDGE_NODE"]
    assert body["borderDeviceSettings"] == {
        "borderTypes": ["LAYER_3"],
        "layer3Settings": {
            "isDefaultExit": True,
            "importExternalRoutes": True,
            "localAutonomousSystemNumber": "65003",
        },
    }


@pytest.mark.parametrize(
    ("me", "peers", "ports", "args", "needle"),
    [
        (BORDER, [OTHER_EDGE], 0, {"roles": ["BORDER_NODE"]}, "last control plane node"),
        (BORDER, [OTHER_EDGE], 0, {"border_asn": "65009"}, "can't change"),
        (EDGE, [], 0, {"border_priority": 3}, "only to a device with the BORDER_NODE role"),
        (EDGE, [], 2, {"roles": ["CONTROL_PLANE_NODE"]}, "2 port assignment(s)"),
        (BORDER, [], 0, {"default_exit": True}, "Nothing to change"),
        (BORDER, [], 0, {"bgp_router_id": "not-an-ip"}, "not an IPv4 address"),
    ],
)
async def test_blockers(
    api: respx.MockRouter,
    me: dict[str, Any],
    peers: list[dict[str, Any]],
    ports: int,
    args: dict[str, Any],
    needle: str,
) -> None:
    lab = Lab(api, me, peers, ports)
    out, _ = await flow("catc_update_fabric_device", {"device": "edge-sw1", **args})
    assert out["status"] == "blocked" and needle in " ".join(out["blockers"]) and not lab.puts


async def test_not_a_fabric_device(api: respx.MockRouter) -> None:
    mock_inventory(api)
    api.get(f"{SDA}/fabricSites").respond(json={"response": [{"id": FID}]})
    api.get(f"{SDA}/fabricDevices").respond(json={"response": []})
    with pytest.raises(ToolError, match="is not a fabric device"):
        await flow("catc_update_fabric_device", {"device": "edge-sw1", "border_priority": 2})
