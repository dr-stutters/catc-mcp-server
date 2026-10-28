"""D48: catc_set_interface (respx). Interface rows follow the 3.2.2 spec's GET interface/network-device/{id}
(portMode routed/access/trunk/dynamic_auto, interfaceType Physical/Virtual, vlanId and voiceVlan as strings);
legit-operation and the PUT interface/{interfaceUuid} (deploymentMode Preview/Deploy) as the spec and a
3.2.2 read show them."""

import copy
import json
from typing import Any

import httpx
import pytest
import respx
from fastmcp.exceptions import ToolError

from catc_mcp._core import InvalidRequest, NotFound
from catc_mcp.tools.ports import find_port, plan_port_change, undo_of

from .test_read_tools import DEV_ID, DEVICE
from .test_safety import mock_inventory
from .test_sda import flow
from .test_write_tools import task_ok

IFACE = "/dna/intent/api/v1/interface"
DIST = "99999999-8888-7777-6666-555555555555"


def row(pid: str, name: str, mode: str = "access", **kw: Any) -> dict[str, Any]:
    return {
        "id": pid,
        "instanceUuid": pid,
        "deviceId": DEV_ID,
        "portName": name,
        "interfaceType": "Physical",
        "portType": "Ethernet Port",
        "portMode": mode,
        "adminStatus": "UP",
        "status": "up",
        "vlanId": "0" if mode == "routed" else "1",
        "nativeVlanId": "" if mode == "routed" else "1",
        "voiceVlan": "",
        "description": "",
        "ipv4Address": None,
        **kw,
    }


PORTS = [
    row("p-mgmt", "GigabitEthernet1/0/1", "routed", ipv4Address=DEVICE["managementIpAddress"]),
    row("p-up", "GigabitEthernet1/0/2", "routed", description="underlay to dist"),
    row("p-cli", "GigabitEthernet1/0/3"),
    row("p-trk", "GigabitEthernet1/0/5", "trunk"),
    row("p-dyn", "GigabitEthernet1/0/16", "dynamic_auto", status="down"),
    row("p-po", "Port-channel1", "trunk", interfaceType="Virtual", portType="Ethernet SVI"),
    row("p-svi", "Vlan1", "routed", interfaceType="Virtual", portType="Ethernet SVI"),
    row("p-te", "TenGigabitEthernet1/1/3"),
]
TOPO = {
    "nodes": [{"id": DEV_ID, "label": "edge-sw1"}, {"id": DIST, "label": "dist-sw1"}],
    "links": [
        {
            "source": DIST,
            "target": DEV_ID,
            "startPortName": "GigabitEthernet1/0/24",
            "endPortName": "GigabitEthernet1/0/2",
            "linkStatus": "up",
        }
    ],
}


def legit(vlan_ok: bool = True) -> dict[str, Any]:
    reason = None if vlan_ok else "VLAN changes are not supported on devices that are part of the fabric"
    return {
        "interfaceUuid": "x",
        "properties": [
            {"name": "description", "applicable": True, "failureReason": None},
            {"name": "adminStatus", "applicable": True, "failureReason": None},
            {"name": "vlanId", "applicable": vlan_ok, "failureReason": reason},
            {"name": "voiceVlanId", "applicable": vlan_ok, "failureReason": reason},
        ],
        "operations": [{"name": "ClearMacAddress", "applicable": True, "failureReason": None}],
    }


class Lab:
    def __init__(self, api: respx.MockRouter, *, vlan_ok: bool = True, preview_fails: bool = False) -> None:
        self.ports = copy.deepcopy(PORTS)
        self.puts: list[tuple[str | None, dict[str, Any]]] = []
        self.preview_fails = preview_fails
        mock_inventory(api)
        api.get(f"{IFACE}/network-device/{DEV_ID}").mock(
            side_effect=lambda _r: httpx.Response(200, json={"response": self.ports})
        )
        api.get("/dna/intent/api/v1/topology/physical-topology").respond(json={"response": TOPO})
        for p in self.ports:
            api.get(f"{IFACE}/{p['id']}/legit-operation").respond(json={"response": legit(vlan_ok)})
            api.get(f"{IFACE}/{p['id']}").mock(side_effect=self.read)
            api.put(f"{IFACE}/{p['id']}").mock(side_effect=self.put)
        task_ok(api, "t-prev", data="preview", progress="Preview generated")
        task_ok(api, "t-dep", data="deployed", progress="Interface updated")

    def read(self, request: httpx.Request) -> httpx.Response:
        pid = request.url.path.rsplit("/", 1)[-1]
        return httpx.Response(200, json={"response": next(p for p in self.ports if p["id"] == pid)})

    def put(self, request: httpx.Request) -> httpx.Response:
        mode = request.url.params.get("deploymentMode")
        body = json.loads(request.content)
        self.puts.append((mode, body))
        if mode == "Preview" and self.preview_fails:
            return httpx.Response(400, json={"response": {"message": "Preview not supported"}})
        if mode == "Deploy":  # the device took it; the inventory reads it back
            pid = request.url.path.rsplit("/", 1)[-1]
            p = next(p for p in self.ports if p["id"] == pid)
            for k, v in body.items():
                p[{"voiceVlanId": "voiceVlan"}.get(k, k)] = str(v) if k.endswith(("vlanId", "VlanId")) else v
        task = "t-prev" if mode == "Preview" else "t-dep"
        return httpx.Response(202, json={"response": {"taskId": task, "url": f"/api/v1/task/{task}"}})


async def test_shut_client_port_preview_then_apply(api: respx.MockRouter) -> None:
    lab = Lab(api)
    preview, done = await flow(
        "catc_set_interface", {"device": "edge-sw1", "interface": "Gi1/0/3", "action": "shut"}
    )
    p = preview["preview"]
    assert preview["status"] == "preview" and preview["blast_radius"] == 1
    assert p["change"] == {"adminStatus": {"from": "UP", "to": "DOWN"}} and p["body"] == {
        "adminStatus": "DOWN"
    }
    assert p["interface"]["portName"] == "GigabitEthernet1/0/3" and p["interface"]["portMode"] == "access"
    assert p["catalyst_center_preview"]["progress"] == "Preview generated"
    assert p["undo"]["call"] == {
        "tool": "catc_set_interface",
        "args": {"device": "edge-sw1.lab.local", "interface": "GigabitEthernet1/0/3", "action": "no_shut"},
    }
    assert done is not None
    # The preview ran Catalyst Center's dry run once; the confirm pushed with Deploy and didn't re-preview.
    assert lab.puts == [("Preview", {"adminStatus": "DOWN"}), ("Deploy", {"adminStatus": "DOWN"})]
    res = done["result"]
    assert res["task"]["task_id"] == "t-dep" and res["interface"]["adminStatus"] == "DOWN"
    assert "note" not in res


async def test_uplink_refused_unless_allowed(api: respx.MockRouter) -> None:
    lab = Lab(api)
    args = {"device": "edge-sw1", "interface": "Gi1/0/2", "action": "shut"}
    preview, _ = await flow("catc_set_interface", args)
    assert preview["status"] == "blocked"
    assert "uplink to dist-sw1 GigabitEthernet1/0/24" in preview["blockers"][0]
    assert lab.puts == []  # no dry run for a refused change
    preview, _ = await flow("catc_set_interface", {**args, "allow_uplink": True})
    assert preview["status"] == "preview"
    assert any("allow_uplink=true" in w for w in preview["preview"]["warnings"])


@pytest.mark.parametrize(
    ("interface", "reason"),
    [
        ("Gi1/0/5", "trunk port"),
        ("GigabitEthernet1/0/16", "dynamic_auto port"),
        ("Port-channel1", "port channel"),
        ("Vlan1", "virtual interface"),
    ],
)
async def test_trunks_channels_and_virtual_refused(
    api: respx.MockRouter, interface: str, reason: str
) -> None:
    Lab(api)
    preview, _ = await flow(
        "catc_set_interface", {"device": "edge-sw1", "interface": interface, "action": "shut"}
    )
    assert preview["status"] == "blocked" and reason in preview["blockers"][0]


async def test_description_allowed_on_trunk(api: respx.MockRouter) -> None:
    lab = Lab(api)
    args = {"device": "edge-sw1", "interface": "Gi1/0/5", "action": "description", "description": "to AP-1"}
    preview, done = await flow("catc_set_interface", args)
    assert preview["status"] == "preview" and preview["preview"]["undo"]["call"]["args"]["description"] == ""
    assert done and lab.puts[-1] == ("Deploy", {"description": "to AP-1"})


async def test_management_port_never_shut(api: respx.MockRouter) -> None:
    Lab(api)
    args = {"device": "edge-sw1", "interface": "Gi1/0/1", "action": "shut", "allow_uplink": True}
    preview, _ = await flow("catc_set_interface", args)
    assert preview["status"] == "blocked"
    assert any("management address" in b for b in preview["blockers"])


async def test_vlan_change_refused_on_fabric_device(api: respx.MockRouter) -> None:
    Lab(api, vlan_ok=False)
    args = {"device": "edge-sw1", "interface": "Gi1/0/3", "action": "access_vlan", "vlan": 20}
    preview, _ = await flow("catc_set_interface", args)
    assert preview["status"] == "blocked"
    assert any("not supported on devices that are part of the fabric" in b for b in preview["blockers"])


async def test_access_vlan_and_undo(api: respx.MockRouter) -> None:
    lab = Lab(api)
    args = {"device": "edge-sw1", "interface": "Gi1/0/3", "action": "access_vlan", "vlan": 20}
    preview, done = await flow("catc_set_interface", args)
    p = preview["preview"]
    assert p["change"] == {"vlanId": {"from": 1, "to": 20}}
    assert p["undo"]["call"]["args"] == {
        "device": "edge-sw1.lab.local",
        "interface": "GigabitEthernet1/0/3",
        "action": "access_vlan",
        "vlan": 1,
    }
    assert any("DHCP" in s for s in preview["side_effects"])
    assert done and lab.puts[-1] == ("Deploy", {"vlanId": 20})
    assert done["result"]["interface"]["vlanId"] == "20"


async def test_voice_vlan_without_prior_has_no_undo_call(api: respx.MockRouter) -> None:
    Lab(api)
    args = {"device": "edge-sw1", "interface": "Gi1/0/3", "action": "voice_vlan", "vlan": 30}
    preview, _ = await flow("catc_set_interface", args)
    undo = preview["preview"]["undo"]
    assert "call" not in undo and "no switchport voice vlan" in undo["note"]
    assert undo["before"] == {"voiceVlanId": None}


@pytest.mark.parametrize(
    ("args", "needle"),
    [
        ({"interface": "Gi1/0/3", "action": "access_vlan"}, "needs `vlan`"),
        ({"interface": "Gi1/0/3", "action": "shut", "vlan": 5}, "takes neither"),
        ({"interface": "Gi1/0/3", "action": "access_vlan", "vlan": 1003}, "reserved"),
        ({"interface": "Gi1/0/3", "action": "description"}, "needs `description`"),
        ({"interface": "Gi1/0/2", "action": "access_vlan", "vlan": 20, "allow_uplink": True}, "routed port"),
        ({"interface": "Gi1/0/3", "action": "no_shut"}, "Nothing to change"),
    ],
)
async def test_argument_and_state_blockers(api: respx.MockRouter, args: dict[str, Any], needle: str) -> None:
    lab = Lab(api)
    preview, _ = await flow("catc_set_interface", {"device": "edge-sw1", **args})
    assert preview["status"] == "blocked" and any(needle in b for b in preview["blockers"])
    assert lab.puts == []


async def test_preview_unavailable_is_reported(api: respx.MockRouter) -> None:
    Lab(api, preview_fails=True)
    preview, _ = await flow(
        "catc_set_interface", {"device": "edge-sw1", "interface": "Gi1/0/3", "action": "shut"}
    )
    assert preview["status"] == "preview" and "unavailable" in preview["preview"]["catalyst_center_preview"]


async def test_state_change_between_preview_and_confirm_is_refused(api: respx.MockRouter) -> None:
    from fastmcp import Client

    from .test_sda import server
    from .test_write_tools import run

    lab = Lab(api)
    args = {"device": "edge-sw1", "interface": "Gi1/0/3", "action": "shut"}
    async with Client(server()) as c:
        preview = await run(c, "catc_set_interface", args)
        lab.ports[2]["description"] = "changed by someone else"
        with pytest.raises(ToolError):
            await c.call_tool("catc_set_interface", {**args, "confirm": preview["confirm"]})
    assert [m for m, _ in lab.puts] == ["Preview"]


def test_find_port_names() -> None:
    assert find_port(PORTS, "gi1/0/3")["id"] == "p-cli"
    assert find_port(PORTS, "Te1/1/3")["id"] == "p-te"
    assert find_port(PORTS, "p-trk")["portName"] == "GigabitEthernet1/0/5"
    with pytest.raises(NotFound):
        find_port(PORTS, "Gi9/9/9")
    with pytest.raises(InvalidRequest):
        find_port(PORTS, " ")
    twins = [row("a", "GigabitEthernet1/0/3"), row("b", "GigabitEthernet1/0/30")]
    assert find_port(twins, "Gi1/0/3")["id"] == "a"  # the number must match exactly


def test_engine_is_reusable_per_row() -> None:
    """D81 runs every row of a port table through plan_port_change without the tool."""
    dev = {**DEVICE, "reachabilityStatus": "Unreachable"}
    change = plan_port_change(dev, PORTS[2], {}, None, "description", description="desk 12")
    assert change["body"] == {"description": "desk 12"} and change["blockers"] == []
    assert any("legit-operation" in w for w in change["warnings"])
    assert any("Unreachable" in w for w in change["warnings"])
    assert undo_of(PORTS[1], "edge-sw1", "adminStatus")["call"]["args"]["action"] == "no_shut"
