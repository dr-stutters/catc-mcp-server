"""D96: SD-Access multicast (respx); payloads follow the 3.2.2 spec's sda/multicast(/virtualNetworks)."""

import json
from typing import Any

import httpx
import pytest
import respx
from fastmcp.exceptions import ToolError

from .test_read_tools import AREA, BLDG, DEV_ID, GLOBAL, call
from .test_safety import mock_inventory
from .test_sda import FABRIC, FID, flow
from .test_write_tools import mock_sites, task_ok

SDA = "/dna/intent/api/v1/sda"
MVN = {
    "id": "a0000000-0000-0000-0000-0000000000d1",
    "fabricId": FID,
    "virtualNetworkName": "MCP_VN",
    "ipPoolName": "mcp-mcast",
    "multicastRPs": [{"rpDeviceLocation": "EXTERNAL", "ipv4Address": "10.255.255.14", "isDefaultV4RP": True}],
}


class Lab:
    def __init__(self, api: respx.MockRouter, *, mode: str | None, vns: list[dict[str, Any]]) -> None:
        self.mode, self.vns = mode, list(vns)
        self.sent: list[tuple[str, str, Any]] = []
        mock_inventory(api)
        mock_sites(api, [GLOBAL, AREA, BLDG])
        api.get(f"/dna/intent/api/v1/sites/{BLDG['id']}").respond(json={"response": BLDG})
        api.get(f"{SDA}/fabricSites").respond(json={"response": [FABRIC]})
        api.get(f"{SDA}/fabricDevices").respond(
            json={
                "response": [
                    {"id": "fd", "networkDeviceId": DEV_ID, "fabricId": FID, "deviceRoles": ["EDGE_NODE"]}
                ]
            }
        )
        api.get(f"{SDA}/layer3VirtualNetworks").respond(
            json={"response": [{"virtualNetworkName": "MCP_VN", "fabricIds": [FID]}]}
        )
        api.get(f"{SDA}/multicast").mock(
            side_effect=lambda r: httpx.Response(
                200, json={"response": [{"fabricId": FID, "replicationMode": self.mode}] if self.mode else []}
            )
        )
        api.get(f"{SDA}/multicast/virtualNetworks").mock(
            side_effect=lambda r: httpx.Response(200, json={"response": self.vns})
        )
        api.route(path__startswith=f"{SDA}/multicast", method__in=["POST", "PUT", "DELETE"]).mock(
            side_effect=self.write
        )
        task_ok(api, "tm")

    def write(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content) if request.content else None
        path = request.url.path.removeprefix(SDA)
        self.sent.append((request.method, path, body))
        if path == "/multicast":
            self.mode = body[0]["replicationMode"]
        return httpx.Response(202, json={"response": {"taskId": "tm"}})


async def test_get(api: respx.MockRouter) -> None:
    Lab(api, mode="HEADEND_REPLICATION", vns=[MVN])
    out = await call("catc_get_fabric_multicast", {"fabric_site": FID})
    assert (
        out["replication"] == "HEADEND_REPLICATION"
        and out["virtual_networks"][0]["ipPoolName"] == "mcp-mcast"
    )


async def test_mode_and_new_vn_in_one_call(api: respx.MockRouter) -> None:
    lab = Lab(api, mode="NATIVE_MULTICAST", vns=[])
    args = {
        "fabric_site": "Global/AU/SYD-1",
        "replication": "headend",
        "virtual_network": "MCP_VN",
        "ip_pool": "mcp-mcast",
        "rp": "fabric",
        "rp_devices": ["edge-sw1"],
        "asm_ranges": "239.1.0.0/16",
    }
    preview, done = await flow("catc_set_fabric_multicast", args)
    assert preview["preview"]["changes"]["replication"] == {
        "from": "NATIVE_MULTICAST",
        "to": "HEADEND_REPLICATION",
    }
    assert done and [s[:2] for s in lab.sent] == [
        ("PUT", "/multicast"),
        ("POST", "/multicast/virtualNetworks"),
    ]
    assert lab.sent[1][2] == [
        {
            "fabricId": FID,
            "virtualNetworkName": "MCP_VN",
            "ipPoolName": "mcp-mcast",
            "multicastRPs": [
                {
                    "rpDeviceLocation": "FABRIC",
                    "networkDeviceIds": [DEV_ID],
                    "isDefaultV4RP": True,
                    "ipv4AsmRanges": ["239.1.0.0/16"],
                }
            ],
        }
    ]
    assert done["result"]["replication"] == "HEADEND_REPLICATION"


async def test_update_keeps_rp_and_remove(api: respx.MockRouter) -> None:
    lab = Lab(api, mode="HEADEND_REPLICATION", vns=[MVN])
    _, done = await flow(
        "catc_set_fabric_multicast",
        {"fabric_site": FID, "virtual_network": "MCP_VN", "ssm_ranges": "232.0.0.0/8"},
    )
    assert done and lab.sent[0][0] == "PUT"
    assert lab.sent[0][2][0] == {
        **{k: MVN[k] for k in ("fabricId", "virtualNetworkName", "ipPoolName", "multicastRPs", "id")},
        "ipv4SsmRanges": ["232.0.0.0/8"],
    }
    _, done = await flow(
        "catc_set_fabric_multicast", {"fabric_site": FID, "virtual_network": "MCP_VN", "remove_vn": True}
    )
    assert done and lab.sent[-1] == ("DELETE", f"/multicast/virtualNetworks/{MVN['id']}", None)


@pytest.mark.parametrize(
    ("args", "needle"),
    [
        ({"replication": "headend"}, "Nothing to change"),
        ({"virtual_network": "MCP_VN", "rp": "external"}, "ip_pool is required"),
        ({"virtual_network": "MCP_VN", "ip_pool": "p", "rp": "external"}, "needs external_rp_ip"),
        ({"virtual_network": "MCP_VN", "ip_pool": "p"}, "Give a rendezvous point"),
        ({"virtual_network": "OTHER", "ip_pool": "p", "ssm_ranges": "232.0.0.0/8"}, "not a layer 3 VN"),
        ({"ip_pool": "p"}, "Give virtual_network"),
    ],
)
async def test_blockers(api: respx.MockRouter, args: dict[str, Any], needle: str) -> None:
    lab = Lab(api, mode="HEADEND_REPLICATION", vns=[])
    out, _ = await flow("catc_set_fabric_multicast", {"fabric_site": FID, **args})
    assert out["status"] == "blocked" and needle in " ".join(out["blockers"]) and not lab.sent


async def test_remove_unknown(api: respx.MockRouter) -> None:
    Lab(api, mode=None, vns=[])
    with pytest.raises(ToolError, match="MCP_VN has no multicast"):
        await flow(
            "catc_set_fabric_multicast", {"fabric_site": FID, "virtual_network": "MCP_VN", "remove_vn": True}
        )


async def test_asm_ranges_without_rp_go_to_the_existing_rp(api: respx.MockRouter) -> None:
    lab = Lab(api, mode="HEADEND_REPLICATION", vns=[MVN])
    preview, done = await flow(
        "catc_set_fabric_multicast",
        {"fabric_site": FID, "virtual_network": "MCP_VN", "asm_ranges": "239.2.0.0/16"},
    )
    assert preview["preview"]["changes"]["MCP_VN"]["multicastRPs"]["to"][0]["ipv4AsmRanges"] == [
        "239.2.0.0/16"
    ]
    assert done and lab.sent[0][2][0]["multicastRPs"] == [
        {**MVN["multicastRPs"][0], "ipv4AsmRanges": ["239.2.0.0/16"]}
    ]


async def test_asm_ranges_without_any_rp_or_an_ambiguous_one(api: respx.MockRouter) -> None:
    two = [
        {"rpDeviceLocation": "EXTERNAL", "ipv4Address": "10.0.0.1"},
        {"rpDeviceLocation": "EXTERNAL", "ipv4Address": "10.0.0.2"},
    ]
    lab = Lab(api, mode="HEADEND_REPLICATION", vns=[{**MVN, "multicastRPs": two}])
    out, _ = await flow(
        "catc_set_fabric_multicast",
        {"fabric_site": FID, "virtual_network": "MCP_VN", "asm_ranges": "239.2.0.0/16"},
    )
    assert out["status"] == "blocked" and "none is the default IPv4 RP" in " ".join(out["blockers"])
    lab.vns = []
    out, _ = await flow(
        "catc_set_fabric_multicast",
        {
            "fabric_site": FID,
            "virtual_network": "MCP_VN",
            "ip_pool": "p",
            "ssm_ranges": "232.0.0.0/8",
            "asm_ranges": "239.2.0.0/16",
        },
    )
    assert out["status"] == "blocked" and "asm_ranges need a rendezvous point" in " ".join(out["blockers"])
    assert not lab.sent
