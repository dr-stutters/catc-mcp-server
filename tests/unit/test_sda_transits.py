"""D93: SD-Access transits and layer 3 handoffs (respx); payloads follow the 3.2.2 spec."""

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
IPT = f"{SDA}/fabricDevices/layer3Handoffs/ipTransits"
SDAT = f"{SDA}/fabricDevices/layer3Handoffs/sdaTransits"
T_IP = {
    "id": "t-ip",
    "name": "mcp-ip-transit",
    "type": "IP_BASED_TRANSIT",
    "ipTransitSettings": {"routingProtocolName": "BGP", "autonomousSystemNumber": "65002"},
}
T_SDA = {
    "id": "t-sda",
    "name": "mcp-sda-transit",
    "type": "SDA_LISP_PUB_SUB_TRANSIT",
    "sdaTransitSettings": {"controlPlaneNetworkDeviceIds": ["cp1"], "isMulticastOverTransitEnabled": False},
}
BORDER = {
    "id": "fd-b",
    "networkDeviceId": DEV_ID,
    "fabricId": FID,
    "deviceRoles": ["BORDER_NODE", "CONTROL_PLANE_NODE"],
}


class Lab:
    def __init__(
        self,
        api: respx.MockRouter,
        *,
        transits: list[dict[str, Any]],
        ip: list[dict[str, Any]] | None = None,
        border: bool = True,
        extranet: list[dict[str, Any]] | None = None,
    ) -> None:
        self.ip = list(ip or [])
        self.sent: list[tuple[str, str, Any]] = []
        mock_inventory(api)
        api.get(f"{SDA}/fabricSites").respond(json={"response": [FABRIC]})
        devs = [BORDER] if border else [{**BORDER, "deviceRoles": ["EDGE_NODE"]}]
        api.get(f"{SDA}/fabricDevices").mock(
            side_effect=lambda r: httpx.Response(
                200,
                json={
                    "response": [
                        d for d in devs if r.url.params.get("networkDeviceId") in (None, d["networkDeviceId"])
                    ]
                },
            )
        )

        def by_name(r: httpx.Request) -> httpx.Response:
            n = r.url.params.get("name")
            return httpx.Response(200, json={"response": [t for t in transits if n in (None, t["name"])]})

        api.get(f"{SDA}/transitNetworks").mock(side_effect=by_name)
        api.get(IPT).mock(side_effect=lambda r: httpx.Response(200, json={"response": self.ip}))
        api.get(SDAT).respond(json={"response": []})
        api.get(f"{SDA}/extranetPolicies").respond(json={"response": extranet or []})
        api.get(f"{SDA}/layer3VirtualNetworks").respond(
            json={
                "response": [
                    {"virtualNetworkName": "MCP_VN", "fabricIds": [FID]},
                    {"virtualNetworkName": "ELSE", "fabricIds": ["x"]},
                ]
            }
        )
        for method in ("POST", "DELETE"):
            api.route(method=method, path__startswith=SDA).mock(side_effect=self.record)
        task_ok(api, "tt")

    def record(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content) if request.content else None
        self.sent.append((request.method, request.url.path.removeprefix(SDA), body))
        return httpx.Response(202, json={"response": {"taskId": "tt"}})


async def test_list_transits(api: respx.MockRouter) -> None:
    Lab(api, transits=[T_IP, T_SDA])
    out = await call("catc_list_transit_networks", {"response_format": "json"})
    assert out["total"] == 2 and out["results"][0] == {
        "name": "mcp-ip-transit",
        "type": "IP_BASED_TRANSIT",
        "id": "t-ip",
        "asn": "65002",
        "routing_protocol": "BGP",
        "kind": "IP transit (VRF-lite eBGP per VN; also SD-Access over SD-WAN to the WAN edge)",
    }
    assert out["results"][1]["control_plane_devices"] == ["cp1"]
    assert out["results"][1]["control_plane"] == ["cp1"]  # not in the inventory: the id


async def test_create_ip_transit(api: respx.MockRouter) -> None:
    lab = Lab(api, transits=[])
    preview, done = await flow(
        "catc_create_transit_network", {"name": "mcp-ip-transit", "transit_type": "ip", "asn": "65002"}
    )
    assert preview["preview"]["body"] == [
        {
            "name": "mcp-ip-transit",
            "type": "IP_BASED_TRANSIT",
            "ipTransitSettings": {"routingProtocolName": "BGP", "autonomousSystemNumber": "65002"},
        }
    ]
    assert done and lab.sent[0][:2] == ("POST", "/transitNetworks")


@pytest.mark.parametrize(
    ("args", "needle"),
    [
        ({"name": "x", "transit_type": "ip"}, "needs asn"),
        ({"name": "x", "transit_type": "sda_pubsub"}, "needs one or two control_plane_devices"),
        ({"name": "mcp-ip-transit", "transit_type": "ip", "asn": "1"}, "exists"),
    ],
)
async def test_create_transit_blockers(api: respx.MockRouter, args: dict[str, Any], needle: str) -> None:
    Lab(api, transits=[T_IP])
    out, _ = await flow("catc_create_transit_network", args)
    assert out["status"] == "blocked" and needle in " ".join(out["blockers"])


async def test_create_sda_transit_resolves_control_planes(api: respx.MockRouter) -> None:
    Lab(api, transits=[])
    out, _ = await flow(
        "catc_create_transit_network",
        {"name": "mcp-sda-transit", "transit_type": "sda_pubsub", "control_plane_devices": ["edge-sw1"]},
    )
    assert out["preview"]["body"][0]["sdaTransitSettings"] == {"controlPlaneNetworkDeviceIds": [DEV_ID]}


async def test_ip_handoff(api: respx.MockRouter) -> None:
    lab = Lab(api, transits=[T_IP])
    args = {
        "border": "edge-sw1",
        "transit": "mcp-ip-transit",
        "interface": "GigabitEthernet1/0/4",
        "virtual_networks": [
            {
                "virtual_network": "MCP_VN",
                "vlan_id": 3001,
                "local_ip": "10.255.30.1/30",
                "remote_ip": "10.255.30.2/30",
            }
        ],
    }
    preview, done = await flow("catc_add_l3_handoff", args)
    assert preview["status"] == "preview" and preview["blast_radius"] == 1
    assert preview["preview"]["body"] == [
        {
            "networkDeviceId": DEV_ID,
            "fabricId": FID,
            "transitNetworkId": "t-ip",
            "interfaceName": "GigabitEthernet1/0/4",
            "virtualNetworkName": "MCP_VN",
            "vlanId": 3001,
            "localIpAddress": "10.255.30.1/30",
            "remoteIpAddress": "10.255.30.2/30",
        }
    ]
    assert done and lab.sent[0][:2] == ("POST", "/fabricDevices/layer3Handoffs/ipTransits")


@pytest.mark.parametrize(
    ("vn", "needle"),
    [
        (
            {
                "virtual_network": "ELSE",
                "vlan_id": 3001,
                "local_ip": "10.0.0.1/30",
                "remote_ip": "10.0.0.2/30",
            },
            "not a layer 3 VN",
        ),
        (
            {
                "virtual_network": "MCP_VN",
                "vlan_id": 3000,
                "local_ip": "10.0.0.1/30",
                "remote_ip": "10.0.0.2/30",
            },
            "VLAN 3000 is already used",
        ),
        ({"virtual_network": "MCP_VN", "vlan_id": 3001}, "give local_ip and remote_ip"),
        (
            {
                "virtual_network": "MCP_VN",
                "vlan_id": 3001,
                "local_ip": "10.0.0.1",
                "remote_ip": "10.0.0.2/30",
            },
            "CIDR",
        ),
    ],
)
async def test_ip_handoff_blockers(api: respx.MockRouter, vn: dict[str, Any], needle: str) -> None:
    Lab(
        api,
        transits=[T_IP],
        ip=[{"id": "h0", "vlanId": 3000, "virtualNetworkName": "OTHER", "transitNetworkId": "t-ip"}],
    )
    out, _ = await flow(
        "catc_add_l3_handoff",
        {"border": "edge-sw1", "transit": "t-ip", "interface": "Gi1/0/4", "virtual_networks": [vn]},
    )
    assert out["status"] == "blocked" and needle in " ".join(out["blockers"])


async def test_handoff_needs_a_border(api: respx.MockRouter) -> None:
    Lab(api, transits=[T_IP], border=False)
    with pytest.raises(ToolError, match="is not a border node"):
        await flow("catc_add_l3_handoff", {"border": "edge-sw1", "transit": "t-ip"})


async def test_sda_handoff(api: respx.MockRouter) -> None:
    Lab(api, transits=[T_SDA])
    out, _ = await flow(
        "catc_add_l3_handoff",
        {"border": "edge-sw1", "transit": "mcp-sda-transit", "connected_to_internet": True},
    )
    assert out["preview"]["path"] == f"{SDAT}" and out["preview"]["body"] == [
        {"networkDeviceId": DEV_ID, "fabricId": FID, "transitNetworkId": "t-sda", "connectedToInternet": True}
    ]


async def test_sda_handoff_blocked_by_extranet_policies(api: respx.MockRouter) -> None:
    """Live on 3.2.2 (2026-10-22, lab mcp-catc-fabric), the handoff passed its preview and then failed: 'add
    layer 3 handoff failed: Failed to add SD-Access Transit mcp-sda-transit to Fabric Site
    Global/mcp-test-lab/mcp-test-fabric due to existing Extranet Policies. Remove these policies from the
    Fabric Site before connecting to the SD-Access Transit. You can apply the appropriate Extranet Policy to
    multisite afterwards, given the transit is not a Hybrid Transit.' The preview now blocks and names the
    policies."""
    lab = Lab(
        api,
        transits=[T_SDA],
        extranet=[
            {"id": "e1", "extranetPolicyName": "MCP_SHARED", "fabricIds": [FID, "other"]},
            {"id": "e2", "extranetPolicyName": "ELSEWHERE", "fabricIds": ["other"]},
        ],
    )
    out, done = await flow("catc_add_l3_handoff", {"border": "edge-sw1", "transit": "mcp-sda-transit"})
    assert out["status"] == "blocked" and done is None and not lab.sent
    (blocker,) = out["blockers"]
    assert "extranet policies (MCP_SHARED)" in blocker and "ELSEWHERE" not in blocker
    assert "catc_set_extranet_policy(name, delete=true)" in blocker and "apply the policies again" in blocker


async def test_ip_handoff_ignores_extranet_policies(api: respx.MockRouter) -> None:
    Lab(api, transits=[T_IP], extranet=[{"id": "e1", "extranetPolicyName": "MCP_SHARED", "fabricIds": [FID]}])
    out, _ = await flow(
        "catc_add_l3_handoff",
        {
            "border": "edge-sw1",
            "transit": "mcp-ip-transit",
            "interface": "Gi1/0/4",
            "virtual_networks": [
                {
                    "virtual_network": "MCP_VN",
                    "vlan_id": 3001,
                    "local_ip": "10.0.0.1/30",
                    "remote_ip": "10.0.0.2/30",
                }
            ],
        },
    )
    assert out["status"] == "preview"


async def test_delete_handoff_and_transit(api: respx.MockRouter) -> None:
    have = [
        {
            "id": "a0000000-0000-0000-0000-0000000000a1",
            "vlanId": 3001,
            "virtualNetworkName": "MCP_VN",
            "transitNetworkId": "t-ip",
            "networkDeviceId": DEV_ID,
        },
        {
            "id": "a0000000-0000-0000-0000-0000000000a2",
            "vlanId": 3002,
            "virtualNetworkName": "SHARED",
            "transitNetworkId": "t-ip",
            "networkDeviceId": DEV_ID,
        },
    ]
    lab = Lab(
        api,
        transits=[{**T_IP, "id": "a0000000-0000-0000-0000-0000000000f1"}],
        ip=[{**h, "transitNetworkId": "a0000000-0000-0000-0000-0000000000f1"} for h in have],
    )
    out, _ = await flow("catc_delete_transit_network", {"transit": "mcp-ip-transit"})
    assert out["status"] == "blocked" and "2 handoff(s) on 1 border(s)" in out["blockers"][0]
    preview, done = await flow(
        "catc_delete_l3_handoff",
        {"border": "edge-sw1", "transit": "mcp-ip-transit", "virtual_networks": ["MCP_VN"]},
    )
    assert len(preview["preview"]["handoffs"]) == 1 and done and done["result"]["removed"] == ["MCP_VN"]
    assert lab.sent == [
        ("DELETE", "/fabricDevices/layer3Handoffs/ipTransits/a0000000-0000-0000-0000-0000000000a1", None)
    ]
    with pytest.raises(ToolError, match="No handoff onto mcp-ip-transit for NOPE"):
        await flow(
            "catc_delete_l3_handoff",
            {"border": "edge-sw1", "transit": "mcp-ip-transit", "virtual_networks": ["NOPE"]},
        )
    lab.ip = []
    _, done = await flow("catc_delete_transit_network", {"transit": "mcp-ip-transit"})
    assert done and lab.sent[-1][:2] == ("DELETE", "/transitNetworks/a0000000-0000-0000-0000-0000000000f1")


# D116: handoff reads. Shapes from the 3.2.2 spec (ipTransitGetResponse, sdaTransitGetResponse,
# fabricDeviceGetResponse.borderDeviceSettings) and checked against a live 3.2.2 read (2026-10-28).
T_WAN = {
    "id": "t-wan",
    "name": "mcp-sdwan-transit",
    "type": "IP_BASED_TRANSIT",
    "ipTransitSettings": {"routingProtocolName": "BGP", "autonomousSystemNumber": "65000"},
}
BORDER_AS = {
    **BORDER,
    "borderDeviceSettings": {
        "borderTypes": ["LAYER_3"],
        "layer3Settings": {"localAutonomousSystemNumber": "65010", "isDefaultExit": True},
    },
}
EDGE = {
    "id": "fd-e",
    "networkDeviceId": "22222222-2222-3333-4444-555555555555",
    "fabricId": FID,
    "deviceRoles": ["EDGE_NODE"],
}
H_CORP = {
    "id": "h-corp",
    "networkDeviceId": DEV_ID,
    "fabricId": FID,
    "transitNetworkId": "t-wan",
    "interfaceName": "GigabitEthernet1/0/8",
    "externalConnectivityIpPoolName": "mcp-handoff-pool",
    "virtualNetworkName": "MCP_CORP_VN",
    "vlanId": 3010,
    "tcpMssAdjustment": 0,
    "localIpAddress": "192.0.2.1/30",
    "remoteIpAddress": "192.0.2.2/30",
}
H_IOT = {
    **H_CORP,
    "id": "h-iot",
    "virtualNetworkName": "MCP_IOT_VN",
    "vlanId": 3020,
    "localIpAddress": "192.0.2.5/30",
    "remoteIpAddress": "192.0.2.6/30",
    "tcpMssAdjustment": 1360,
}
H_SDA = {
    "networkDeviceId": DEV_ID,
    "fabricId": FID,
    "transitNetworkId": "t-sda",
    "connectedToInternet": True,
    "lispTransportType": "IPV4",
    "isDualStack": False,
    "isMulticastOverTransitEnabled": False,
}


def handoff_lab(api: respx.MockRouter, *, sda: bool = True) -> None:
    mock_inventory(api)
    mock_sites(api, [GLOBAL, AREA, BLDG])
    api.get(f"/dna/intent/api/v1/sites/{BLDG['id']}").respond(json={"response": BLDG})
    api.get(f"{SDA}/fabricSites").respond(json={"response": [FABRIC]})
    api.get(f"{SDA}/fabricDevices").respond(json={"response": [BORDER_AS, EDGE]})
    api.get(f"{SDA}/transitNetworks").respond(json={"response": [T_WAN, T_SDA]})

    def per_device(rows: list[dict[str, Any]]) -> Any:
        def answer(r: httpx.Request) -> httpx.Response:
            assert r.url.params.get("fabricId") == FID
            nd = r.url.params.get("networkDeviceId")
            return httpx.Response(
                200, json={"response": [h for h in rows if nd in (None, h["networkDeviceId"])]}
            )

        return answer

    api.get(IPT).mock(side_effect=per_device([H_CORP, H_IOT]))
    api.get(SDAT).mock(side_effect=per_device([H_SDA] if sda else []))


async def test_list_l3_handoffs(api: respx.MockRouter) -> None:
    handoff_lab(api)
    out = await call("catc_list_l3_handoffs", {"fabric_site": FID, "response_format": "json"})
    assert out["total"] == 3
    corp, iot, lisp = out["results"]
    assert corp == {
        "border": "edge-sw1.lab.local (10.0.0.11)",
        "transit": "mcp-sdwan-transit",
        "transit_type": "IP_BASED_TRANSIT",
        "virtual_network": "MCP_CORP_VN",
        "vlan_id": 3010,
        "interface": "GigabitEthernet1/0/8",
        "local_ip": "192.0.2.1/30",
        "remote_ip": "192.0.2.2/30",
        "local_as": "65010",
        "remote_as": "65000",
        "external_pool": "mcp-handoff-pool",
        "id": "h-corp",
    }
    assert iot["virtual_network"] == "MCP_IOT_VN" and iot["tcp_mss_adjustment"] == 1360
    assert lisp["transit"] == "mcp-sda-transit" and lisp["connected_to_internet"] is True
    assert lisp["lisp_transport"] == "IPV4" and "id" not in lisp  # 3.2.2 returns no id for these


async def test_list_l3_handoffs_filters(api: respx.MockRouter) -> None:
    handoff_lab(api)
    out = await call(
        "catc_list_l3_handoffs",
        {
            "fabric_site": BLDG["nameHierarchy"],
            "border": "edge-sw1",
            "virtual_network": "MCP_IOT_VN",
            "response_format": "json",
        },
    )
    assert [r["id"] for r in out["results"]] == ["h-iot"]


async def test_list_l3_handoffs_not_a_border(api: respx.MockRouter) -> None:
    handoff_lab(api)
    with pytest.raises(ToolError, match="not a border node"):
        await call("catc_list_l3_handoffs", {"fabric_site": FID, "border": "edge-sw2"})


async def test_list_transits_usage(api: respx.MockRouter) -> None:
    handoff_lab(api)
    out = await call("catc_list_transit_networks", {"usage": True, "response_format": "json"})
    wan, sda = out["results"]
    assert wan["handoffs"] == 2 and wan["borders"] == ["edge-sw1.lab.local (10.0.0.11)"]
    assert wan["virtual_networks"] == ["MCP_CORP_VN", "MCP_IOT_VN"]
    assert sda["handoffs"] == 1 and "virtual_networks" not in sda
    assert sda["kind"] == "SD-Access transit (LISP pub/sub)"
