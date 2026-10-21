"""D106: extended-node ports and the INFRA_VN extended-node pool; Closed Authentication ports without a VLAN
(respx; the 3.2.2 spec: 'at least one vlanName is required ... for authenticateTemplateName other than Closed
Authentication')."""

from typing import Any

import pytest
import respx

from .test_read_tools import DEV_ID
from .test_safety import mock_inventory
from .test_sda import FABRIC, FID, flow, mock_fabric
from .test_write_tools import task_ok

SDA = "/dna/intent/api/v1/sda"
EDGE = {"id": "fd", "networkDeviceId": DEV_ID, "fabricId": FID, "deviceRoles": ["EDGE_NODE"]}


def gateway_lab(api: respx.MockRouter) -> None:
    mock_fabric(api, [EDGE])
    api.get(f"{SDA}/layer3VirtualNetworks").respond(
        json={
            "response": [
                {"virtualNetworkName": "INFRA_VN"},
                {"virtualNetworkName": "CORP", "fabricIds": [FID]},
            ]
        }
    )
    api.get("/dna/intent/api/v1/ipam/siteIpAddressPools").respond(
        json={"response": [{"name": "mcp-extnodes"}]}
    )
    api.get(f"{SDA}/anycastGateways").respond(json={"response": []})
    api.post(f"{SDA}/anycastGateways").respond(202, json={"response": {"taskId": "tg"}})
    task_ok(api, "tg")


async def test_infra_vn_extended_node_pool(api: respx.MockRouter) -> None:
    gateway_lab(api)
    args = {
        "fabric_site": FID,
        "virtual_network": "INFRA_VN",
        "ip_pool": "mcp-extnodes",
        "pool_type": "EXTENDED_NODE",
        "supplicant_based_onboarding": True,
    }
    out, _ = await flow("catc_add_anycast_gateway", args)
    body = out["preview"]["body"][0]
    assert out["status"] == "preview" and body["poolType"] == "EXTENDED_NODE"
    assert (
        body["isSupplicantBasedExtendedNodeOnboarding"] is True and body["virtualNetworkName"] == "INFRA_VN"
    )


@pytest.mark.parametrize(
    ("args", "needle"),
    [
        ({"virtual_network": "INFRA_VN"}, "needs pool_type"),
        (
            {"virtual_network": "INFRA_VN", "pool_type": "FABRIC_AP", "supplicant_based_onboarding": True},
            "EXTENDED_NODE pool",
        ),
        ({"virtual_network": "CORP", "pool_type": "EXTENDED_NODE"}, "INFRA_VN gateways only"),
    ],
)
async def test_gateway_blockers(api: respx.MockRouter, args: dict[str, Any], needle: str) -> None:
    gateway_lab(api)
    out, _ = await flow("catc_add_anycast_gateway", {"fabric_site": FID, "ip_pool": "mcp-extnodes", **args})
    assert out["status"] == "blocked" and needle in " ".join(out["blockers"])


def port_lab(api: respx.MockRouter, default: str = "No Authentication") -> None:
    mock_inventory(api)
    api.get(f"{SDA}/fabricSites").respond(
        json={"response": [{**FABRIC, "authenticationProfileName": default}]}
    )
    api.get(f"{SDA}/fabricDevices").respond(json={"response": [EDGE]})
    api.get(f"{SDA}/anycastGateways").respond(
        json={"response": [{"ipPoolName": "corp-pool", "vlanName": "CORP_VLAN"}]}
    )
    api.get(f"{SDA}/portAssignments").respond(json={"response": []})
    api.post(f"{SDA}/portAssignments").respond(202, json={"response": {"taskId": "tp"}})
    task_ok(api, "tp")


@pytest.mark.parametrize(
    ("default", "args", "ok"),
    [
        ("No Authentication", {"connected_device_type": "AUTHENTICATOR_SWITCH"}, True),
        ("No Authentication", {"connected_device_type": "SUPPLICANT_BASED_EXTENDED_NODE"}, True),
        ("No Authentication", {"authentication": "Closed Authentication"}, True),
        ("Closed Authentication", {}, True),
        ("No Authentication", {}, False),
        ("Closed Authentication", {"authentication": "Open Authentication"}, False),
        (
            "No Authentication",
            {"connected_device_type": "AUTHENTICATOR_SWITCH", "data_vlan": "corp-pool"},
            False,
        ),
    ],
)
async def test_port_vlan_rules(api: respx.MockRouter, default: str, args: dict[str, Any], ok: bool) -> None:
    port_lab(api, default)
    out, _ = await flow(
        "catc_assign_fabric_port", {"device": "edge-sw1", "interface": "GigabitEthernet1/0/5", **args}
    )
    assert (out["status"] == "preview") is ok, out.get("blockers")
    if ok:
        body = out["preview"]["body"][0]
        assert "dataVlanName" not in body
        if body["connectedDeviceType"] == "USER_DEVICE":
            # no VLAN only with the template named in the request, even when it comes from the site default
            assert body["authenticateTemplateName"] == "Closed Authentication"
