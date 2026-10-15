"""D13: SD-Access writes (respx)."""

from typing import Any

import httpx
import respx
from fastmcp import Client

from catc_mcp.server import create_server

from .conftest import make_settings
from .test_read_tools import AREA, BLDG, DEV_ID, GLOBAL
from .test_safety import mock_inventory
from .test_write_tools import mock_sites, run, task_ok

SDA = "/dna/intent/api/v1/sda"
FID = "ffffffff-1111-2222-3333-444444444444"
FABRIC = {"id": FID, "siteId": BLDG["id"], "authenticationProfileName": "No Authentication"}


def server() -> Any:
    return create_server(make_settings(mcp_enable_writes=True, mcp_enable_dangerous=True))


async def flow(name: str, args: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any] | None]:
    async with Client(server()) as c:
        preview = await run(c, name, args)
        if preview.get("status") != "preview":
            return preview, None
        return preview, await run(c, name, {**args, "confirm": preview["confirm"]})


async def test_create_fabric_site(api: respx.MockRouter) -> None:
    mock_sites(api, [GLOBAL, AREA, BLDG])
    api.get(f"{SDA}/fabricSites").mock(
        side_effect=[
            httpx.Response(200, json={"response": []}),  # preview
            httpx.Response(200, json={"response": []}),  # confirm re-check
            httpx.Response(200, json={"response": [FABRIC]}),  # after
        ]
    )
    post = api.post(f"{SDA}/fabricSites").respond(202, json={"response": {"taskId": "tf"}})
    task_ok(api, "tf")
    preview, done = await flow("catc_create_fabric_site", {"site": "Global/AU/SYD-1"})
    assert preview["preview"]["body"][0]["siteId"] == BLDG["id"]
    assert done and done["result"]["fabric_id"] == FID and post.call_count == 1


async def test_fabric_site_refuses_floor_and_duplicate(api: respx.MockRouter) -> None:
    floor = {
        **BLDG,
        "id": "aaaaaaaa-0000-0000-0000-000000000003",
        "nameHierarchy": "Global/AU/SYD-1/F1",
        "name": "F1",
        "type": "floor",
    }
    mock_sites(api, [GLOBAL, AREA, BLDG, floor])
    api.get(f"{SDA}/fabricSites").respond(json={"response": [FABRIC]})
    out, _ = await flow("catc_create_fabric_site", {"site": "Global/AU/SYD-1/F1"})
    assert out["status"] == "blocked" and "not a floor" in " ".join(out["blockers"])
    out, _ = await flow("catc_create_fabric_site", {"site": "Global/AU/SYD-1"})
    assert out["status"] == "blocked" and "already a fabric site" in out["blockers"][0]


def mock_fabric(
    api: respx.MockRouter, devices: list[dict[str, Any]], *, site: str = "Global/AU/SYD-1"
) -> None:
    mock_sites(api, [GLOBAL, AREA, BLDG])
    api.get(f"{SDA}/fabricSites").respond(json={"response": [FABRIC]})
    api.get(f"/dna/intent/api/v1/sites/{BLDG['id']}").respond(json={"response": BLDG})
    api.get(f"{SDA}/fabricDevices").respond(json={"response": devices})
    api.get(f"/dna/intent/api/v1/networkDevices/{DEV_ID}/assignedToSite").respond(
        json={"response": {"siteNameHierarchy": site}}
    )


async def test_add_fabric_device_blockers(api: respx.MockRouter) -> None:
    mock_inventory(api)
    mock_fabric(api, [], site="Global/Elsewhere")
    api.get(f"{SDA}/provisionDevices").respond(json={"response": []})
    out, _ = await flow(
        "catc_add_fabric_device", {"device": "edge-sw1", "fabric_site": FID, "roles": ["EDGE_NODE"]}
    )
    text = " ".join(out["blockers"])
    assert "not inside the fabric site" in text and "not provisioned" in text and "no control plane" in text
    out, _ = await flow(
        "catc_add_fabric_device",
        {"device": "edge-sw1", "fabric_site": FID, "roles": ["BORDER_NODE", "CONTROL_PLANE_NODE"]},
    )
    assert "border_asn" in " ".join(out["blockers"])


async def test_add_border_cp(api: respx.MockRouter) -> None:
    mock_inventory(api)
    mock_fabric(api, [])
    api.get(f"{SDA}/provisionDevices").respond(json={"response": [{"id": "p", "networkDeviceId": DEV_ID}]})
    post = api.post(f"{SDA}/fabricDevices").respond(202, json={"response": {"taskId": "td"}})
    task_ok(api, "td")
    args = {
        "device": "edge-sw1",
        "fabric_site": "Global/AU/SYD-1",
        "roles": ["CONTROL_PLANE_NODE", "BORDER_NODE"],
        "border_asn": "65001",
    }
    preview, done = await flow("catc_add_fabric_device", args)
    body = preview["preview"]["body"][0]
    assert body["deviceRoles"] == ["BORDER_NODE", "CONTROL_PLANE_NODE"] and preview["blast_radius"] == 1
    assert body["borderDeviceSettings"]["layer3Settings"]["localAutonomousSystemNumber"] == "65001"
    assert done and done["status"] == "applied" and post.call_count == 1


async def test_anycast_gateway_counts_edges(api: respx.MockRouter) -> None:
    edges = [
        {"id": f"fd{i}", "networkDeviceId": f"d{i}", "fabricId": FID, "deviceRoles": ["EDGE_NODE"]}
        for i in range(3)
    ]
    mock_fabric(api, edges)
    api.get(f"{SDA}/layer3VirtualNetworks").respond(
        json={"response": [{"virtualNetworkName": "CORP", "fabricIds": [FID]}]}
    )
    api.get("/dna/intent/api/v1/ipam/siteIpAddressPools").respond(json={"response": [{"name": "corp-pool"}]})
    api.get(f"{SDA}/anycastGateways").respond(json={"response": []})
    api.post(f"{SDA}/anycastGateways").respond(202, json={"response": {"taskId": "tg"}})
    task_ok(api, "tg")
    args = {"fabric_site": FID, "virtual_network": "CORP", "ip_pool": "corp-pool"}
    out, _ = await flow("catc_add_anycast_gateway", args)
    assert out["status"] == "preview" and out["blast_radius"] == 3
    assert out["preview"]["body"][0]["autoGenerateVlanName"] is True
    out, _ = await flow("catc_add_anycast_gateway", {**args, "ip_pool": "missing"})
    assert "No IP pool 'missing'" in " ".join(out["blockers"])


async def test_port_assignment_maps_pool_to_vlan(api: respx.MockRouter) -> None:
    mock_inventory(api)
    api.get(f"{SDA}/fabricDevices").respond(
        json={
            "response": [
                {"id": "fd", "networkDeviceId": DEV_ID, "fabricId": FID, "deviceRoles": ["EDGE_NODE"]}
            ]
        }
    )
    api.get(f"{SDA}/anycastGateways").respond(
        json={"response": [{"ipPoolName": "corp-pool", "vlanName": "CORP_VLAN"}]}
    )
    api.get(f"{SDA}/portAssignments").respond(json={"response": []})
    api.post(f"{SDA}/portAssignments").respond(202, json={"response": {"taskId": "tp"}})
    task_ok(api, "tp")
    out, _ = await flow(
        "catc_assign_fabric_port",
        {"device": "edge-sw1", "interface": "GigabitEthernet1/0/3", "data_vlan": "corp-pool"},
    )
    assert out["status"] == "preview" and out["preview"]["body"][0]["dataVlanName"] == "CORP_VLAN"
    out, _ = await flow(
        "catc_assign_fabric_port",
        {"device": "edge-sw1", "interface": "GigabitEthernet1/0/3", "data_vlan": "nope"},
    )
    assert out["status"] == "blocked"


async def test_delete_vn_in_use_refused(api: respx.MockRouter) -> None:
    api.get(f"{SDA}/layer3VirtualNetworks").respond(
        json={"response": [{"id": "vn1", "virtualNetworkName": "CORP", "fabricIds": [FID]}]}
    )
    api.get(f"{SDA}/anycastGateways").respond(json={"response": [{"virtualNetworkName": "CORP"}]})
    out, _ = await flow("catc_delete_sda_object", {"kind": "virtual_network", "name": "CORP"})
    assert out["status"] == "blocked" and "anycast gateway" in out["blockers"][0]


async def test_sda_application_missing_is_explained(api: respx.MockRouter) -> None:
    import pytest
    from fastmcp.exceptions import ToolError

    mock_sites(api, [GLOBAL, AREA, BLDG])
    api.get(f"{SDA}/fabricSites").respond(json={"response": []})
    api.post(f"{SDA}/fabricSites").respond(202, json={"response": {"taskId": "tx"}})
    api.get("/dna/intent/api/v1/task/tx").respond(
        json={
            "response": {
                "isError": True,
                "endTime": 1,
                "failureReason": "NCSP11008: Package required to process the request was not found.",
            }
        }
    )
    with pytest.raises(ToolError, match="SD-Access application"):
        await flow("catc_create_fabric_site", {"site": "Global/AU/SYD-1"})
