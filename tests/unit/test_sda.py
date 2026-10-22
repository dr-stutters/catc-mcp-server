"""D13: SD-Access writes (respx)."""

from typing import Any

import httpx
import respx
from fastmcp import Client

from catc_mcp._core.testing import call_tool
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
    l3 = body["borderDeviceSettings"]["layer3Settings"]
    assert l3["localAutonomousSystemNumber"] == "65001"
    # 3.2.2 allows priority 1-9 and prepend 1-10: unset ones are left out (Catalyst Center defaults them)
    assert "borderPriority" not in l3 and "prependAutonomousSystemCount" not in l3
    assert done and done["status"] == "applied" and post.call_count == 1


async def test_anycast_gateway_counts_edges(api: respx.MockRouter) -> None:
    edges = [
        {
            "id": f"fd{i}",
            "networkDeviceId": DEV_ID if i == 0 else f"d{i}",
            "fabricId": FID,
            "deviceRoles": ["EDGE_NODE"],
        }
        for i in range(3)
    ]
    mock_inventory(api)
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
    # edges by name where the inventory knows them, else the device id
    assert out["preview"]["edges"] == ["edge-sw1.lab.local (10.0.0.11)", "d1", "d2"]
    assert out["preview"]["body"][0]["autoGenerateVlanName"] is True
    out, _ = await flow("catc_add_anycast_gateway", {**args, "ip_pool": "missing"})
    assert "No IP pool 'missing'" in " ".join(out["blockers"])


async def test_port_assignment_maps_pool_to_vlan(api: respx.MockRouter) -> None:
    mock_inventory(api)
    api.get(f"{SDA}/fabricSites").respond(json={"response": [FABRIC]})
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


async def test_delete_last_cp_with_edges_refused(api: respx.MockRouter) -> None:
    cp = {
        "id": "fd-cp",
        "networkDeviceId": "d1",
        "fabricId": FID,
        "deviceRoles": ["CONTROL_PLANE_NODE", "BORDER_NODE"],
    }
    edge = {"id": "fd-e", "networkDeviceId": "d2", "fabricId": FID, "deviceRoles": ["EDGE_NODE"]}
    api.get(f"{SDA}/fabricSites").respond(json={"response": [FABRIC]})
    api.get(f"{SDA}/fabricDevices").respond(json={"response": [cp, edge]})
    api.get(f"{SDA}/portAssignments").respond(json={"response": []})
    out, _ = await flow("catc_delete_sda_object", {"kind": "fabric_device", "id": "fd-cp"})
    assert out["status"] == "blocked" and "last control plane" in out["blockers"][0]


async def test_delete_fabric_site_in_use_refused(api: respx.MockRouter) -> None:
    api.get(f"{SDA}/fabricSites").respond(json={"response": [FABRIC]})
    api.get(f"{SDA}/fabricDevices").respond(json={"response": []})
    api.get(f"{SDA}/anycastGateways").respond(json={"response": [{"id": "g1", "fabricId": FID}]})
    api.get(f"{SDA}/layer3VirtualNetworks").respond(
        json={"response": [{"virtualNetworkName": "CORP", "fabricIds": [FID]}]}
    )
    out, _ = await flow("catc_delete_sda_object", {"kind": "fabric_site", "id": FID})
    text = " ".join(out["blockers"])
    assert "anycast gateway" in text and "CORP" in text


async def test_status_reports_sda_not_deployed(api: respx.MockRouter) -> None:
    """D13: the dCloud 3.2.2 image ships SD Access as an optional package left SKIPPED."""
    api.get("/dna/system/api/v1/installedRelease").respond(
        json={
            "response": {
                "packages": [
                    {"name": "sda", "status": "SKIPPED"},
                    {"name": "aca", "status": "SKIPPED"},
                    {"name": "ncp", "status": "DEPLOYED"},
                ]
            }
        }
    )
    out = await call_tool(server(), "catc_status")
    sda = out["catc"]["sda"]
    assert sda["available"] is False and sda["packages"] == {"sda": "SKIPPED", "aca": "SKIPPED"}
    assert "NCSP11008" in sda["reason"]


async def test_status_reports_sda_deployed(api: respx.MockRouter) -> None:
    out = await call_tool(server(), "catc_status")
    assert out["catc"]["sda"] == {"available": True, "packages": {"sda": "DEPLOYED", "aca": "DEPLOYED"}}


async def test_status_survives_unreadable_release(api: respx.MockRouter) -> None:
    api.get("/dna/system/api/v1/installedRelease").respond(403, json={"message": "no"})
    out = await call_tool(server(), "catc_status")
    assert out["catc"]["sda"]["available"] == "unknown" and out["catc"]["devices"] == 0


# D13: catc_delete_fabric_site (cascade teardown) and catc_delete_fabric_device

PORT = {
    "id": "a0000000-0000-0000-0000-00000000000a",
    "fabricId": FID,
    "networkDeviceId": "d2",
    "interfaceName": "GigabitEthernet1/0/3",
    "dataVlanName": "CORP_VLAN",
}
GW = {
    "id": "a0000000-0000-0000-0000-00000000000b",
    "fabricId": FID,
    "ipPoolName": "corp-pool",
    "virtualNetworkName": "CORP",
    "vlanName": "CORP_VLAN",
}
CP = {
    "id": "a0000000-0000-0000-0000-00000000000c",
    "networkDeviceId": "d1",
    "fabricId": FID,
    "deviceRoles": ["CONTROL_PLANE_NODE", "BORDER_NODE"],
}
EDGE = {
    "id": "a0000000-0000-0000-0000-00000000000d",
    "networkDeviceId": "d2",
    "fabricId": FID,
    "deviceRoles": ["EDGE_NODE"],
}
OTHER_FID = "eeeeeeee-1111-2222-3333-444444444444"
VNS = [
    {"id": "vn-corp", "virtualNetworkName": "CORP", "fabricIds": [FID, OTHER_FID]},
    {"id": "vn-infra", "virtualNetworkName": "INFRA_VN", "fabricIds": [FID]},
    {"id": "vn-else", "virtualNetworkName": "ELSE", "fabricIds": [OTHER_FID]},
]


def mock_contents(
    api: respx.MockRouter,
    *,
    ports: list[dict[str, Any]],
    gws: list[dict[str, Any]],
    devices: list[dict[str, Any]],
    vns: list[dict[str, Any]],
    ipt: list[dict[str, Any]] | None = None,
) -> None:
    mock_sites(api, [GLOBAL, AREA, BLDG])
    api.get(f"/dna/intent/api/v1/sites/{BLDG['id']}").respond(json={"response": BLDG})
    api.get(f"{SDA}/fabricSites").respond(json={"response": [FABRIC]})
    api.get(f"{SDA}/fabricZones").respond(json={"response": []})
    api.get(f"{SDA}/portAssignments").respond(json={"response": ports})
    api.get(f"{SDA}/portChannels").respond(json={"response": []})
    api.get(f"{SDA}/multicast/virtualNetworks").respond(json={"response": []})
    api.get(f"{SDA}/anycastGateways").respond(json={"response": gws})
    api.get(f"{SDA}/layer2VirtualNetworks").respond(json={"response": []})

    def fabric_devices(request: httpx.Request) -> httpx.Response:
        nd = request.url.params.get("networkDeviceId")
        return httpx.Response(
            200, json={"response": [d for d in devices if nd in (None, d["networkDeviceId"])]}
        )

    api.get(f"{SDA}/fabricDevices").mock(side_effect=fabric_devices)

    def ip_transits(request: httpx.Request) -> httpx.Response:
        nd = request.url.params.get("networkDeviceId")
        return httpx.Response(200, json={"response": [x for x in ipt or [] if x["networkDeviceId"] == nd]})

    api.get(f"{SDA}/fabricDevices/layer3Handoffs/ipTransits").mock(side_effect=ip_transits)
    api.get(f"{SDA}/fabricDevices/layer3Handoffs/sdaTransits").respond(json={"response": []})
    api.get(f"{SDA}/fabricDevices/layer2Handoffs").respond(json={"response": []})
    api.get(f"{SDA}/layer3VirtualNetworks").respond(json={"response": vns})


async def test_delete_fabric_site_without_cascade_lists_contents(api: respx.MockRouter) -> None:
    mock_contents(api, ports=[PORT], gws=[GW], devices=[CP, EDGE], vns=VNS)
    out, _ = await flow("catc_delete_fabric_site", {"fabric_site": "Global/AU/SYD-1"})
    assert out["status"] == "blocked"
    text = " ".join(out["blockers"])
    assert "1 port_assignments" in text and "2 fabric_devices" in text and "cascade=true" in text
    # an INFRA_VN membership is left to go with the fabric site; only CORP is listed
    assert out["preview"]["contents"]["virtual_networks_left_by_this_site"] == ["CORP"]


async def test_delete_fabric_site_cascade_runs_in_reverse_order(api: respx.MockRouter) -> None:
    ipt = [{"id": "h1", "networkDeviceId": "d1"}]
    mock_contents(api, ports=[PORT], gws=[GW], devices=[CP, EDGE], vns=VNS, ipt=ipt)
    calls: list[str] = []

    def record(request: httpx.Request) -> httpx.Response:
        calls.append(f"{request.method} {request.url.path.removeprefix(SDA)} {dict(request.url.params)}")
        if request.method == "PUT":
            calls.append(request.content.decode())
        return httpx.Response(202, json={"response": {"taskId": "tk"}})

    api.route(method="DELETE", path__startswith=SDA).mock(side_effect=record)
    api.put(f"{SDA}/layer3VirtualNetworks").mock(side_effect=record)
    task_ok(api, "tk")
    preview, done = await flow("catc_delete_fabric_site", {"fabric_site": FID, "cascade": True})
    assert preview["status"] == "preview" and preview["blast_radius"] == 2
    order = preview["preview"]["order"]
    assert order[0].startswith("delete port assignment") and order[-1].startswith("delete fabric site")
    assert done and done["status"] == "applied" and done["result"]["steps"] == len(order) == 7
    paths = [c for c in calls if not c.startswith("[")]
    assert paths == [
        f"DELETE /portAssignments/{PORT['id']} {{}}",
        f"DELETE /anycastGateways/{GW['id']} {{}}",
        f"DELETE /fabricDevices/layer3Handoffs/ipTransits {{'fabricId': '{FID}', 'networkDeviceId': 'd1'}}",
        "PUT /layer3VirtualNetworks {}",
        f"DELETE /fabricDevices/{EDGE['id']} {{}}",  # edges before the control plane
        f"DELETE /fabricDevices/{CP['id']} {{}}",
        f"DELETE /fabricSites/{FID} {{}}",
    ]
    put = [c for c in calls if c.startswith("[")][0]
    assert f'"fabricIds":["{OTHER_FID}"]' in put.replace(" ", "") and "INFRA_VN" not in put


async def test_delete_fabric_site_stops_and_reports(api: respx.MockRouter) -> None:
    import pytest
    from fastmcp.exceptions import ToolError

    mock_contents(api, ports=[PORT], gws=[GW], devices=[], vns=[])
    api.delete(f"{SDA}/portAssignments/{PORT['id']}").respond(202, json={"response": {"taskId": "ok"}})
    api.delete(f"{SDA}/anycastGateways/{GW['id']}").respond(202, json={"response": {"taskId": "bad"}})
    task_ok(api, "ok")
    api.get("/dna/intent/api/v1/task/bad").respond(
        json={"response": {"isError": True, "endTime": 1, "failureReason": "NCSP10000: gateway in use"}}
    )
    with pytest.raises(ToolError, match=r"Stopped at 'delete anycast gateway corp-pool' \(1 of 3"):
        await flow("catc_delete_fabric_site", {"fabric_site": FID, "cascade": True})


async def test_delete_empty_fabric_site(api: respx.MockRouter) -> None:
    mock_contents(api, ports=[], gws=[], devices=[], vns=[VNS[1]])
    delete = api.delete(f"{SDA}/fabricSites/{FID}").respond(202, json={"response": {"taskId": "tk"}})
    task_ok(api, "tk")
    preview, done = await flow("catc_delete_fabric_site", {"fabric_site": "Global/AU/SYD-1"})
    assert preview["status"] == "preview" and preview.get("blast_radius") is None
    assert "no device configuration changes" in preview["side_effects"][0]
    assert done and done["status"] == "applied" and delete.call_count == 1


async def test_delete_fabric_device_by_name(api: respx.MockRouter) -> None:
    import pytest
    from fastmcp.exceptions import ToolError

    mock_inventory(api)
    edge = {**EDGE, "networkDeviceId": DEV_ID}
    port = {**PORT, "networkDeviceId": DEV_ID}
    mock_contents(api, ports=[port], gws=[], devices=[CP, edge], vns=[])
    out, _ = await flow("catc_delete_fabric_device", {"device": "edge-sw1"})
    assert out["status"] == "blocked" and "1 port_assignments" in out["blockers"][0]
    dp = api.delete(f"{SDA}/portAssignments/{PORT['id']}").respond(202, json={"response": {"taskId": "tk"}})
    dd = api.delete(f"{SDA}/fabricDevices/{EDGE['id']}").respond(202, json={"response": {"taskId": "tk"}})
    task_ok(api, "tk")
    preview, done = await flow("catc_delete_fabric_device", {"device": "edge-sw1", "cascade": True})
    assert preview["status"] == "preview", preview
    assert preview["blast_radius"] == 1 and len(preview["preview"]["order"]) == 2
    assert done and done["status"] == "applied" and dp.call_count == dd.call_count == 1
    api.get(f"{SDA}/fabricDevices").respond(json={"response": []})
    with pytest.raises(ToolError, match="not a fabric device"):
        await flow("catc_delete_fabric_device", {"device": "edge-sw1"})


async def test_add_border_with_priority_and_prepend(api: respx.MockRouter) -> None:
    mock_inventory(api)
    mock_fabric(api, [])
    api.get(f"{SDA}/provisionDevices").respond(json={"response": [{"id": "p", "networkDeviceId": DEV_ID}]})
    args = {
        "device": "edge-sw1",
        "fabric_site": FID,
        "roles": ["CONTROL_PLANE_NODE", "BORDER_NODE"],
        "border_asn": "65001",
        "border_priority": 2,
        "prepend_as_count": 3,
    }
    api.post(f"{SDA}/fabricDevices").respond(202, json={"response": {"taskId": "td"}})
    task_ok(api, "td")
    out, _ = await flow("catc_add_fabric_device", {**args})
    l3 = out["preview"]["body"][0]["borderDeviceSettings"]["layer3Settings"]
    assert l3["borderPriority"] == 2 and l3["prependAutonomousSystemCount"] == 3
