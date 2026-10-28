"""D50: catc_provision_site provisions every assigned, unprovisioned device at a site (mocked).

Payload shapes recorded from Catalyst Center 3.2.2 (2026-10-28): `networkDevices/assignedToSite` lists a
site's own devices only ({"deviceId", "siteId", "siteNameHierarchy", "siteType"}), so each floor is read;
`sda/provisionDevices` records are {"id", "siteId", "networkDeviceId"}.
"""

import json
from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client
from fastmcp.exceptions import ToolError

from catc_mcp.server import create_server

from .conftest import make_settings
from .test_read_tools import AREA, BLDG, GLOBAL
from .test_write_tools import mock_sites, run

FLOOR = {
    "id": "aaaaaaaa-0000-0000-0000-000000000003",
    "name": "F1",
    "nameHierarchy": "Global/AU/SYD-1/F1",
    "type": "floor",
}
OTHER_SITE = "aaaaaaaa-0000-0000-0000-0000000000ff"
PROV = "/dna/intent/api/v1/sda/provisionDevices"


def dev(n: int, host: str, family: str = "Switches and Hubs", reach: str = "Reachable") -> dict[str, Any]:
    return {
        "id": f"00000000-0000-0000-0000-00000000000{n}",
        "hostname": f"{host}.example.com",
        "managementIpAddress": f"192.0.2.{n}",
        "family": family,
        "reachabilityStatus": reach,
    }


SW1 = dev(1, "sw1")
SW2 = dev(2, "sw2")
R1 = dev(3, "r1", "Routers")  # already provisioned here
R2 = dev(4, "r2", "Routers")  # provisioned to another site
AP1 = dev(5, "ap1", "Unified AP")
WLC = dev(6, "wlc1", "Wireless Controller")
SW3 = dev(7, "sw3", reach="Unreachable")
DEVICES = [SW1, SW2, R1, R2, AP1, WLC, SW3]
ON_FLOOR = [SW1, AP1]


def mock_site(api: respx.MockRouter, provisioned: list[dict[str, Any]]) -> None:
    """Sites, assignments, inventory and a provisioning list the test can change (`provisioned`)."""
    mock_sites(api, [GLOBAL, AREA, BLDG, FLOOR])

    def assigned(request: httpx.Request) -> httpx.Response:
        site = request.url.params["siteId"]
        s = FLOOR if site == FLOOR["id"] else BLDG
        members = (
            []
            if site == AREA["id"]
            else ON_FLOOR
            if s is FLOOR
            else [d for d in DEVICES if d not in ON_FLOOR]
        )
        rows = [
            {
                "deviceId": d["id"],
                "siteId": s["id"],
                "siteNameHierarchy": s["nameHierarchy"],
                "siteType": s["type"],
            }
            for d in members
        ]
        return httpx.Response(200, json={"response": rows, "version": "1.0"})

    api.get("/dna/intent/api/v1/networkDevices/assignedToSite").mock(side_effect=assigned)

    def inventory(request: httpx.Request) -> httpx.Response:
        ids = set(request.url.params.get("id", "").split(","))
        return httpx.Response(200, json={"response": [d for d in DEVICES if d["id"] in ids]})

    api.get("/dna/intent/api/v1/network-device").mock(side_effect=inventory)

    def records(request: httpx.Request) -> httpx.Response:
        did = request.url.params.get("networkDeviceId")
        rows = [r for r in provisioned if did is None or r["networkDeviceId"] == did]
        return httpx.Response(200, json={"response": rows, "version": "1.0"})

    api.get(PROV).mock(side_effect=records)


def record(d: dict[str, Any], site_id: str) -> dict[str, Any]:
    return {"id": f"prov-{d['id'][-1]}", "siteId": site_id, "networkDeviceId": d["id"]}


def start(provisioned: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [record(R1, BLDG["id"]), record(R2, OTHER_SITE), *provisioned]


async def flow(args: dict[str, Any], apply: bool = True, **settings: Any) -> tuple[Any, Any]:
    s = make_settings(mcp_enable_writes=True, mcp_enable_dangerous=True, **settings)
    async with Client(create_server(s)) as c:
        preview = await run(c, "catc_provision_site", args)
        if preview.get("status") != "preview" or not apply:
            return preview, None
        done = await run(c, "catc_provision_site", {**args, "confirm": preview["confirm"]})
    return preview, done


async def test_provision_site_includes_skips_and_applies(api: respx.MockRouter) -> None:
    provisioned = start([])
    mock_site(api, provisioned)

    def post(request: httpx.Request) -> httpx.Response:
        for item in json.loads(request.content):
            provisioned.append({"id": "new", **item})
        return httpx.Response(202, json={"response": {"taskId": "tp"}})

    route = api.post(PROV).mock(side_effect=post)
    api.get("/dna/intent/api/v1/task/tp").respond(
        json={"response": {"progress": "done", "endTime": 1, "isError": False}}
    )
    preview, done = await flow({"site": "Global/AU/SYD-1"})

    assert preview["status"] == "preview" and preview["blast_radius"] == 2
    included = preview["preview"]["provision"]
    assert included == [
        {"device": "sw1.example.com (192.0.2.1)", "site": FLOOR["nameHierarchy"]},
        {"device": "sw2.example.com (192.0.2.2)", "site": BLDG["nameHierarchy"]},
    ]
    reasons = {r["device"].split(".")[0]: r["reason"] for r in preview["preview"]["skipped"]}
    assert set(reasons) == {"r1", "r2", "ap1", "wlc1", "sw3"}
    assert reasons["r1"].startswith("already provisioned")
    assert reasons["r2"].startswith("provisioned to another site")
    assert (
        reasons["ap1"].startswith("access point") and "catc_provision_wireless_controller" in reasons["wlc1"]
    )
    assert reasons["sw3"].startswith("not reachable (Unreachable)")
    assert route.call_count == 1  # the preview sent nothing; the apply one bulk request

    # Each device goes to the building or floor it is assigned to.
    assert json.loads(route.calls.last.request.content) == [
        {"networkDeviceId": SW1["id"], "siteId": FLOOR["id"]},
        {"networkDeviceId": SW2["id"], "siteId": BLDG["id"]},
    ]
    result = done["result"]
    assert done["status"] == "applied" and (result["provisioned"], result["failed"], result["skipped"]) == (
        2,
        0,
        5,
    )
    assert [r["status"] for r in result["results"]] == ["provisioned", "provisioned"]
    assert "error" not in result and "next" not in result


async def test_provision_site_partial_failure(api: respx.MockRouter) -> None:
    provisioned = start([])
    mock_site(api, provisioned)

    def post(request: httpx.Request) -> httpx.Response:
        provisioned.append({"id": "new", **json.loads(request.content)[0]})  # only sw1 makes it
        return httpx.Response(202, json={"response": {"taskId": "tf"}})

    api.post(PROV).mock(side_effect=post)
    api.get("/dna/intent/api/v1/task/tf").respond(
        json={
            "response": {"endTime": 1, "isError": True, "failureReason": "NCSP10250: sw2 config push failed"}
        }
    )
    _, done = await flow({"site": "Global/AU/SYD-1"})
    result = done["result"]
    assert (result["provisioned"], result["failed"]) == (1, 1)
    assert {r["device"].split(".")[0]: r["status"] for r in result["results"]} == {
        "sw1": "provisioned",
        "sw2": "failed",
    }
    assert "NCSP10250" in result["error"] and "catc_provision_site again" in result["next"]


async def test_provision_site_device_limit(api: respx.MockRouter) -> None:
    mock_site(api, start([]))
    route = api.post(PROV).respond(202, json={"response": {"taskId": "tp"}})
    preview, _ = await flow({"site": "Global/AU/SYD-1"}, max_devices_per_change=1)
    assert preview["status"] == "blocked" and "CATC_MAX_DEVICES_PER_CHANGE=1" in preview["blockers"][0]
    # Skipped devices don't count: the floor alone has one candidate (the AP is skipped).
    preview, _ = await flow({"site": FLOOR["nameHierarchy"]}, apply=False, max_devices_per_change=1)
    assert preview["status"] == "preview" and preview["blast_radius"] == 1
    assert route.call_count == 0


async def test_provision_site_nothing_to_do_and_global(api: respx.MockRouter) -> None:
    mock_site(api, start([record(SW1, FLOOR["id"]), record(SW2, BLDG["id"])]))
    preview, _ = await flow({"site": "Global/AU/SYD-1"})
    assert preview["status"] == "blocked" and "Nothing to provision" in preview["blockers"][-1]
    s = make_settings(mcp_enable_writes=True, mcp_enable_dangerous=True)
    async with Client(create_server(s)) as c:
        with pytest.raises(ToolError, match="not Global"):
            await c.call_tool("catc_provision_site", {"site": "Global"})


async def test_provision_site_no_wait(api: respx.MockRouter) -> None:
    mock_site(api, start([]))
    api.post(PROV).respond(202, json={"response": {"taskId": "tp"}})
    _, done = await flow({"site": "Global/AU/SYD-1", "wait": False})
    assert done["result"]["devices"] == ["sw1.example.com (192.0.2.1)", "sw2.example.com (192.0.2.2)"]
    assert "catc_get_task" in done["result"]["check_with"]
