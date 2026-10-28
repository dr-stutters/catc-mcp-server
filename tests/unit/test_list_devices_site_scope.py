"""#264: catc_list_devices(site=<building>) includes the devices on the building's floors (mocked).

Payload shape recorded from Catalyst Center 3.2.2 (2026-10-28): `networkDevices/assignedToSite` lists only the
site's own devices ({"deviceId", "siteId", "siteNameHierarchy", "siteType"}); the 3.2.2 spec has no child-site
option, so each child site is read. The normal layout puts every switch on a floor, none on the building.
"""

from typing import Any

import httpx
import respx

from .test_read_tools import AREA, BLDG, GLOBAL, call
from .test_write_tools import mock_sites

ASSIGNED = "/dna/intent/api/v1/networkDevices/assignedToSite"
F1 = {
    "id": "aaaaaaaa-0000-0000-0000-000000000003",
    "name": "F1",
    "nameHierarchy": "Global/AU/SYD-1/F1",
    "type": "floor",
}
F2 = {
    "id": "aaaaaaaa-0000-0000-0000-000000000004",
    "name": "F2",
    "nameHierarchy": "Global/AU/SYD-1/F2",
    "type": "floor",
}
# A sibling building whose name starts with the reviewed one's: never part of its scope.
SIBLING = {
    "id": "aaaaaaaa-0000-0000-0000-000000000005",
    "name": "SYD-10",
    "nameHierarchy": "Global/AU/SYD-10",
    "type": "building",
}


def dev(n: int, host: str, role: str = "ACCESS") -> dict[str, Any]:
    return {
        "id": f"00000000-0000-0000-0000-00000000000{n}",
        "hostname": f"{host}.example.com",
        "managementIpAddress": f"192.0.2.{n}",
        "family": "Switches and Hubs",
        "role": role,
        "reachabilityStatus": "Reachable",
    }


BORDER = dev(1, "border1", "BORDER ROUTER")
EDGE1 = dev(2, "edge1")
EDGE2 = dev(3, "edge2")
OTHER = dev(4, "other1")
DEVICES = [BORDER, EDGE1, EDGE2, OTHER]
MEMBERS = {F1["id"]: (F1, [BORDER, EDGE1]), F2["id"]: (F2, [EDGE2]), SIBLING["id"]: (SIBLING, [OTHER])}


def mock_floors(api: respx.MockRouter) -> respx.Route:
    mock_sites(api, [GLOBAL, AREA, BLDG, F1, F2, SIBLING])

    def assigned(request: httpx.Request) -> httpx.Response:
        site, members = MEMBERS.get(request.url.params["siteId"], (None, []))
        rows = [
            {
                "deviceId": d["id"],
                "siteId": site["id"],
                "siteNameHierarchy": site["nameHierarchy"],
                "siteType": site["type"],
            }
            for d in members
            if site
        ]
        return httpx.Response(200, json={"response": rows, "version": "1.0"})

    route = api.get(ASSIGNED).mock(side_effect=assigned)

    def inventory(request: httpx.Request) -> httpx.Response:
        ids = set(request.url.params.get("id", "").split(","))
        return httpx.Response(200, json={"response": [d for d in DEVICES if d["id"] in ids]})

    api.get("/dna/intent/api/v1/network-device").mock(side_effect=inventory)
    return route


async def test_building_includes_floor_devices(api: respx.MockRouter) -> None:
    route = mock_floors(api)
    out = await call("catc_list_devices", {"site": "Global/AU/SYD-1", "response_format": "json"})
    assert out["total"] == 3 and out["includes_child_sites"] is True
    rows = {r["hostname"]: r["site"] for r in out["results"]}
    assert rows == {
        "border1.example.com": "Global/AU/SYD-1/F1",
        "edge1.example.com": "Global/AU/SYD-1/F1",
        "edge2.example.com": "Global/AU/SYD-1/F2",
    }
    # The building and both floors were read; the sibling SYD-10 never was.
    read = {c.request.url.params["siteId"] for c in route.calls}
    assert read == {BLDG["id"], F1["id"], F2["id"]}
    # Filters still apply to the child-site devices.
    out = await call(
        "catc_list_devices", {"site": "Global/AU/SYD-1", "role": "BORDER ROUTER", "response_format": "json"}
    )
    assert [r["hostname"] for r in out["results"]] == ["border1.example.com"]


async def test_area_includes_buildings_and_floors(api: respx.MockRouter) -> None:
    mock_floors(api)
    out = await call("catc_list_devices", {"site": "Global/AU", "response_format": "json"})
    assert out["total"] == 4


async def test_exact_site_only_opt_out(api: respx.MockRouter) -> None:
    route = mock_floors(api)
    out = await call(
        "catc_list_devices",
        {"site": "Global/AU/SYD-1", "include_children": False, "response_format": "json"},
    )
    assert out["total"] == 0 and "includes_child_sites" not in out
    assert {c.request.url.params["siteId"] for c in route.calls} == {BLDG["id"]}
    out = await call(
        "catc_list_devices",
        {"site": "Global/AU/SYD-1/F2", "include_children": False, "response_format": "json"},
    )
    assert [(r["hostname"], r["site"]) for r in out["results"]] == [
        ("edge2.example.com", "Global/AU/SYD-1/F2")
    ]
