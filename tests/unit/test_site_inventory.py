"""D61: catc_site_inventory (respx). Payloads follow the 3.2.2 lab appliance's live shapes (2026-10-29):
membership with one `device` entry per site in the subtree (devices carry instanceUuid), notAssignedToSite
as {"response": {"siteId": null, "deviceIds": [...]}}, site-topology as the whole site tree, physical-topology
nodes keyed by network device id. Addresses are documentation ranges."""

from typing import Any

import httpx
import pytest
import respx
from fastmcp.exceptions import ToolError

from catc_mcp.tools.site_inventory import speed_text

from .test_read_tools import call

BLDG_ID = "bbbbbbbb-0000-0000-0000-000000000001"
FLOOR_ID = "bbbbbbbb-0000-0000-0000-000000000002"
EMPTY_ID = "bbbbbbbb-0000-0000-0000-000000000003"
OTHER_ID = "bbbbbbbb-0000-0000-0000-000000000004"
BLDG = {"id": BLDG_ID, "name": "SYD-1", "nameHierarchy": "Global/AU/SYD-1", "type": "building"}
EMPTY = {"id": EMPTY_ID, "name": "SYD-2", "nameHierarchy": "Global/AU/SYD-2", "type": "building"}
EDGE1 = "dddddddd-0000-0000-0000-000000000001"
BCP = "dddddddd-0000-0000-0000-000000000002"
CORE = "dddddddd-0000-0000-0000-000000000009"  # outside the site
LOOSE = "dddddddd-0000-0000-0000-00000000000a"  # not assigned to any site
LOOSE2 = "dddddddd-0000-0000-0000-00000000000b"  # not assigned, gone from the lookup

MEMBERSHIP = "/dna/intent/api/v1/membership"
NOT_ASSIGNED = "/dna/intent/api/v1/networkDevices/notAssignedToSite"
SITE_TOPO = "/dna/intent/api/v1/topology/site-topology"
PHYSICAL = "/dna/intent/api/v1/topology/physical-topology"


def dev(uid: str, host: str, ip: str, role: str, **kw: Any) -> dict[str, Any]:
    d = {
        "instanceUuid": uid,
        "hostname": host,
        "managementIpAddress": ip,
        "family": "Switches and Hubs",
        "role": role,
        "platformId": "C9KV-UADP-8P",
        "softwareVersion": "17.18.2",
        "reachabilityStatus": "Reachable",
        "serialNumber": f"SN{uid[-4:]}",
        "series": "Cisco Catalyst 9000 Series Virtual Switches",
    }
    d.update(kw)
    return d


def site_record(sid: str, parent: str, path: str, kind: str) -> dict[str, Any]:
    return {
        "id": sid,
        "parentId": parent,
        "name": path.rsplit("/", 1)[1],
        "groupNameHierarchy": path,
        "additionalInfo": [
            {"nameSpace": "Location", "attributes": {"type": kind}},
            {"nameSpace": "System Settings", "attributes": {"member.count.total": "2"}},
        ],
    }


EMPTY_MSG = "Site doesn’t not have device member with given device family or serial number as input"


def mock_common(api: respx.MockRouter, unassigned: list[str] | None = None) -> None:
    def sites(request: httpx.Request) -> httpx.Response:
        q = request.url.params
        if q.get("nameHierarchy") == "Global/AU/SYD-1" or q.get("name") == "SYD-1":
            return httpx.Response(200, json={"response": [BLDG]})
        if q.get("nameHierarchy") == "Global/AU/SYD-2":
            return httpx.Response(200, json={"response": [EMPTY]})
        return httpx.Response(200, json={"response": []})

    api.get("/dna/intent/api/v1/sites").mock(side_effect=sites)
    api.get(SITE_TOPO).respond(
        json={
            "response": {
                "sites": [
                    {
                        "id": BLDG_ID,
                        "name": "SYD-1",
                        "parentId": "a",
                        "locationType": "building",
                        "locationAddress": "1 Example St",
                        "groupNameHierarchy": "Global/AU/SYD-1",
                    },
                    {
                        "id": FLOOR_ID,
                        "name": "Floor 1",
                        "parentId": BLDG_ID,
                        "locationType": "floor",
                        "locationAddress": "1 Example St",
                        "groupNameHierarchy": "Global/AU/SYD-1/Floor 1",
                    },
                    {
                        "id": OTHER_ID,
                        "name": "SYD-10",
                        "parentId": "a",
                        "locationType": "building",
                        "groupNameHierarchy": "Global/AU/SYD-10",
                    },
                    {
                        "id": EMPTY_ID,
                        "name": "SYD-2",
                        "parentId": "a",
                        "locationType": "building",
                        "groupNameHierarchy": "Global/AU/SYD-2",
                    },
                ]
            },
            "version": "1.0",
        }
    )
    ids = [LOOSE, LOOSE2] if unassigned is None else unassigned
    api.get(NOT_ASSIGNED).respond(json={"response": {"siteId": None, "deviceIds": ids}, "version": "1.0"})
    api.get(f"{NOT_ASSIGNED}/count").respond(json={"response": {"count": len(ids)}, "version": "1.0"})

    def lookup(request: httpx.Request) -> httpx.Response:
        wanted = set((request.url.params.get("id") or "").split(","))
        out = []
        if LOOSE in wanted:
            out.append(
                {
                    "id": LOOSE,
                    "hostname": "new-sw1.example.com",
                    "managementIpAddress": "192.0.2.50",
                    "family": "Switches and Hubs",
                    "role": "ACCESS",
                }
            )
        return httpx.Response(200, json={"response": out})

    api.get("/dna/intent/api/v1/network-device").mock(side_effect=lookup)
    api.get(PHYSICAL).respond(
        json={
            "response": {
                "nodes": [
                    {"id": EDGE1, "label": "edge1.example.com", "ip": "192.0.2.11", "nodeType": "device"},
                    {"id": BCP, "label": "bcp1.example.com", "ip": "192.0.2.10", "nodeType": "device"},
                    {
                        "id": CORE,
                        "label": "core1.example.com",
                        "ip": "198.51.100.1",
                        "role": "CORE",
                        "nodeType": "device",
                    },
                ],
                "links": [
                    {
                        "source": BCP,
                        "target": EDGE1,
                        "startPortName": "GigabitEthernet1/0/2",
                        "endPortName": "GigabitEthernet1/0/1",
                        "linkStatus": "up",
                        "startPortSpeed": "1000000",
                    },
                    # the same link reported from the other end
                    {
                        "source": EDGE1,
                        "target": BCP,
                        "startPortName": "GigabitEthernet1/0/1",
                        "endPortName": "GigabitEthernet1/0/2",
                        "linkStatus": "up",
                    },
                    {
                        "source": CORE,
                        "target": BCP,
                        "startPortName": "TenGigabitEthernet1/1/1",
                        "endPortName": "GigabitEthernet1/0/8",
                        "linkStatus": "down",
                    },
                ],
            }
        }
    )


def mock_floor_only(api: respx.MockRouter) -> None:
    """A building whose devices are all on its floor (the building itself holds none)."""
    mock_common(api)
    api.get(f"{MEMBERSHIP}/{BLDG_ID}").respond(
        json={
            "site": {
                "response": [site_record(FLOOR_ID, BLDG_ID, "Global/AU/SYD-1/Floor 1", "floor")],
                "version": "1.0",
            },
            "device": [
                {"response": [], "version": "1.0", "siteId": BLDG_ID, "message": EMPTY_MSG},
                {
                    "response": [
                        dev(EDGE1, "edge1.example.com", "192.0.2.11", "ACCESS"),
                        dev(BCP, "bcp1.example.com", "192.0.2.10", "BORDER ROUTER"),
                    ],
                    "version": "1.0",
                    "siteId": FLOOR_ID,
                },
            ],
        }
    )


async def test_floor_only_building(api: respx.MockRouter) -> None:
    mock_floor_only(api)
    out = await call("catc_site_inventory", {"site": "Global/AU/SYD-1", "format": "json"})
    assert out["site"]["name"] == "Global/AU/SYD-1"
    assert out["site"]["devices_here"] == 0
    # the child floor only: no sibling SYD-10 though its path shares the prefix
    assert [s["name"] for s in out["sites"]] == ["Global/AU/SYD-1/Floor 1"]
    assert out["sites"][0]["type"] == "floor" and out["sites"][0]["devices"] == 2
    assert out["members"]["device_count"] == 2
    assert out["members"]["by_family"] == {"Switches and Hubs": 2}
    assert out["members"]["by_role"] == {"BORDER ROUTER": 1, "ACCESS": 1}
    hosts = {d["hostname"]: d for d in out["devices"]}
    assert hosts["edge1.example.com"]["site"] == "Global/AU/SYD-1/Floor 1"
    assert hosts["edge1.example.com"]["id"] == EDGE1
    assert hosts["bcp1.example.com"]["ip"] == "192.0.2.10"
    # one internal link (deduplicated), one uplink to the core outside the site
    internal, uplinks = out["physical_links"]["internal"], out["physical_links"]["uplinks"]
    assert len(internal) == 1 and internal[0]["status"] == "up"
    assert {internal[0]["a"], internal[0]["b"]} == {"edge1.example.com", "bcp1.example.com"}
    assert uplinks == [
        {
            "a": "bcp1.example.com",
            "a_port": "GigabitEthernet1/0/8",
            "b": "core1.example.com",
            "b_port": "TenGigabitEthernet1/1/1",
            "status": "down",
        }
    ]
    un = out["unassigned"]
    assert un["count"] == 2
    assert {"id": LOOSE2} in un["devices"]
    assert any(d.get("hostname") == "new-sw1.example.com" for d in un["devices"])
    assert "unavailable" not in out


async def test_markdown_and_mermaid(api: respx.MockRouter) -> None:
    mock_floor_only(api)
    md = await call("catc_site_inventory", {"site": "SYD-1"})
    assert "Site inventory: Global/AU/SYD-1 (building)" in md
    assert "Devices: 2" in md and "Uplinks to devices outside the site: 1" in md
    assert "Devices not assigned to any site: 2" in md
    mer = await call(
        "catc_site_inventory", {"site": "SYD-1", "format": "mermaid", "include_unassigned": False}
    )
    assert mer.startswith("```mermaid")
    assert "edge1.example.com" in mer and "BORDER ROUTER" in mer and "192.0.2.10" in mer
    assert "SYD-1/Floor 1" in mer and "outside the site" in mer
    assert "Gi1/0/2 - Gi1/0/1 1G" in mer
    drawio = await call("catc_site_inventory", {"site": "SYD-1", "format": "drawio", "include_links": False})
    assert drawio.startswith("<mxfile") and "bcp1.example.com" in drawio
    assert "core1.example.com" not in drawio


async def test_empty_site(api: respx.MockRouter) -> None:
    mock_common(api, unassigned=[])
    api.get(f"{MEMBERSHIP}/{EMPTY_ID}").respond(
        json={
            "site": {"response": [], "version": "1.0"},
            "device": [{"response": [], "version": "1.0", "siteId": EMPTY_ID, "message": EMPTY_MSG}],
        }
    )
    out = await call("catc_site_inventory", {"site": "Global/AU/SYD-2", "format": "json"})
    assert out["members"]["device_count"] == 0
    assert not out.get("sites")  # empty lists are left out of the json
    assert "physical_links" not in out
    assert out["unassigned"]["count"] == 0
    assert any("No devices are assigned" in n for n in out["notes"])
    mer = await call("catc_site_inventory", {"site": "Global/AU/SYD-2", "format": "mermaid"})
    assert "No devices are assigned" in mer


async def test_unknown_site(api: respx.MockRouter) -> None:
    mock_common(api)
    with pytest.raises(ToolError, match="No site"):
        await call("catc_site_inventory", {"site": "Global/AU/NOPE"})


async def test_section_failure_is_reported(api: respx.MockRouter) -> None:
    mock_floor_only(api)
    api.get(PHYSICAL).respond(status_code=500, json={"error": "boom"})
    out = await call("catc_site_inventory", {"site": "SYD-1", "format": "json"})
    assert out["members"]["device_count"] == 2
    assert "physical" in out["unavailable"] and "physical_links" not in out


def test_speed_text() -> None:
    assert speed_text("1000000") == "1G"
    assert speed_text("100000") == "100M"
    assert speed_text(None) == ""
    assert speed_text("auto") == "auto"
