"""D119: catc_link_mismatch over the Inventory Insight device-link endpoint (respx). The VLAN row is the
shape the 3.2.2 lab appliance returned live (2026-10-28: allowed VLANs 'none' on one end, 'ALL' on the
other; ids and addresses replaced); the speed/duplex row follows the spec's response schema."""

from typing import Any

import httpx
import respx

from catc_mcp.tools.link_insight import fmt_speed

from .test_read_tools import AREA, BLDG, GLOBAL, call
from .test_write_tools import mock_sites

PATH = f"/dna/intent/api/v1/network-device/insight/{BLDG['id']}/device-link"
ASSIGNED = "/dna/intent/api/v1/networkDevices/assignedToSite"


def link(**kw: Any) -> dict[str, Any]:
    row: dict[str, Any] = {
        "startDeviceHostName": "sw-a.example.com",
        "startDeviceIpAddress": "192.0.2.11",
        "startDeviceId": "dev-a",
        "startPortName": "GigabitEthernet1/0/5",
        "startPortSpeed": "1000000",
        "startPortDuplex": "FullDuplex",
        "startPortNativeVlanId": "1",
        "startPortAllowedVlanIds": "none",
        "endDeviceHostName": "sw-b.example.com",
        "endDeviceIpAddress": "192.0.2.12",
        "endDeviceId": "dev-b",
        "endPortName": "GigabitEthernet1/0/5",
        "endPortSpeed": "1000000",
        "endPortDuplex": "FullDuplex",
        "endPortNativeVlanId": "1",
        "endPortAllowedVlanIds": "ALL",
        "endPortAddress": None,
        "linkStatus": "up",
        "lastUpdated": "",
        "type": "physical",
        "id": "link-1",
    }
    row.update(kw)
    return row


def mock_insight(api: respx.MockRouter, rows: dict[str, list[dict[str, Any]]]) -> respx.Route:
    def handler(request: httpx.Request) -> httpx.Response:
        q = request.url.params
        assert q["offset"] == "1"  # 1-based
        return httpx.Response(200, json={"response": rows.get(q["category"], []), "version": "1.0"})

    return api.get(PATH).mock(side_effect=handler)


def test_fmt_speed() -> None:
    assert fmt_speed("1000000") == "1 Gbps"
    assert fmt_speed("100000") == "100 Mbps"
    assert fmt_speed("auto") == "auto"
    assert fmt_speed(None) is None


async def test_vlan_mismatch_names_both_ends(api: respx.MockRouter) -> None:
    mock_sites(api, [GLOBAL, AREA, BLDG])
    route = mock_insight(api, {"vlan": [link()]})
    out = await call("catc_link_mismatch", {"site": "Global/AU/SYD-1", "category": "vlan"})
    assert route.call_count == 1 and route.calls[0].request.url.params["category"] == "vlan"
    assert out["site"] == "Global/AU/SYD-1" and out["count"] == 1
    m = out["mismatches"][0]
    assert m["a"]["device"] == "sw-a.example.com" and m["b"]["device"] == "sw-b.example.com"
    assert m["a"]["allowed_vlans"] == "none" and m["b"]["allowed_vlans"] == "ALL"
    assert m["mismatch"] == ["allowed_vlans"] and "not a trunk" in m["fix"]
    assert out["findings"] == [
        "sw-a.example.com GigabitEthernet1/0/5 <-> sw-b.example.com GigabitEthernet1/0/5: "
        "allowed_vlans none vs ALL"
    ]
    assert "note" not in out  # mismatches found: no collection caveat needed


async def test_both_merges_two_calls(api: respx.MockRouter) -> None:
    mock_sites(api, [GLOBAL, AREA, BLDG])
    native = link(startPortAllowedVlanIds="ALL", endPortNativeVlanId="20", startPortName="Gi1/0/1")
    speed = link(endPortSpeed="100000", endPortDuplex="HalfDuplex", startPortName="Gi1/0/2")
    route = mock_insight(api, {"vlan": [native], "speed-duplex": [speed]})
    out = await call("catc_link_mismatch", {"site": "Global/AU/SYD-1"})
    assert route.call_count == 2
    assert {c.request.url.params["category"] for c in route.calls} == {"vlan", "speed-duplex"}
    assert out["categories"] == ["speed-duplex", "vlan"] and out["count"] == 2
    by_cat = {m["category"]: m for m in out["mismatches"]}
    assert by_cat["vlan"]["mismatch"] == ["native_vlan"] and "native vlan" in by_cat["vlan"]["fix"]
    sd = by_cat["speed-duplex"]
    assert sd["mismatch"] == ["speed", "duplex"]
    assert (
        sd["a"]["speed"] == "1 Gbps" and sd["b"]["speed"] == "100 Mbps" and sd["b"]["duplex"] == "HalfDuplex"
    )
    assert "late collisions" in sd["fix"]
    # sorted by the A end's device then interface
    assert [m["a"]["interface"] for m in out["mismatches"]] == ["Gi1/0/1", "Gi1/0/2"]


async def test_empty_never_claims_clean(api: respx.MockRouter) -> None:
    mock_sites(api, [GLOBAL, AREA, BLDG])
    mock_insight(api, {})
    api.get(ASSIGNED).respond(json={"response": [{"deviceId": "dev-a"}, {"deviceId": "dev-b"}]})
    api.get("/dna/intent/api/v1/network-device").respond(
        json={
            "response": [
                {
                    "id": "dev-a",
                    "hostname": "sw-a",
                    "collectionStatus": "Managed",
                    "reachabilityStatus": "Reachable",
                },
                {
                    "id": "dev-b",
                    "hostname": "sw-b",
                    "collectionStatus": "Partial Collection Failure",
                    "reachabilityStatus": "Reachable",
                },
            ]
        }
    )
    out = await call("catc_link_mismatch", {"site": "Global/AU/SYD-1", "category": "speed-duplex"})
    assert out["count"] == 0 and out["mismatches"] == []
    assert out["note"].startswith("No mismatches found by Catalyst Center (1 of 2 devices")
    assert "not compared" in out["note"]
    assert out["collection"]["devices_not_collected"][0]["device"] == "sw-b"


async def test_empty_all_collected(api: respx.MockRouter) -> None:
    mock_sites(api, [GLOBAL, AREA, BLDG])
    mock_insight(api, {})
    api.get(ASSIGNED).respond(json={"response": [{"deviceId": "dev-a"}]})
    api.get("/dna/intent/api/v1/network-device").respond(
        json={"response": [{"id": "dev-a", "collectionStatus": "Managed", "reachabilityStatus": "Reachable"}]}
    )
    out = await call("catc_link_mismatch", {"site": "Global/AU/SYD-1", "category": "vlan"})
    assert "0 of 1 devices" in out["note"] and "not compared" not in out["note"]
