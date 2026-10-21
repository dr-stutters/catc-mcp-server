"""D47: catc_find_host (mac / ip / hostname / user, live search) and catc_list_clients(user=).

Rows and CLI output are the 3.2.2 shapes recorded live on 2026-10-21 (lab mcp-cml-ise: the Ubuntu
EAP-TLS client `mcp-eaptls-client` on sw1 Gi1/0/3, the Alpine MAB client on Gi1/0/2)."""

import json
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx
from fastmcp.exceptions import ToolError

from catc_mcp.tools.smart import dotted, live_hits

from .test_read_tools import call

FIX = json.loads((Path(__file__).parent.parent / "fixtures" / "clients_find_host_322.json").read_text())
EAPTLS: dict[str, Any] = FIX["eaptls_client"]
MAB: dict[str, Any] = FIX["mab_client"]
CLI: dict[str, str] = FIX["cli"]
SW1_ID = EAPTLS["connectedNetworkDevice"]["connectedNetworkDeviceId"]
SW1 = {
    "id": SW1_ID,
    "hostname": "mcp-sw1.mcp.lab",
    "managementIpAddress": "198.18.128.154",
    "family": "Switches and Hubs",
    "role": "ACCESS",
}
QUERY = "/dna/data/api/v1/clients/query"
BAD_KEY = (
    "Filter key is missing or has invalid value. Valid values are: 'macAddress', 'type', 'name', "
    "'ipv4Address'"
)


def mock_sw1(api: respx.MockRouter) -> None:
    def by_query(request: httpx.Request) -> httpx.Response:
        q = request.url.params
        hit = (
            q.get("id") == SW1_ID
            or q.get("managementIpAddress") == "198.18.128.154"
            or q.get("hostname") in ("mcp-sw1", "mcp-sw1.*", "mcp-sw1.mcp.lab")
        )
        return httpx.Response(200, json={"response": [SW1] if hit else []})

    api.get("/dna/intent/api/v1/network-device").mock(side_effect=by_query)


def mock_runner(api: respx.MockRouter, outputs: list[dict[str, str]]) -> respx.Route:
    """Command runner jobs answered in order with these {command: output} maps."""
    jobs = iter(range(len(outputs)))
    route = api.post("/dna/intent/api/v1/network-device-poller/cli/read-request").mock(
        side_effect=lambda req: httpx.Response(202, json={"response": {"taskId": f"t-{next(jobs)}"}})
    )
    for n, out in enumerate(outputs):
        api.get(f"/dna/intent/api/v1/task/t-{n}").respond(
            json={"response": {"progress": json.dumps({"fileId": f"f-{n}"}), "endTime": 1}}
        )
        api.get(f"/dna/intent/api/v1/file/f-{n}").respond(
            json=[
                {"deviceUuid": SW1_ID, "commandResponses": {"SUCCESS": out, "FAILURE": {}, "BLACKLISTED": {}}}
            ]
        )
    return route


# --- pure helpers ------------------------------------------------------------------------------


def test_live_hits_parse_recorded_output() -> None:
    mac = "show mac address-table address 5254.0062.c6b2"
    trk = "show device-tracking database mac 5254.0062.c6b2"
    arp = "show ip arp 10.10.10.50"
    hits = live_hits("mcp-sw1", {mac: CLI[mac], trk: CLI[trk], arp: CLI[arp]})
    assert {"device": "mcp-sw1", "vlan": "10", "mac": "52:54:00:62:c6:b2", "type": "static",
            "port": "Gi1/0/3", "source": mac} in hits  # fmt: skip
    assert {"device": "mcp-sw1", "ip": "FE80::5054:FF:FE62:C6B2", "mac": "52:54:00:62:c6:b2",
            "port": "Gi1/0/3", "vlan": "10", "source": trk} in hits  # fmt: skip
    assert {"device": "mcp-sw1", "ip": "10.10.10.50", "mac": "52:54:00:62:c6:b2", "interface": "Vlan10",
            "source": arp} in hits  # fmt: skip
    # Headers, legends and an empty binding table yield nothing.
    empty = "show device-tracking database address 10.10.10.50"
    assert live_hits("mcp-sw1", {empty: CLI[empty]}) == []
    full = live_hits("mcp-sw1", {"show device-tracking database": CLI["show device-tracking database"]})
    assert [(h["ip"], h["port"]) for h in full] == [
        ("10.10.10.100", "Gi1/0/2"),
        ("FE80::5054:FF:FE62:C6B2", "Gi1/0/3"),
        ("FE80::5054:FF:FE61:3D9E", "Gi1/0/2"),
    ]


def test_dotted_mac() -> None:
    assert dotted("52:54:00:62:C6:B2") == "5254.0062.c6b2"


# --- catc_find_host ----------------------------------------------------------------------------


async def test_find_host_by_user(api: respx.MockRouter) -> None:
    mock_sw1(api)
    route = api.post(QUERY).respond(json={"response": [EAPTLS, MAB], "page": {"count": 2}})
    out = await call("catc_find_host", {"user": "MCP-EAPTLS-CLIENT"})
    body = json.loads(route.calls.last.request.content)
    # `like` without a wildcard is an exact, case-insensitive match on 3.2.2.
    assert body["filters"] == [{"key": "username", "operator": "like", "value": "MCP-EAPTLS-CLIENT"}]
    assert body["page"]["sortBy"] == [{"name": "lastUpdatedTime", "order": "desc"}]
    assert out["user_match"] == "username filter (clients/query)"
    assert out["found"] == 1  # the MAB row (username = its own MAC) is not a login name
    host = out["hosts"][0]
    assert host["mac"] == "52:54:00:62:C6:B2" and host["user"] == "mcp-eaptls-client"
    assert (host["device"], host["device_ip"], host["port"], host["vlan"]) == (
        "mcp-sw1",
        "198.18.128.154",
        "GigabitEthernet1/0/3",
        "10",
    )
    assert host["sgt"] == "7" and host["aaa_server"] == "198.18.134.35"
    assert "device_id" not in host and "device_in_inventory" not in host
    assert out["where"] == (
        "mcp-sw1 (198.18.128.154) GigabitEthernet1/0/3, VLAN 10, Global/mcp-test-lab/mcp-test-nac"
    )


async def test_find_host_user_falls_back_when_the_key_is_rejected(api: respx.MockRouter) -> None:
    mock_sw1(api)
    api.post(QUERY).respond(400, json={"response": {"errorCode": 400, "message": BAD_KEY}})
    scan = api.get("/dna/data/api/v1/clients").respond(json={"response": [MAB, EAPTLS], "page": {"count": 2}})
    out = await call("catc_find_host", {"user": "mcp-eaptls*"})
    assert scan.called
    assert out["user_match"].startswith("matched client-side")
    assert [h["mac"] for h in out["hosts"]] == ["52:54:00:62:C6:B2"]


async def test_find_host_by_mac_marks_a_deleted_switch(api: respx.MockRouter) -> None:
    api.get("/dna/intent/api/v1/network-device").respond(json={"response": []})  # sw1 no longer managed
    route = api.get("/dna/data/api/v1/clients").respond(json={"response": [EAPTLS]})
    out = await call("catc_find_host", {"mac": "5254.0062.c6b2"})
    assert route.calls.last.request.url.params["macAddress"] == "52:54:00:62:c6:b2"
    assert out["hosts"][0]["device_in_inventory"] is False


async def test_find_host_by_ip_live_when_assurance_has_none(api: respx.MockRouter) -> None:
    """The live case of 2026-10-21: Assurance had lost the client's IPv4 (device-tracking kept only
    its IPv6 link-local), ARP still had it on Vlan10, and the MAC table gave the port."""
    mock_sw1(api)
    api.get("/dna/data/api/v1/clients").respond(json={"response": []})
    trk, arp = "show device-tracking database address 10.10.10.50", "show ip arp 10.10.10.50"
    mac = "show mac address-table address 5254.0062.c6b2"
    runner = mock_runner(api, [{trk: CLI[trk], arp: CLI[arp]}, {mac: CLI[mac]}])
    out = await call("catc_find_host", {"ip": "10.10.10.50", "search_devices": ["198.18.128.154"]})
    first = json.loads(runner.calls[0].request.content)
    second = json.loads(runner.calls[1].request.content)
    assert first["commands"] == [trk, arp] and first["deviceUuids"] == [SW1_ID]
    assert second["commands"] == [mac]
    assert out["found"] == 0
    assert out["where"] == "mcp-sw1.mcp.lab Gi1/0/3, VLAN 10 (live; not in Assurance)"
    assert {h["source"] for h in out["live"]} == {arp, mac}


async def test_find_host_user_then_live_by_its_mac(api: respx.MockRouter) -> None:
    mock_sw1(api)
    api.post(QUERY).respond(json={"response": [EAPTLS]})
    mac, trk = (
        "show mac address-table address 5254.0062.c6b2",
        "show device-tracking database mac 5254.0062.c6b2",
    )
    runner = mock_runner(api, [{mac: CLI[mac], trk: CLI[trk]}])
    out = await call("catc_find_host", {"user": "mcp-eaptls-client", "search_devices": ["mcp-sw1"]})
    assert json.loads(runner.calls[0].request.content)["commands"] == [mac, trk]
    assert runner.call_count == 1  # the MAC table already named the port
    assert {(h["port"], h["vlan"]) for h in out["live"]} == {("Gi1/0/3", "10")}


async def test_find_host_hostname_of_a_network_device(api: respx.MockRouter) -> None:
    mock_sw1(api)
    route = api.post(QUERY).respond(json={"response": []})
    out = await call("catc_find_host", {"hostname": "mcp-sw1"})
    assert json.loads(route.calls.last.request.content)["filters"][0]["key"] == "name"
    assert out["network_device"]["managementIpAddress"] == "198.18.128.154"
    assert "catc_device_360" in out["note"]


async def test_find_host_nothing_found_says_what_next(api: respx.MockRouter) -> None:
    api.get("/dna/data/api/v1/clients").respond(json={"response": []})
    out = await call("catc_find_host", {"mac": "00:11:22:33:44:55", "hours": 4})
    assert out["found"] == 0 and not out.get("hosts")
    assert any("search_devices" in s for s in out["next_steps"])
    assert any("ise_why_auth_failed" in s for s in out["next_steps"])


@pytest.mark.parametrize(
    "args",
    [{}, {"mac": "00:11:22:33:44:55", "user": "x"}, {"ip": "fe80::1"}, {"user": "*"}, {"mac": "nope"}],
)
async def test_find_host_refuses_bad_arguments(api: respx.MockRouter, args: dict[str, Any]) -> None:
    with pytest.raises(ToolError):
        await call("catc_find_host", args)


async def test_find_host_caps_search_devices(api: respx.MockRouter) -> None:
    with pytest.raises(ToolError, match="At most 10"):
        await call(
            "catc_find_host", {"mac": "00:11:22:33:44:55", "search_devices": [f"s{i}" for i in range(11)]}
        )


# --- catc_list_clients(user=) ------------------------------------------------------------------


async def test_list_clients_by_user_partial_with_filters(api: respx.MockRouter) -> None:
    mock_sw1(api)
    other = {
        **EAPTLS,
        "macAddress": "52:54:00:00:00:01",
        "username": "mcp-eaptls-other",
        "connectionStatus": "connected",  # the recorded row is 'disconnected'
        "connectedNetworkDevice": {
            **EAPTLS["connectedNetworkDevice"],
            "connectedNetworkDeviceName": "edge-sw9",
        },
    }
    route = api.post(QUERY).respond(json={"response": [EAPTLS, other, MAB]})
    out = await call("catc_list_clients", {"user": "eaptls", "response_format": "json"})
    assert json.loads(route.calls.last.request.content)["filters"][0]["value"] == "*eaptls*"
    assert [r["user"] for r in out["results"]] == ["mcp-eaptls-client", "mcp-eaptls-other"]
    assert out["user_match"] == "username filter (clients/query)"
    # The GET filters apply to the query rows; the short device name matches Assurance's FQDN or not.
    out = await call("catc_list_clients", {"user": "eaptls", "device": "mcp-sw1", "response_format": "json"})
    assert [r["mac"] for r in out["results"]] == ["52:54:00:62:C6:B2"]
    out = await call(
        "catc_list_clients", {"user": "eaptls", "connected_only": True, "response_format": "json"}
    )
    assert [r["mac"] for r in out["results"]] == ["52:54:00:00:00:01"]
    out = await call(
        "catc_list_clients", {"user": "eaptls", "mac": "52:54:00:00*", "response_format": "json"}
    )
    assert [r["mac"] for r in out["results"]] == ["52:54:00:00:00:01"]


async def test_list_clients_by_user_pages_the_query(api: respx.MockRouter) -> None:
    rows = [{**EAPTLS, "macAddress": f"52:54:00:00:{i // 256:02x}:{i % 256:02x}"} for i in range(150)]
    seen: list[int] = []

    def page(request: httpx.Request) -> httpx.Response:
        p = json.loads(request.content)["page"]
        seen.append(p["offset"])
        return httpx.Response(200, json={"response": rows[p["offset"] - 1 : p["offset"] - 1 + p["limit"]]})

    api.post(QUERY).mock(side_effect=page)
    out = await call("catc_list_clients", {"user": "mcp-*", "limit": 10, "response_format": "json"})
    assert seen == [1, 101]
    assert out["total"] == 150 and out["returned"] == 10
