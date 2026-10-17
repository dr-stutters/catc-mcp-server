"""Operator-eyes pass (D25/D26): ghost devices in Assurance, issue rows that name their device,
grouped repeats, and template deploys that only target applicable device families."""

import time
from typing import Any

import httpx
import respx
from fastmcp import Client

from catc_mcp.server import create_server
from catc_mcp.tools.assurance import group_issues, issue_row
from catc_mcp.tools.dangerous import split_applicable, template_families

from .conftest import make_settings
from .test_read_tools import DEV_ID, DEVICE
from .test_safety import DEV2, TID, mock_inventory, mock_template, preview

GONE = "99999999-0000-0000-0000-000000000000"
NOW = int(time.time() * 1000)


async def call(name: str, args: dict[str, Any]) -> Any:
    async with Client(create_server(make_settings())) as c:
        r = await c.call_tool(name, args)
    return r.structured_content if r.structured_content else r.content[0].text  # type: ignore[union-attr]


def raw_issue(iid: str, entity: str, name: str = "switch_issue_reboot", **kw: Any) -> dict[str, Any]:
    return {
        "issueId": iid,
        "name": name,
        "summary": 'Device has rebooted due to "reload".',
        "priority": "P2",
        "status": "active",
        "entityType": "network device",
        "entityId": entity,
        "mostRecentOccurredTime": NOW - 3 * 3600 * 1000,
        "firstOccurredTime": NOW - 4 * 3600 * 1000,
        **kw,
    }


def test_issue_row_names_device_and_age() -> None:
    row = issue_row(
        raw_issue(
            "i1",
            DEV_ID,
            additionalAttributes=[
                {"key": "nwDeviceName", "value": "edge-sw1.lab.local"},
                {"key": "_count", "value": "4"},
            ],
        ),
        now_ms=NOW,
    )
    assert row["device"] == "edge-sw1.lab.local" and row["id"] == "i1"
    assert row["last_seen"] == "3h00m ago" and row["occurrenceCount"] == "4"
    assert isinstance(row["mostRecentOccurredTime"], str)


def test_group_issues_keeps_newest_and_all_ids() -> None:
    old = issue_row(raw_issue("old", DEV_ID, mostRecentOccurredTime=NOW - 9 * 3600 * 1000))
    new = issue_row(raw_issue("new", DEV_ID))
    other = issue_row(raw_issue("x", DEV_ID, name="OSPF_Down", summary="OSPF down"))
    out = group_issues([old, other, new])
    reboot = next(g for g in out if g["name"] == "switch_issue_reboot")
    assert reboot["ids"] == ["new", "old"] and reboot["times_raised"] == 2 and "id" not in reboot
    assert reboot["last_seen"].startswith("3h")
    assert next(g for g in out if g["name"] == "OSPF_Down")["id"] == "x"


async def test_list_issues_device_column_and_ghosts(api: respx.MockRouter) -> None:
    mock_inventory(api)
    api.get("/dna/data/api/v1/assuranceIssues").respond(
        json={
            "response": [
                raw_issue("i1", DEV_ID),
                raw_issue("i2", GONE, additionalAttributes=[{"key": "nwDeviceName", "value": "old-sw"}]),
            ],
            "page": {"count": 2},
        }
    )
    out = await call("catc_list_issues", {"response_format": "json"})
    rows = {r["id"]: r for r in out["results"]}
    assert rows["i1"]["device"] == DEVICE["hostname"]  # from the inventory when the issue doesn't say
    assert rows["i2"]["device"] == "old-sw (not in inventory)"
    assert "old-sw (not in inventory)" in out["unmanaged"]


async def test_device_health_leaves_out_deleted_devices(api: respx.MockRouter) -> None:
    mock_inventory(api)
    api.get("/dna/intent/api/v1/device-health").respond(
        json={
            "response": [
                {"name": "edge-sw1", "uuid": DEV_ID, "overallHealth": 10},
                {"name": "ghost-sw", "uuid": GONE, "overallHealth": -1, "issueCount": 3},
            ],
            "totalCount": 2,
        }
    )
    out = await call("catc_list_device_health", {"response_format": "json"})
    assert [r["name"] for r in out["results"]] == ["edge-sw1"]
    assert "ghost-sw" in out["left_out"] and "-1" in out["legend"]
    assert out["total"] == 1 and "next_offset" not in out


async def test_device_health_kept_when_inventory_lookup_fails(api: respx.MockRouter) -> None:
    api.get("/dna/intent/api/v1/network-device").respond(500, text="boom")
    api.get("/dna/intent/api/v1/device-health").respond(
        json={"response": [{"name": "ghost-sw", "uuid": GONE}], "totalCount": 1}
    )
    out = await call("catc_list_device_health", {"response_format": "json"})
    assert [r["name"] for r in out["results"]] == ["ghost-sw"] and "left_out" not in out
    assert out["inventory_check"].startswith("failed")


def test_split_applicable_by_family() -> None:
    fams = template_families({"deviceTypes": [{"productFamily": "Routers"}]})
    router = {"id": "r", "family": "Routers"}
    wlc = {"id": "w", "family": "Wireless Controller"}
    assert split_applicable([router, wlc], fams) == ([router], [wlc])
    assert split_applicable([router, wlc], set()) == ([router, wlc], [])


async def test_deploy_skips_devices_outside_template_families(api: respx.MockRouter) -> None:
    mock_inventory(api)
    mock_template(api)  # a 'Switches and Hubs' template
    router = {**DEV2, "family": "Routers"}

    def by_id(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"response": router})

    api.get(f"/dna/intent/api/v1/network-device/{DEV2['id']}").mock(side_effect=by_id)
    out = await preview("catc_deploy_template", {"template": TID, "devices": [DEV_ID, DEV2["id"]]})
    assert out["status"] == "preview" and out["blast_radius"] == 1
    assert out["preview"]["devices"] == [f"{DEVICE['hostname']} ({DEVICE['managementIpAddress']})"]
    assert out["preview"]["targets"]["skipped_not_applicable"] == ["edge-sw2 (10.0.0.12) - Routers"]


async def test_deploy_refuses_when_nothing_applies(api: respx.MockRouter) -> None:
    mock_inventory(api)
    mock_template(api)
    api.get(f"/dna/intent/api/v1/network-device/{DEV2['id']}").respond(
        json={"response": {**DEV2, "family": "Routers"}}
    )
    s = make_settings(mcp_enable_writes=True, mcp_enable_dangerous=True)
    async with Client(create_server(s)) as c:
        r = await c.call_tool(
            "catc_deploy_template", {"template": TID, "devices": [DEV2["id"]]}, raise_on_error=False
        )
    assert r.is_error and "device families" in r.content[0].text  # type: ignore[union-attr]


async def test_device_health_paging_after_filter(api: respx.MockRouter) -> None:
    mock_inventory(api)
    health = [{"name": f"ghost{n}", "uuid": f"9999999{n}-0000-0000-0000-000000000000"} for n in range(3)]
    health.insert(1, {"name": "edge-sw1", "uuid": DEV_ID})
    api.get("/dna/intent/api/v1/device-health").respond(json={"response": health, "totalCount": 4})
    out = await call("catc_list_device_health", {"limit": 1, "response_format": "json"})
    assert [r["name"] for r in out["results"]] == ["edge-sw1"] and out["total"] == 1
    assert "next_offset" not in out


def test_families_not_filtered_for_series_only_entries() -> None:
    assert template_families({"deviceTypes": [{"productFamily": "Routers"}, {"productSeries": "x"}]}) == set()


# --- D28-D30 --------------------------------------------------------------------------------------


async def test_list_clients_by_device(api: respx.MockRouter) -> None:
    from .test_read_tools import mock_device_lookup

    mock_device_lookup(api)
    client = {
        "macAddress": "52:54:00:C8:EF:06",
        "username": "52:54:00:C8:EF:06",
        "ipv4Address": "10.77.0.10",
        "type": "Wired",
        "connectionStatus": "connected",
        "lastUpdatedTime": int(time.time() * 1000) - 120_000,  # not NOW: collection may be minutes ago
        "health": {"overallScore": 10, "rssiThreshold": -72},
        "connectedNetworkDevice": {
            "connectedNetworkDeviceName": "edge-sw1.lab.local",
            "interfaceName": "Gi1/0/2",
        },
        "connection": {"vlanId": "10", "ssid": None, "rssi": 0},
        "onboarding": {"latestFailureReason": "SUCCESS"},
        "traffic": {"txBytes": 1},
    }
    old = {**client, "macAddress": "aa", "connectionStatus": "disconnected"}
    route = api.get("/dna/data/api/v1/clients").respond(
        json={"response": [client, old], "page": {"count": 2}}
    )
    out = await call("catc_list_clients", {"device": "edge-sw1", "response_format": "json"})
    assert route.calls.last.request.url.params["connectedNetworkDeviceName"] == DEVICE["hostname"]
    row = out["results"][0]
    assert row == {
        "mac": "52:54:00:C8:EF:06",
        "ip": "10.77.0.10",
        "type": "Wired",
        "status": "connected",
        "health": 10,
        "device": "edge-sw1.lab.local",
        "port": "Gi1/0/2",
        "vlan": "10",
        "last_seen": "2m ago",
    }
    out = await call("catc_list_clients", {"connected_only": True, "response_format": "json"})
    assert [r["mac"] for r in out["results"]] == ["52:54:00:C8:EF:06"]


async def test_path_trace_accepts_device_names(api: respx.MockRouter) -> None:
    from .test_read_tools import fixture, mock_device_lookup

    mock_device_lookup(api)
    fid = "aeb4c1b6-0c13-4dba-9210-6a4627d81a3b"
    post = api.post("/dna/intent/api/v1/flow-analysis").respond(
        202, json={"response": {"flowAnalysisId": fid, "taskId": "t"}}
    )
    api.get(f"/dna/intent/api/v1/flow-analysis/{fid}").respond(json=fixture("flow_analysis_failed.json"))
    await call("catc_path_trace", {"source_ip": "edge-sw1", "dest_ip": "10.2.2.2"})
    import json as _json

    assert _json.loads(post.calls.last.request.content)["sourceIP"] == "10.0.0.11"


async def test_get_issue_drops_internal_attributes(api: respx.MockRouter) -> None:
    iid = "8928922f-257f-432a-bdfb-17b8e26317f0"
    api.get(f"/dna/data/api/v1/assuranceIssues/{iid}").respond(
        json={
            "response": [
                {
                    **raw_issue(iid, DEV_ID, name="OSPF_Down", summary="OSPF down"),
                    "additionalAttributes": [
                        {"key": "_key", "value": "NetworkDevice:x:y"},
                        {"key": "siteHierarchyGraphId", "value": "/a/b/"},
                        {"key": "deviceUuid", "value": DEV_ID},
                        {"key": "priority", "value": "P2"},
                        {"key": "syslogMsg", "value": "Nbr 10.255.255.2 from FULL to DOWN"},
                        {"key": "intfName", "value": "GigabitEthernet2"},
                        {"key": "nwDeviceName", "value": "r1"},
                    ],
                }
            ]
        }
    )
    out = await call("catc_get_issue", {"issue_id": iid})
    assert out["attributes"] == {
        "syslogMsg": "Nbr 10.255.255.2 from FULL to DOWN",
        "intfName": "GigabitEthernet2",
    }
    assert out["device"] == "r1"


def test_deployment_summary_keeps_realized_cli() -> None:
    from catc_mcp.tools.templates import deployment_summary

    out = deployment_summary(
        {
            "status": "SUCCESS",
            "devices": [{"name": "r1", "status": "SUCCESS", "realizedClis": "ntp server 1.1.1.1"}],
        }
    )
    assert out["devices"][0]["realizedClis"] == "ntp server 1.1.1.1"


def test_wlc_provision_status_readable() -> None:
    from catc_mcp.tools.wireless import provision_status

    out = provision_status(
        {
            "networkDeviceId": "x",
            "siteId": "y",
            "lastProvisionedTimeStamp": "1792080802897",
            "outOfSync": False,
        }
    )
    assert out == {"outOfSync": False, "lastProvisioned": "2026-10-15 16:13 UTC"}


async def test_get_issue_keeps_ssid_and_real_values(api: respx.MockRouter) -> None:
    iid = "8928922f-257f-432a-bdfb-17b8e26317f1"
    api.get(f"/dna/data/api/v1/assuranceIssues/{iid}").respond(
        json={
            "response": {
                **raw_issue(iid, DEV_ID, name="wifi"),
                "additionalAttributes": [
                    {"key": "ssid", "value": "corp"},
                    {"key": "bssid", "value": "aa:bb"},
                    {"key": "routerId", "value": "1.1.1.1"},
                    {"key": "count", "value": "1"},
                    {"key": "nwDeviceName", "value": "r1"},
                    {"key": "failureReason", "value": "AAA timeout"},
                ],
            }
        }
    )
    out = await call("catc_get_issue", {"issue_id": iid})
    assert out["attributes"] == {
        "ssid": "corp",
        "bssid": "aa:bb",
        "count": "1",
        "failureReason": "AAA timeout",
    }


def test_deployment_summary_redacts_lists() -> None:
    from catc_mcp.tools.templates import deployment_summary

    out = deployment_summary(
        {"devices": [{"name": "r1", "realizedClis": ["username a secret 9 xyz", "ntp x"]}]}
    )
    assert "xyz" not in str(out) and out["devices"][0]["realizedClis"][1] == "ntp x"


async def test_path_trace_rejects_bad_ip(api: respx.MockRouter) -> None:
    async with Client(create_server(make_settings())) as c:
        r = await c.call_tool(
            "catc_path_trace", {"source_ip": "10.0.0.999", "dest_ip": "10.0.0.1"}, raise_on_error=False
        )
    assert r.is_error and "not a valid IP" in r.content[0].text  # type: ignore[union-attr]
