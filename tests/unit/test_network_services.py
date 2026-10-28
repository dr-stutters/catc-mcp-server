"""D68: catc_network_services_health on aaaServices / dhcpServices rows in the 3.2.2 data-API shape
(spec CE_Cat_Center_Org-AAAServices-1.0.0: counters summed, latency averaged per row).

#259: dead-AAA Assurance issues (assuranceIssues rows in the spec IssuesResponse shape, names and fields as
Catalyst Center 3.2.2 raised them) fold into the AAA verdict."""

import json
from typing import Any

import httpx
import respx
from fastmcp import Client

from catc_mcp.server import create_server

from .conftest import make_settings
from .test_read_tools import AREA, GLOBAL
from .test_write_tools import mock_sites, run

AAA = "/dna/data/api/v1/aaaServices"
ISSUES = "/dna/data/api/v1/assuranceIssues"
ISE = "198.18.134.35"


def aaa_row(device: str, tx: int, failed: int, eap: int, eap_failed: int, latency: int) -> dict[str, Any]:
    mab, mab_failed = tx - eap, failed - eap_failed
    return {
        "id": f"{ISE}-{device}",
        "serverIp": ISE,
        "deviceId": f"id-{device}",
        "deviceName": device,
        "deviceFamily": "Switches and Hubs",
        "deviceSiteHierarchy": "Global/AU/SYD-1",
        "transactions": tx,
        "successfulTransactions": tx - failed,
        "failedTransactions": failed,
        "eapTransactions": eap,
        "eapSuccessfulTransactions": eap - eap_failed,
        "eapFailedTransactions": eap_failed,
        "mabTransactions": mab,
        "mabSuccessfulTransactions": mab - mab_failed,
        "mabFailedTransactions": mab_failed,
        "latency": latency,
        "eapLatency": latency + 20,
        "mabLatency": latency - 20,
    }


ROWS = [aaa_row("sw1", 200, 6, 100, 0, 100), aaa_row("sw2", 12, 0, 12, 0, 400)]


def mock_policy(api: respx.MockRouter, issues: list[dict[str, Any]] | None = None) -> respx.Route:
    api.get("/dna/intent/api/v1/authentication-policy-servers").respond(
        json={"response": [{"ipAddress": ISE, "isIseEnabled": True}]}
    )
    return api.get(ISSUES).respond(json=page(issues or []))


def dead_issue(
    device: str,
    *,
    name: str = "fabric_aaa_server_down_trigger",
    status: str = "resolved",
    site: str = "Global/AU/SYD-1/Level 1",
    first: int = 1793153068020,  # 02:04:28 UTC
    last: int = 1793153071450,
    updated: int | None = 1793153400301,  # 02:10:00 UTC
    server: str = ISE,
) -> dict[str, Any]:
    """An assuranceIssues row (spec IssuesResponse) as Catalyst Center 3.2.2 raises it."""
    if name == "radius_error_trigger":
        text = (
            f"The RADIUS server '{server}:1812,1813' is not responding to requests being made from the "
            f"network device '{device}'"
        )
        prio, kind = "P2", "access"
    else:
        text = f"AAA Server '{server}' state on Edge device '{device}' is DEAD."
        prio, kind = "P1", "border router"
    return {
        "issueId": f"issue-{device}-{name}",
        "name": name,
        "description": text,
        "summary": text,
        "priority": prio,
        "severity": "high",
        "deviceType": kind,
        "deviceFamily": "Switches and Hubs",
        "category": "connected",
        "entityType": "network device",
        "entityId": "00000000-0000-4000-8000-000000000041",
        "firstOccurredTime": first,
        "mostRecentOccurredTime": last,
        "status": status,
        "isGlobal": True,
        "updatedBy": "System" if updated else None,
        "updatedTime": updated,
        "siteName": "Level 1",
        "siteHierarchy": site,
        "additionalAttributes": [
            {"key": "nwDeviceName", "value": device},
            {"key": "managementIpAddr", "value": "192.0.2.41"},
            {"key": "status", "value": status},
        ],
    }


def page(rows: list[dict[str, Any]]) -> dict[str, Any]:
    return {"response": rows, "page": {"limit": 50, "offset": 1, "count": len(rows)}, "version": "1.0"}


async def test_aaa_rows_aggregate_verdict_and_trend(api: respx.MockRouter) -> None:
    mock_policy(api)
    lst = api.get(AAA).respond(json=page(ROWS))
    trend = api.post(f"{AAA}/trendAnalytics").respond(
        json={
            "response": [
                {
                    "timestamp": 1792500000000,
                    "aggregateAttributes": [
                        {"name": "transactions", "function": "sum", "value": 150},
                        {"name": "failedTransactions", "function": "sum", "value": 6},
                    ],
                },
                {"timestamp": 1792503600000, "aggregateAttributes": [{"name": "transactions", "value": 0}]},
            ]
        }
    )
    async with Client(create_server(make_settings())) as c:
        out = await run(c, "catc_network_services_health", {"hours": 6})
    srv = out["aaa"]["servers"][0]
    assert srv["server"] == ISE and srv["name"] == "ISE"
    assert srv["transactions"] == 212 and srv["failedTransactions"] == 6 and srv["success_percent"] == 97.2
    assert srv["mabFailedTransactions"] == 6 and srv["eapTransactions"] == 112
    # latency weighted by transactions: (100*200 + 400*12) / 212 = 117
    assert srv["latency_ms"] == 117
    assert srv["verdict"] == (
        "ISE 198.18.134.35 answered 97.2% of 212 AAA requests, average latency 117 ms; 6 MAB failures on sw1."
    )
    assert out["verdict"] == [srv["verdict"]]
    assert out["aaa"]["top_failing_devices"][0]["deviceName"] == "sw1"
    (bucket,) = out["aaa"]["trend"]  # the empty bucket is dropped
    assert bucket["transactions"] == 150 and bucket["failed"] == 6 and bucket["time"]
    body = json.loads(trend.calls.last.request.content)
    assert body["trendInterval"] == "5MIN" and {a["name"] for a in body["aggregateAttributes"]} == {
        "transactions",
        "failedTransactions",
    }
    q = lst.calls.last.request.url.params
    assert "startTime" in q and "endTime" in q


async def test_site_filter_and_empty_window(api: respx.MockRouter) -> None:
    mock_policy(api)
    mock_sites(api, [GLOBAL, AREA])
    lst = api.get(AAA).respond(json=page([]))
    trend = api.post(f"{AAA}/trendAnalytics")
    async with Client(create_server(make_settings())) as c:
        out = await run(c, "catc_network_services_health", {"site": "Global/AU"})
    assert lst.calls.last.request.url.params["siteHierarchy"] == "Global/AU*"
    assert out["aaa"]["servers"] == [] and "No AAA rows" in out["aaa"]["note"]
    assert out["verdict"] == ["No network-service transactions measured in the window."]
    assert trend.call_count == 0 and out["site"] == "Global/AU"


async def test_all_services_and_trend_failure_is_reported(api: respx.MockRouter) -> None:
    mock_policy(api)
    api.get(AAA).respond(json=page(ROWS[:1]))
    api.post(f"{AAA}/trendAnalytics").respond(400, json={"response": {"message": "bad trendInterval"}})
    api.get("/dna/data/api/v1/dhcpServices").respond(
        json=page(
            [
                {
                    "serverIp": "198.18.133.1",
                    "deviceName": "sw1",
                    "transactions": 10,
                    "successfulTransactions": 10,
                    "failedTransactions": 0,
                    "latency": 30,
                    "discoverOfferLatency": 20,
                    "requestAcknowledgeLatency": 10,
                }
            ]
        )
    )
    api.post("/dna/data/api/v1/dhcpServices/trendAnalytics").respond(json={"response": []})
    api.get("/dna/data/api/v1/dnsServices").mock(side_effect=lambda r: httpx.Response(500, text="boom"))
    async with Client(create_server(make_settings())) as c:
        out = await run(c, "catc_network_services_health", {"service": "all"})
    assert "trend_unavailable" in out["aaa"]
    dhcp = out["dhcp"]["servers"][0]
    assert dhcp["discoverOfferLatency_ms"] == 20 and dhcp["verdict"].startswith(
        "198.18.133.1 answered 100.0% of 10 DHCP requests"
    )
    assert "unavailable" in out["dns"] and len(out["verdict"]) == 2


async def test_dead_issue_folds_into_a_healthy_looking_verdict(api: respx.MockRouter) -> None:
    """The live #259 case: some transactions counted, but the switch marked ISE DEAD in the window."""
    issues = mock_policy(api, [dead_issue("sw1.example.com")])
    api.get(AAA).respond(json=page([aaa_row("sw1", 5, 2, 0, 0, 48)]))
    async with Client(create_server(make_settings())) as c:
        out = await run(c, "catc_network_services_health", {"device": "sw1", "hours": 0.5, "trend": False})
    srv = out["aaa"]["servers"][0]
    assert srv["verdict"] == (
        "ISE 198.18.134.35 answered 60.0% of 5 AAA requests, average latency 48 ms; 2 MAB failures on sw1. "
        "But sw1.example.com marked ISE 198.18.134.35 DEAD at 02:04 UTC (P1, resolved 02:10 UTC): requests "
        "in that window never reached the server and are not counted."
    )
    assert out["verdict"] == [srv["verdict"]]
    (row,) = out["aaa"]["dead_server_issues"]
    assert row["server"] == ISE and row["priority"] == "P1" and row["resolved_at"] == "02:10 UTC"
    assert row["id"] == "issue-sw1.example.com-fabric_aaa_server_down_trigger"
    assert "only the AAA transactions a device actually sent" in out["aaa"]["counting_note"]
    q = issues.calls.last.request.url.params
    assert q.get_list("name") == ["fabric_aaa_server_down_trigger", "radius_error_trigger"]
    assert q.get_list("status") == ["active", "resolved"] and "startTime" in q and "endTime" in q


async def test_no_transactions_and_dead_issue_is_not_healthy(api: respx.MockRouter) -> None:
    """A switch without clients sends nothing: an empty window plus a DEAD issue must not read as fine."""
    mock_policy(api, [dead_issue("sw2.example.com")])
    api.get(AAA).respond(json=page([]))
    async with Client(create_server(make_settings())) as c:
        out = await run(c, "catc_network_services_health", {"device": "sw2*"})
    assert out["aaa"]["servers"] == [] and "No AAA rows" in out["aaa"]["note"]
    assert out["verdict"] == [
        "ISE 198.18.134.35: no AAA transactions counted, but sw2.example.com marked ISE 198.18.134.35 DEAD "
        "at 02:04 UTC (P1, resolved 02:10 UTC): requests in that window never reached the server and are "
        "not counted."
    ]
    assert not any("No network-service transactions" in v for v in out["verdict"])


async def test_dead_issues_filtered_to_site_and_device(api: respx.MockRouter) -> None:
    mock_sites(api, [GLOBAL, AREA])
    issues = mock_policy(
        api,
        [
            dead_issue(
                "sw1.example.com",
                name="radius_error_trigger",
                status="active",
                site="Global/AU/SYD-1",
                updated=None,
            ),
            dead_issue("sw9.example.com", site="Global/AU/SYD-1"),  # another device
            dead_issue("sw1.example.com", site="Global/AUX/Other"),  # outside the site
        ],
    )
    api.get(AAA).respond(json=page([]))
    async with Client(create_server(make_settings())) as c:
        out = await run(
            c, "catc_network_services_health", {"site": "Global/AU", "device": "sw1", "trend": False}
        )
    assert issues.calls.last.request.url.params["siteHierarchy"] == "Global/AU*"
    (row,) = out["aaa"]["dead_server_issues"]
    assert row["name"] == "radius_error_trigger" and "resolved_at" not in row
    (line,) = out["verdict"]
    assert "sw1.example.com reported ISE 198.18.134.35 not responding at 02:04 UTC (P2, still active" in line


async def test_dead_issue_read_failure_is_reported(api: respx.MockRouter) -> None:
    mock_policy(api)
    api.get(ISSUES).mock(side_effect=lambda r: httpx.Response(500, text="boom"))
    api.get(AAA).respond(json=page(ROWS))
    async with Client(create_server(make_settings())) as c:
        out = await run(c, "catc_network_services_health", {"trend": False})
    assert "dead_server_issues_unavailable" in out["aaa"] and "dead_server_issues" not in out["aaa"]
    assert out["verdict"][0].startswith("ISE 198.18.134.35 answered 97.2% of 212 AAA requests")
