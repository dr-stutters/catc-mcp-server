"""D68: catc_network_services_health on aaaServices / dhcpServices rows in the 3.2.2 data-API shape
(spec CE_Cat_Center_Org-AAAServices-1.0.0: counters summed, latency averaged per row)."""

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


def mock_policy(api: respx.MockRouter) -> None:
    api.get("/dna/intent/api/v1/authentication-policy-servers").respond(
        json={"response": [{"ipAddress": ISE, "isIseEnabled": True}]}
    )


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
