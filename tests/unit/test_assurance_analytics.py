"""D38: health trends with dips, top problem devices/clients, issue recurrence, AI insights and the
site health report. Payload shapes are recorded from the 3.2.2 lab (tests/fixtures/
assurance_analytics.json: r2 GigabitEthernet2 shut for ~17 minutes); the health dips are hand-made
on top of them, since a cat8000v's health score doesn't move for a down link."""

import json
import time
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx
from fastmcp.exceptions import ToolError

from catc_mcp.tools.assurance_analytics import (
    CHUNK_MS,
    DEVICE_MINUTES,
    NETWORK_INTERVALS,
    SITE_INTERVALS,
    device_interval,
    healthy_percent,
    issue_periods,
    pick_interval,
    recurrence,
    series,
    summarize,
    trend_buckets,
)

from .test_read_tools import call

FIX = json.loads((Path(__file__).parent.parent / "fixtures" / "assurance_analytics.json").read_text())
R1 = "f64d8d9f-30b2-48f6-a6fe-73d2aaed0fa3"
R2 = "02a69307-652c-4518-90e1-700099ecd3ec"
BLDG = "ec510a85-c946-4be2-94d0-22d76af7f403"
SITE = {"id": BLDG, "name": "mcp-test-bldg", "nameHierarchy": "Global/mcp-test-lab/mcp-test-bldg"}
T0 = 1_792_200_000_000  # 2026-10-17 01:20 UTC
MIN = 60_000


def pts(*values: float, step: int = 5) -> list[tuple[int, float]]:
    return [(T0 + i * step * MIN, v) for i, v in enumerate(values)]


def mock_lookups(api: respx.MockRouter) -> None:
    api.get(f"/dna/intent/api/v1/sites/{BLDG}").respond(json={"response": SITE})
    for dev_id, name in ((R1, "r1.mcp.lab"), (R2, "r2.mcp.lab")):
        api.get(f"/dna/intent/api/v1/network-device/{dev_id}").respond(
            json={"response": {"id": dev_id, "hostname": name, "family": "Routers"}}
        )


def issue(
    iid: str, *, name: str = "OSPF_Down", dev: str = R2, first: int, status: str = "resolved", **kw: Any
) -> dict[str, Any]:
    return {
        "issueId": iid,
        "name": name,
        "summary": f"{name} on {dev}",
        "priority": "P2",
        "status": status,
        "entityType": "network device",
        "entityId": dev,
        "firstOccurredTime": first,
        "mostRecentOccurredTime": first + 2 * MIN,
        "updatedTime": first + 15 * MIN if status == "resolved" else None,
        "additionalAttributes": [
            {"key": "nwDeviceName", "value": "r2.mcp.lab" if dev == R2 else "r1.mcp.lab"}
        ],
        **kw,
    }


# --- pure helpers ------------------------------------------------------------------------------


def test_summarize_finds_dips_their_length_and_depth() -> None:
    out = summarize(pts(10, 10, 6, 3, 7, 10, 10, 9, 5, 10), dip_below=8, bucket_min=5, unit="score 1-10")
    assert out["min"] == 3 and out["latest"] == 10 and out["samples"] == 10
    assert out["avg"] == 8.0 and out["worst_at"] == "2026-10-17 01:35"
    first, second = out["dips"]
    assert first == {"start": "2026-10-17 01:30", "end": "2026-10-17 01:45", "minutes": 15, "lowest": 3}
    assert second["minutes"] == 5 and second["lowest"] == 5
    assert out["dip_threshold"] == "below 8"


def test_summarize_ongoing_dip_and_direction() -> None:
    out = summarize(pts(100, 100, 100, 100, 80, 70), dip_below=90, bucket_min=10, unit="%")
    assert out["dips"] == [
        {"start": "2026-10-17 01:40", "end": None, "minutes": 15, "lowest": 70, "ongoing": True}
    ]
    assert out["direction"] == "worse" and out["dip_threshold"] == "below 90%"
    assert summarize(pts(70, 70, 100, 100), dip_below=50, bucket_min=5, unit="%")["direction"] == "better"
    assert summarize([], dip_below=8, bucket_min=5, unit="x") == {
        "samples": 0,
        "note": "no data in this window",
    }


def test_summarize_trims_points_but_keeps_the_last() -> None:
    out = summarize(pts(*([10.0] * 100)), dip_below=8, bucket_min=5, unit="score 1-10")
    assert len(out["points"]) <= 25 and out["points"][-1].endswith(" 10")
    assert out["dips"] == [] and out["direction"] == "steady"


def test_trend_parsing_recorded_shapes() -> None:
    # Network trend: counts arrive as strings and are sample sums per bucket; only the ratio counts.
    net = healthy_percent(trend_buckets(FIX["network_trend"]))
    assert net and all(v == 100.0 for _, v in net)
    dev = series(trend_buckets(FIX["device_trend"]), "overallHealthScore:min")
    assert dev and all(v == 10 for _, v in dev)
    site = series(trend_buckets(FIX["site_trend"]), "networkDeviceGoodHealthPercentage")
    assert site and site == sorted(site)


def test_healthy_percent_from_counts() -> None:
    body = {
        "response": [
            {"timestamp": T0, "attributes": [{"name": "goodDeviceCount", "value": "6"}]},
            {
                "timestamp": T0 + 5 * MIN,
                "attributes": [
                    {"name": "goodDeviceCount", "value": "3"},
                    {"name": "poorDeviceCount", "value": "3"},
                ],
            },
            {"timestamp": T0 + 10 * MIN, "attributes": []},
        ]
    }
    assert healthy_percent(trend_buckets(body)) == [(T0, 100.0), (T0 + 5 * MIN, 50.0)]


def test_recurrence_groups_openings_of_the_same_issue() -> None:
    issues = [
        issue("a", first=T0),
        issue("b", first=T0 + 60 * MIN),
        issue("c", first=T0 + 120 * MIN, status="active"),
        issue("d", dev=R1, first=T0 + 5 * MIN),
        issue("e", name="router_cpu_high", first=T0),
    ]
    out = recurrence(issues, min_times=2, now_ms=T0 + 130 * MIN)
    assert len(out) == 1
    g = out[0]
    assert g["name"] == "OSPF_Down" and g["device"] == "r2.mcp.lab" and g["times_opened"] == 3
    assert g["avg_minutes_between"] == 60 and g["status_now"] == "active"
    assert g["openings"][0] == {
        "opened": "2026-10-17 01:20",
        "closed": "2026-10-17 01:35",
        "status": "resolved",
        "open_minutes": 15,
        "id": "a",
    }
    assert g["openings"][-1]["open_minutes"] == 10 and "closed" not in g["openings"][-1]
    # min_times=1 lists every issue, the most recurrent first.
    all_ = recurrence(issues, min_times=1, now_ms=T0 + 130 * MIN)
    assert len(all_) == 3 and all_[0]["times_opened"] == 3


def test_recurrence_counts_repeats_within_one_issue() -> None:
    one = issue("a", first=T0, additionalAttributes=[{"key": "_count", "value": "4"}])
    out = recurrence([one], min_times=2, now_ms=T0)
    assert out[0]["times_opened"] == 1 and out[0]["occurrences"] == 4


def test_issue_periods() -> None:
    out = issue_periods([issue("b", first=T0 + 60 * MIN), issue("a", first=T0)], now_ms=T0)
    assert [p["opened"] for p in out] == ["2026-10-17 01:20", "2026-10-17 02:20"]
    assert out[0] == {
        "priority": "P2",
        "name": "OSPF_Down",
        "opened": "2026-10-17 01:20",
        "closed": "2026-10-17 01:35",
        "status": "resolved",
        "open_minutes": 15,
    }


# --- tools ---------------------------------------------------------------------------------------


def test_week_and_month_trends_keep_enough_buckets() -> None:
    # Over a day the network/device trend APIs take only 60-minute buckets (read in 7-day chunks).
    assert device_interval(24, NETWORK_INTERVALS) == ("5MIN", 5)
    assert device_interval(168, NETWORK_INTERVALS) == ("1HR", 60)  # 168 buckets, not 1-2 at 7 days
    assert device_interval(168, DEVICE_MINUTES) == ("60", 60)
    assert pick_interval(168, SITE_INTERVALS) == ("1HR", 60)
    assert pick_interval(720, SITE_INTERVALS) == ("1DAY", 1440)


async def test_health_trend_network_month_in_week_chunks(api: respx.MockRouter) -> None:
    def week(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        assert body["trendInterval"] == "1HR" and body["endTime"] - body["startTime"] <= CHUNK_MS
        good = [{"name": "goodDeviceCount", "value": "2"}]
        return httpx.Response(200, json={"response": [{"timestamp": body["startTime"], "attributes": good}]})

    route = api.post("/dna/data/api/v1/networkDevices/trendAnalytics").mock(side_effect=week)
    out = await call("catc_health_trend", {"hours": 720})
    assert route.call_count == 5 and out["interval"] == "1HR"  # 30 days = 4 weeks + 2 days
    assert out["network_devices_healthy"]["samples"] == 5


async def test_health_trend_network(api: respx.MockRouter) -> None:
    route = api.post("/dna/data/api/v1/networkDevices/trendAnalytics").respond(json=FIX["network_trend"])
    out = await call("catc_health_trend", {"hours": 2})
    body = json.loads(route.calls.last.request.content)
    assert body["trendInterval"] == "5MIN" and "goodDeviceCount" in body["attributes"]
    assert out["network_devices_healthy"]["min"] == 100 and not out["network_devices_healthy"].get("dips")


async def test_health_trend_device_with_dip_and_issue_periods(api: respx.MockRouter) -> None:
    mock_lookups(api)
    now = int(time.time() * 1000)
    scores = [10, 10, 4, 3, 10, 10]
    api.post(f"/dna/data/api/v1/networkDevices/{R2}/trendAnalytics").respond(
        json={
            "response": [
                {
                    "timestamp": now - (6 - i) * 10 * MIN,
                    "aggregateAttributes": [{"name": "overallHealthScore", "function": "MIN", "value": v}],
                }
                for i, v in enumerate(scores)
            ]
        }
    )
    issues = api.get("/dna/data/api/v1/assuranceIssues").respond(
        json={"response": FIX["issues"]["response"], "page": {"count": len(FIX["issues"]["response"])}}
    )
    out = await call("catc_health_trend", {"scope": "device", "target": R2, "hours": 1})
    assert out["device"] == "r2.mcp.lab" and out["interval"] == "5MIN"
    assert out["health"]["min"] == 3 and len(out["health"]["dips"]) == 1
    assert out["health"]["dips"][0]["minutes"] == 15  # from the first low bucket to the end of the last
    assert issues.calls.last.request.url.params["networkDeviceId"] == R2
    assert out["issue_periods"] and out["issue_periods"][0]["name"] == "OSPF_Down"


async def test_health_trend_device_404_is_no_data(api: respx.MockRouter) -> None:
    mock_lookups(api)
    api.post(f"/dna/data/api/v1/networkDevices/{R2}/trendAnalytics").respond(404, json={"message": "nope"})
    api.get("/dna/data/api/v1/assuranceIssues").respond(json={"response": [], "page": {"count": 0}})
    out = await call("catc_health_trend", {"scope": "device", "target": R2})
    assert out["health"] == {"samples": 0, "note": "no data in this window"} and not out.get("issue_periods")


async def test_health_trend_site_polls_the_assurance_task(api: respx.MockRouter) -> None:
    mock_lookups(api)
    path = f"/dna/data/api/v1/siteHealthSummaries/{BLDG}/trendAnalytics"

    def trend(request: httpx.Request) -> httpx.Response:
        if request.url.params.get("taskId"):
            return httpx.Response(200, json=FIX["site_trend"])
        return httpx.Response(200, json=FIX["site_trend_task"])

    route = api.get(path).mock(side_effect=trend)
    task_id = FIX["site_trend_task"]["response"]["taskId"]
    api.get(f"/dna/data/api/v1/assuranceTasks/{task_id}").mock(
        side_effect=[
            httpx.Response(200, json={"response": {"id": task_id, "status": "IN_PROGRESS"}}),
            httpx.Response(200, json=FIX["assurance_task"]),
        ]
    )
    out = await call("catc_health_trend", {"scope": "site", "target": BLDG, "hours": 2})
    first = route.calls[0].request.url.params
    assert first["trendInterval"] == "5MIN" and "issueCount" in first.get_list("attribute")
    assert out["site"] == "Global/mcp-test-lab/mcp-test-bldg"
    assert out["network_devices_healthy"]["min"] == 100
    assert out["clients_healthy"]["samples"] == 0
    bursts = out["issue_bursts"]
    assert bursts and bursts[0]["issues_raised"] == 2 and bursts[0]["p1_p2_raised"] == 2


async def test_health_trend_needs_a_target() -> None:
    with pytest.raises(ToolError, match="Give target"):
        await call("catc_health_trend", {"scope": "device"})


async def test_health_trend_client(api: respx.MockRouter) -> None:
    route = api.post("/dna/data/api/v1/clients/aa:bb:cc:dd:ee:ff/trendAnalytics").respond(
        json={
            "response": [
                {
                    "timestamp": T0,
                    "aggregateAttributes": [{"name": "overallScore", "function": "min", "value": 9}],
                },
                {
                    "timestamp": T0 + 5 * MIN,
                    "aggregateAttributes": [{"name": "overallScore", "function": "min", "value": 2}],
                },
            ]
        }
    )
    api.get("/dna/data/api/v1/assuranceIssues").respond(json={"response": [], "page": {"count": 0}})
    out = await call("catc_health_trend", {"scope": "client", "target": "aabb.ccdd.eeff", "hours": 1})
    assert json.loads(route.calls.last.request.content)["trendInterval"] == "5MIN"
    assert out["client"] == "aa:bb:cc:dd:ee:ff" and out["health"]["min"] == 2
    assert out["health"]["dips"][0]["ongoing"] is True


async def test_top_problem_devices_have_the_issue_behind_them(api: respx.MockRouter) -> None:
    devices = FIX["devices_query"]["response"]
    healthy = {**devices[0], "id": "cccccccc-0000-0000-0000-000000000000", "name": "healthy-sw"}
    sick = {
        **devices[0],
        "id": "dddddddd-0000-0000-0000-000000000000",
        "name": "sick-sw",
        "metricsDetails": {"overallHealthScore": 6},
        "aggregateAttributes": [
            {"name": "overallHealthScore", "function": "MIN", "value": 2.0},
            {"name": "overallHealthScore", "function": "AVG", "value": 6.5},
        ],
    }
    q = api.post("/dna/data/api/v1/networkDevices/query").respond(
        json={"response": [sick, *devices, healthy]}
    )
    api.get("/dna/data/api/v1/assuranceIssues").respond(
        json={"response": FIX["issues"]["response"], "page": {"count": len(FIX["issues"]["response"])}}
    )
    out = await call("catc_top_problems", {"hours": 2})
    names = [r["device"] for r in out["results"]]
    assert names[0] == "sick-sw" and "healthy-sw" not in names
    assert {"r1.mcp.lab", "r2.mcp.lab"} <= set(names)
    r2 = next(r for r in out["results"] if r["device"] == "r2.mcp.lab")
    assert r2["issue"]["name"] == "OSPF_Down" and r2["issues"] >= 1 and r2["worst_health"] == 10
    assert "re-evaluates" in out["active_issues"]  # the recorded issues are still active
    body = json.loads(q.calls.last.request.content)
    assert body["page"]["sortBy"][0] == {"name": "overallHealthScore", "order": "asc", "function": "min"}


async def test_top_problem_devices_by_site(api: respx.MockRouter) -> None:
    mock_lookups(api)
    # A sibling whose name extends the site's ('mcp-test-bldg2') is not below it.
    sibling = {**FIX["devices_query"]["response"][0], "siteHierarchy": "Global/mcp-test-lab/mcp-test-bldg2"}
    sibling["aggregateAttributes"] = [{"name": "overallHealthScore", "function": "MIN", "value": 1}]
    q = api.post("/dna/data/api/v1/networkDevices/query").respond(json={"response": [sibling]})
    issues = api.get("/dna/data/api/v1/assuranceIssues").respond(json={"response": [], "page": {"count": 0}})
    out = await call("catc_top_problems", {"site": BLDG})
    assert not out.get("results") and "no devices" in out["note"]
    assert issues.calls.last.request.url.params.get_list("siteHierarchy") == [
        "Global/mcp-test-lab/mcp-test-bldg",
        "Global/mcp-test-lab/mcp-test-bldg/*",
    ]
    filters = json.loads(q.calls.last.request.content)["filters"]
    assert filters == [{"key": "siteId", "operator": "eq", "value": BLDG}]


async def test_top_problem_clients_by_site_and_scan_note(api: respx.MockRouter) -> None:
    mock_lookups(api)
    worst = [
        {
            "macAddress": f"AA:BB:CC:00:01:{n:02X}",
            "aggregateAttributes": [{"name": "overallScore", "function": "min", "value": 2}],
        }
        for n in range(100)
    ]
    q = api.post("/dna/data/api/v1/clients/query").respond(json={"response": worst})
    api.get("/dna/data/api/v1/assuranceIssues").respond(json={"response": [], "page": {"count": 0}})
    out = await call("catc_top_problems", {"kind": "clients", "site": BLDG, "limit": 5})
    assert len(out["results"]) == 5 and "lowest health" in out["scan_limit"]
    assert json.loads(q.calls.last.request.content)["filters"] == [
        {
            "key": "siteHierarchy",
            "operator": "in",
            "value": ["Global/mcp-test-lab/mcp-test-bldg", "Global/mcp-test-lab/mcp-test-bldg/*"],
        }
    ]


async def test_top_problem_clients(api: respx.MockRouter) -> None:
    clients = [
        {
            "macAddress": "AA:BB:CC:00:00:01",
            "ipv4Address": "10.1.1.10",
            "type": "Wired",
            "overallScore": 3,
            "latestFailureReason": "AAA_FAILURE",
            "aggregateAttributes": [{"name": "overallScore", "function": "min", "value": 1}],
        },
        {
            "macAddress": "AA:BB:CC:00:00:02",
            "overallScore": 10,
            "aggregateAttributes": [{"name": "overallScore", "function": "min", "value": 10}],
        },
    ]
    q = api.post("/dna/data/api/v1/clients/query").respond(json={"response": clients})
    api.get("/dna/data/api/v1/assuranceIssues").respond(json={"response": [], "page": {"count": 0}})
    out = await call("catc_top_problems", {"kind": "clients"})
    assert [r["mac"] for r in out["results"]] == ["AA:BB:CC:00:00:01"]
    assert out["results"][0]["last_failure"] == "AAA_FAILURE" and out["results"][0]["worst_health"] == 1
    assert json.loads(q.calls.last.request.content)["aggregateAttributes"][0]["name"] == "overallScore"


async def test_issue_recurrence_tool(api: respx.MockRouter) -> None:
    mock_lookups(api)
    now = int(time.time() * 1000)
    rows = [issue(f"i{n}", first=now - (5 - n) * 60 * MIN) for n in range(4)]
    route = api.get("/dna/data/api/v1/assuranceIssues").respond(json={"response": rows, "page": {"count": 4}})
    out = await call("catc_issue_recurrence", {"device": R2, "hours": 24})
    params = route.calls.last.request.url.params
    assert params["networkDeviceId"] == R2 and "status" not in params  # resolved issues count too
    assert out["recurring"][0]["times_opened"] == 4 and out["recurring"][0]["avg_minutes_between"] == 60
    none = await call("catc_issue_recurrence", {"hours": 24, "min_times": 5})
    assert not none.get("recurring") and "5+ times" in none["note"]


async def test_ai_insights_none_found_and_available(api: respx.MockRouter) -> None:
    mock_lookups(api)
    # The recorded response (aiDriven filter left out) has only non-AI issues: they are not reported.
    route = api.get("/dna/intent/api/v1/issues").respond(json=FIX["intent_issues"])
    out = await call("catc_ai_insights", {"site": BLDG})
    assert out["status"] == "no_ai_issues" and "cloud" in out["note"]
    params = route.calls.last.request.url.params
    assert params["siteId"] == BLDG and params["aiDriven"] == "Yes"
    await call("catc_ai_insights", {})
    params = route.calls.last.request.url.params
    assert params["aiDriven"] == "Yes" and "siteId" not in params  # filtered server-side network-wide too
    ai = {**FIX["intent_issues"]["response"][0], "aiDriven": "Yes", "name": "Excessive onboarding time"}
    api.get("/dna/intent/api/v1/issues").respond(json={"response": [ai]})
    out = await call("catc_ai_insights", {})
    assert out["status"] == "available" and out["insights"][0]["issue"] == "Excessive onboarding time"


async def test_ai_insights_never_fails(api: respx.MockRouter) -> None:
    api.get("/dna/intent/api/v1/issues").respond(500, json={"message": "cloud unreachable"})
    out = await call("catc_ai_insights", {})
    assert out["status"] == "unavailable" and "AI Network Analytics" in out["reason"]


def mock_report(api: respx.MockRouter) -> None:
    mock_lookups(api)
    path = f"/dna/data/api/v1/siteHealthSummaries/{BLDG}/trendAnalytics"
    api.get(path).mock(
        side_effect=lambda r: httpx.Response(
            200, json=FIX["site_trend"] if r.url.params.get("taskId") else FIX["site_trend_task"]
        )
    )
    task_id = FIX["site_trend_task"]["response"]["taskId"]
    api.get(f"/dna/data/api/v1/assuranceTasks/{task_id}").respond(json=FIX["assurance_task"])
    api.get(f"/dna/data/api/v1/siteHealthSummaries/{BLDG}").respond(json=FIX["site_summary"])
    api.get("/dna/data/api/v1/assuranceIssues").respond(
        json={"response": FIX["issues"]["response"], "page": {"count": len(FIX["issues"]["response"])}}
    )
    api.post("/dna/data/api/v1/networkDevices/query").respond(json=FIX["devices_query"])
    api.post("/dna/data/api/v1/clients/query").respond(json={"response": []})
    api.get("/dna/intent/api/v1/issues").respond(json=FIX["intent_issues"])


async def test_site_health_report(api: respx.MockRouter) -> None:
    mock_report(api)
    out = await call("catc_site_health_report", {"site": BLDG, "hours": 2})
    assert out["site"] == "Global/mcp-test-lab/mcp-test-bldg"
    assert out["now"]["devices"] == 2 and "devices_healthy_pct" in out["now"]
    assert out["trend"]["network_devices_healthy"]["min"] == 100 and out["trend"]["issue_bursts"]
    assert {d["device"] for d in out["problem_devices"]} == {"r1.mcp.lab", "r2.mcp.lab"}
    assert out["problem_clients"] == "none in the window" and out["issues"]["in_window"] >= 2
    assert out["ai_insights"]["status"] == "no_ai_issues"
    assert "issues raised in" in out["verdict"] and "worst device" in out["verdict"]


async def test_site_health_report_marks_a_failed_section(api: respx.MockRouter) -> None:
    mock_report(api)
    api.post("/dna/data/api/v1/networkDevices/query").respond(500, json={"message": "boom"})
    out = await call("catc_site_health_report", {"site": BLDG, "hours": 2})
    assert "unavailable" in out["problem_devices"] and out["trend"]["network_devices_healthy"]
