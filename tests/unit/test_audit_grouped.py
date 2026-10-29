"""D62: catc_list_audit_logs(grouped=True) from audit-log/parent-records and audit-log/summary."""

import time
from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client
from fastmcp.exceptions import ToolError

from catc_mcp.server import create_server

from .conftest import make_settings
from .test_read_tools import call

NOW = int(time.time() * 1000)
PARENTS = "/dna/data/api/v1/event/event-series/audit-log/parent-records"
SUMMARY = "/dna/data/api/v1/event/event-series/audit-log/summary"
CHILDREN = "/dna/data/api/v1/event/event-series/audit-logs"


def parent(i: int, *, children: int, user: str = "admin", **kw: Any) -> dict[str, Any]:
    """A parent record shaped like the 3.2.2 spec (and a live 3.2.2 capture)."""
    return {
        "version": "1.0.0",
        "instanceId": f"p{i}",
        "eventId": "AUDIT_LOG_EVENT",
        "namespace": "AUDIT_LOG",
        "name": "AUDIT_LOG",
        "description": f"Provision request #{i}",
        "type": "AUDIT_LOG",
        "category": "INFO",
        "domain": "Audit",
        "severity": 1,
        "source": "NA",
        "timestamp": NOW - i * 1000,
        "userId": user,
        "parentInstanceId": None,
        "network": {"siteId": None, "deviceId": None},
        "childCount": children,
        **kw,
    }


def summary(request: httpx.Request) -> httpx.Response:
    if request.url.params.get("isParentOnly") == "true":
        return httpx.Response(200, json=[{"count": 2, "minTimestamp": NOW - 5000, "maxTimestamp": NOW}])
    return httpx.Response(200, json=[{"count": 9, "minTimestamp": NOW - 5000, "maxTimestamp": NOW}])


async def test_grouped_rows_and_summary(api: respx.MockRouter) -> None:
    parents = api.get(PARENTS).respond(
        json=[
            parent(0, children=7, network={"deviceId": "192.0.2.11"}),
            parent(1, children=0, user="op", category="TASK_FAILURE", severity=4),
        ]
    )
    summ = api.get(SUMMARY).mock(side_effect=summary)
    api.get("/dna/intent/api/v1/network-device").respond(
        json={"response": [{"managementIpAddress": "192.0.2.11", "hostname": "edge-1"}]}
    )
    children = api.get(CHILDREN)
    out = await call("catc_list_audit_logs", {"grouped": True, "response_format": "json"})
    rows = out["results"]
    assert [(r["id"], r["user"], r["children"]) for r in rows] == [("p0", "admin", 7), ("p1", "op", 0)]
    assert rows[0]["device"] == "edge-1" and rows[0]["what"] == "Provision request #0"
    assert rows[1]["category"] == "TASK_FAILURE" and rows[1]["severity"] == 4
    s = out["summary"]
    assert (
        s["records"] == 9 and s["actions"] == 2 and s["first"].startswith("20") and s["last"].startswith("20")
    )
    assert parents.called and summ.call_count == 2 and not children.called


async def test_grouped_passes_window_and_filters(api: respx.MockRouter) -> None:
    parents = api.get(PARENTS).respond(json=[])
    summ = api.get(SUMMARY).mock(side_effect=summary)
    before = int(time.time() * 1000)
    await call(
        "catc_list_audit_logs",
        {
            "grouped": True,
            "hours": 2,
            "user": "admin",
            "category": "ERROR",
            "text": "provision",
            "include_system": True,
            "limit": 10,
            "offset": 20,
            "response_format": "json",
        },
    )
    q = parents.calls.last.request.url.params
    start, end = int(q["startTime"]), int(q["endTime"])
    assert end - start == 2 * 3600 * 1000 and before <= end <= int(time.time() * 1000)
    assert q["userId"] == "admin" and q["category"] == "ERROR" and q["description"] == "provision"
    assert q["isSystemEvents"] == "true" and q["offset"] == "20" and q["limit"] == "10"
    for c in summ.calls:
        sq = c.request.url.params
        assert sq["startTime"] == str(start) and sq["endTime"] == str(end) and sq["userId"] == "admin"
        assert "limit" not in sq and "offset" not in sq
    assert sorted(c.request.url.params.get("isParentOnly", "-") for c in summ.calls) == ["-", "true"]


async def test_grouped_empty_window(api: respx.MockRouter) -> None:
    api.get(PARENTS).respond(json=[])
    api.get(SUMMARY).respond(json=[{"count": 0}])
    out = await call("catc_list_audit_logs", {"grouped": True, "response_format": "json"})
    assert out["results"] == [] and out["summary"] == {"records": 0, "actions": 0}
    md = await call("catc_list_audit_logs", {"grouped": True})
    assert "summary" in str(md)


async def test_grouped_summary_failure_keeps_rows(api: respx.MockRouter) -> None:
    api.get(PARENTS).respond(json=[parent(0, children=3)])
    api.get(SUMMARY).respond(500, json={"message": "boom"})
    out = await call("catc_list_audit_logs", {"grouped": True, "response_format": "json"})
    assert out["results"][0]["children"] == 3 and "error" in out["summary"]


@pytest.mark.parametrize("extra", [{"device": "edge-1"}, {"site": "Global/A"}, {"changes_only": True}])
async def test_grouped_rejects_scoped_filters(api: respx.MockRouter, extra: dict[str, Any]) -> None:
    parents = api.get(PARENTS).respond(json=[])
    async with Client(create_server(make_settings())) as c:
        with pytest.raises(ToolError, match="grouped=true"):
            await c.call_tool("catc_list_audit_logs", {"grouped": True, **extra})
    assert not parents.called


async def test_default_unchanged(api: respx.MockRouter) -> None:
    parents = api.get(PARENTS).respond(json=[])
    children = api.get(CHILDREN).respond(json=[{"instanceId": "a1", "description": "x", "timestamp": NOW}])
    out = await call("catc_list_audit_logs", {"response_format": "json"})
    assert [r["id"] for r in out["results"]] == ["a1"] and "summary" not in out
    assert children.called and not parents.called
