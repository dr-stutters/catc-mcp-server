"""D2: catc_list_event_notifications, catc_recent_activity and the audit-log device filter."""

import time
from typing import Any

import httpx
import respx

from catc_mcp.tools.activity import matches, merge

from .test_read_tools import DEV_ID, DEVICE, call, mock_device_lookup

NOW = int(time.time() * 1000)


def notif(
    i: int, *, type_: str = "NETWORK", ip: str | None = None, sev: int = 1, **kw: Any
) -> dict[str, Any]:
    details = {"managementIpAddr": ip} if ip else {}
    return {
        "instanceId": f"n{i}",
        "eventId": "NETWORK-X",
        "name": f"notif {i}",
        "type": type_,
        "category": "ALERT",
        "domain": "Connectivity",
        "severity": sev,
        "timestamp": NOW - i * 1000,
        "details": details,
        **kw,
    }


def test_matches_ip_boundary() -> None:
    e = {"details": {"managementIpAddr": "10.0.0.110"}}
    assert not matches(e, ["10.0.0.11"])
    assert matches({"details": {"managementIpAddr": "10.0.0.11"}}, ["10.0.0.11"])
    assert matches({"description": "drift on 10.0.0.11, ok"}, ["10.0.0.11"])
    assert matches(
        {"details": {"_key": "NetworkDevice:abc:edge-sw1.lab.local:Global"}}, ["edge-sw1.lab.local"]
    )


def test_merge_newest_first_and_limit() -> None:
    rows = {
        "issue": [{"what": "i", "_ms": 300}],
        "event": [{"what": "e1", "_ms": 500}, {"what": "e2", "_ms": 100}],
        "audit": [{"what": "a", "_ms": 400}],
    }
    out = merge(rows, 3)
    assert [r["what"] for r in out] == ["e1", "a", "i"]
    assert all("_ms" not in r for r in out)


async def test_notifications_hide_audit_and_filter_device(api: respx.MockRouter) -> None:
    mock_device_lookup(api)
    items = [
        notif(1, ip="10.0.0.11"),
        notif(2, type_="AUDIT_LOG", ip="10.0.0.11"),
        notif(3, ip="10.0.0.12"),
        notif(4, ip="10.0.0.11", sev=5),
    ]
    route = api.get("/dna/intent/api/v1/event/event-series").respond(json=items)
    out = await call(
        "catc_list_event_notifications",
        {"device": "10.0.0.11", "severity": 2, "hours": 2, "response_format": "json"},
    )
    assert [r["id"] for r in out["results"]] == ["n1"]
    q = route.calls.last.request.url.params
    assert q["offset"] == "0" and int(q["endTime"]) - int(q["startTime"]) == 2 * 3600 * 1000
    assert "type" not in q


async def test_notifications_type_passed_through(api: respx.MockRouter) -> None:
    route = api.get("/dna/intent/api/v1/event/event-series").respond(json=[notif(1, type_="AUDIT_LOG")])
    out = await call(
        "catc_list_event_notifications", {"notification_type": "AUDIT_LOG", "response_format": "json"}
    )
    assert route.calls.last.request.url.params["type"] == "AUDIT_LOG"
    assert out["returned"] == 1


async def test_recent_activity_merges_and_survives_a_failing_source(api: respx.MockRouter) -> None:
    mock_device_lookup(api)
    issues = api.get("/dna/data/api/v1/assuranceIssues").respond(
        json={
            "response": [
                {
                    "issueId": "iss1",
                    "summary": "Interface down",
                    "priority": "P2",
                    "mostRecentOccurredTime": NOW - 3000,
                }
            ],
            "page": {"count": 1},
        }
    )
    events = api.get("/dna/data/api/v1/assuranceEvents").respond(
        json={
            "response": [
                {
                    "id": "ev1",
                    "details": "%LINK-3-UPDOWN",
                    "timestamp": NOW - 1000,
                    "networkDeviceName": "edge-sw1",
                }
            ],
            "page": {"count": 1},
        }
    )
    api.get("/dna/intent/api/v1/event/event-series").respond(
        json=[notif(2, ip="10.0.0.11"), notif(9, ip="10.9.9.9")]
    )
    api.get("/dna/data/api/v1/event/event-series/audit-logs").respond(500, json={"message": "boom"})
    out = await call("catc_recent_activity", {"device": "edge-sw1", "hours": 1, "response_format": "json"})
    assert [r["source"] for r in out["results"]] == ["event", "notification", "issue"]
    assert out["counts"] == {"issue": 1, "event": 1, "notification": 1}
    assert "audit" in out["errors"]
    assert issues.calls.last.request.url.params["networkDeviceId"] == DEV_ID
    ev = events.calls.last.request.url.params
    assert ev["deviceFamily"] == DEVICE["family"] and ev["networkDeviceId"] == DEV_ID


async def test_recent_activity_sources_and_limit(api: respx.MockRouter) -> None:
    api.get("/dna/intent/api/v1/event/event-series").respond(json=[notif(i) for i in range(5)])
    audit = api.get("/dna/data/api/v1/event/event-series/audit-logs")
    out = await call(
        "catc_recent_activity", {"sources": ["notification"], "limit": 2, "response_format": "json"}
    )
    assert out["returned"] == 2 and out["counts"] == {"notification": 5}
    assert "note" in out and not audit.called


async def test_audit_logs_device_by_name_and_text(api: respx.MockRouter) -> None:
    mock_device_lookup(api)

    def audit(request: httpx.Request) -> httpx.Response:
        if request.url.params.get("deviceId"):
            return httpx.Response(200, json=[{"instanceId": "a1", "description": "tagged", "timestamp": NOW}])
        return httpx.Response(
            200,
            json=[
                {"instanceId": "a1", "description": "tagged", "timestamp": NOW},
                {
                    "instanceId": "a2",
                    "description": "Provisioning done for [10.0.0.11].",
                    "timestamp": NOW - 5,
                },
                {
                    "instanceId": "a3",
                    "description": "Provisioning done for [10.0.0.110].",
                    "timestamp": NOW - 9,
                },
                {"instanceId": "a4", "description": "unrelated", "timestamp": NOW - 1},
            ],
        )

    route = api.get("/dna/data/api/v1/event/event-series/audit-logs").mock(side_effect=audit)
    out = await call("catc_list_audit_logs", {"device": "10.0.0.11", "response_format": "json"})
    assert any(c.request.url.params.get("deviceId") == DEV_ID for c in route.calls)
    assert [r["instanceId"] for r in out["results"]] == ["a1", "a2"]
