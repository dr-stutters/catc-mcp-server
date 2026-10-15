"""D2: catc_list_event_notifications, catc_recent_activity and the audit-log device filter."""

import time
from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client
from fastmcp.exceptions import ToolError

from catc_mcp.server import create_server
from catc_mcp.tools.activity import in_scope, merge

from .conftest import make_settings
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


def test_device_matcher_boundaries() -> None:
    dev = {"managementIpAddress": "10.0.0.11", "hostname": "r1", "id": "dev-1"}

    def hit(text: str) -> bool:
        return in_scope({"description": text}, dev, None)

    assert hit("drift on 10.0.0.11, ok") and hit("Provisioning done for 10.0.0.11.")
    assert hit("device [10.0.0.11]") and hit("NetworkDevice:x:r1:Global")
    assert not hit("10.0.0.110") and not hit("110.0.0.11") and not hit("10.0.0.11.5")
    assert not hit("r10 is down") and not hit("mirror1") and not hit("r1-b")


def test_site_matcher_children_not_siblings() -> None:
    site = {"nameHierarchy": "Global/A", "id": "site-a"}

    def hit(text: str) -> bool:
        return in_scope({"description": text}, None, site)

    assert hit("The site Global/A was created.") and hit("key:Global/A/B:x") and hit("groupuuid = site-a")
    assert not hit("Global/A2") and not hit("Global/AB/x")
    assert in_scope({"description": "anything"}, None, {"nameHierarchy": "Global", "id": "g"})


def test_device_and_site_are_and() -> None:
    dev = {"managementIpAddress": "10.0.0.11", "hostname": "r1", "id": "dev-1"}
    site = {"nameHierarchy": "Global/A", "id": "site-a"}
    assert in_scope({"description": "r1 at Global/A"}, dev, site)
    assert not in_scope({"description": "r1 at Global/B"}, dev, site)
    assert not in_scope({"description": "r2 at Global/A"}, dev, site)


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
    assert [r["id"] for r in out["results"]] == ["a1", "a2"]


async def test_recent_activity_all_sources_fail(api: respx.MockRouter) -> None:
    api.get("/dna/intent/api/v1/event/event-series").respond(500, json={})
    api.get("/dna/data/api/v1/event/event-series/audit-logs").respond(500, json={})
    async with Client(create_server(make_settings())) as c:
        with pytest.raises(ToolError, match="Every activity source failed"):
            await c.call_tool("catc_recent_activity", {"sources": ["notification", "audit"]})


async def test_audit_scoped_paging(api: respx.MockRouter) -> None:
    mock_device_lookup(api)
    rows = [
        {"instanceId": f"a{i}", "description": f"job on 10.0.0.11 #{i}", "timestamp": NOW - i}
        for i in range(7)
    ]

    def audit(request: httpx.Request) -> httpx.Response:
        q = request.url.params
        if q.get("deviceId"):
            return httpx.Response(200, json=[])
        off, n = int(q["offset"]), int(q["limit"])
        return httpx.Response(200, json=rows[off : off + n])

    api.get("/dna/data/api/v1/event/event-series/audit-logs").mock(side_effect=audit)
    first = await call("catc_list_audit_logs", {"device": "10.0.0.11", "limit": 3, "response_format": "json"})
    assert [r["id"] for r in first["results"]] == ["a0", "a1", "a2"] and first["next_offset"] == 3
    last = await call(
        "catc_list_audit_logs", {"device": "10.0.0.11", "limit": 5, "offset": 5, "response_format": "json"}
    )
    assert [r["id"] for r in last["results"]] == ["a5", "a6"] and "next_offset" not in last
    assert "note" not in last


async def test_audit_changes_only_device_names_and_times(api: respx.MockRouter) -> None:
    mock_device_lookup(api)
    rows = [
        {
            "instanceId": "c1",
            "description": 'Going to deploy template "ntp"',
            "timestamp": NOW,
            "userId": "op",
            "network": {"deviceId": "10.0.0.11"},
            "category": "INFO",
            "source": "10.1.1.1",
        },
        {
            "instanceId": "n1",
            "description": "DNS Settings not applicable for the device:10.0.0.11[x]",
            "timestamp": NOW - 1,
            "userId": "op",
        },
        {
            "instanceId": "n2",
            "description": "LOGIN_USER_EVENT: 'op' logged in successfully.",
            "timestamp": NOW - 2,
            "userId": "op",
        },
        {
            "instanceId": "n3",
            "description": "Sending notification to dna-common-service for x",
            "timestamp": NOW - 3,
            "userId": "SYSTEM-USER",
        },
    ]
    api.get("/dna/data/api/v1/event/event-series/audit-logs").mock(
        side_effect=lambda r: httpx.Response(
            200, json=rows[int(r.url.params["offset"]) :][: int(r.url.params["limit"])]
        )
    )
    out = await call("catc_list_audit_logs", {"changes_only": True, "response_format": "json"})
    assert [r["id"] for r in out["results"]] == ["c1"] and "3 " in out["left_out"]
    row = out["results"][0]
    assert (
        row["device"] == DEVICE["hostname"] and row["time"].startswith("20") and row["source"] == "10.1.1.1"
    )
    assert "category" not in row  # INFO is the default and left out
    every = await call("catc_list_audit_logs", {"response_format": "json"})
    assert len(every["results"]) == 4


async def test_recent_activity_hides_internal_audit(api: respx.MockRouter) -> None:
    api.get("/dna/data/api/v1/event/event-series/audit-logs").respond(
        json=[
            {"instanceId": "c1", "description": "Successfully deployed template ntp.", "timestamp": NOW},
            {
                "instanceId": "n1",
                "description": "Finished executing DNS Settings flow for the device:x",
                "timestamp": NOW - 1,
            },
        ]
    )
    out = await call("catc_recent_activity", {"sources": ["audit"], "response_format": "json"})
    assert [r["id"] for r in out["results"]] == ["c1"]
    assert "1 audit records left out" in out["partial"]["audit"]


@pytest.mark.parametrize(
    ("text", "kind"),
    [
        ("DNS Settings not applicable for the device:198.18.128.153[x]", "internal"),
        ("Finished executing WSA Configuration flow for the device:198.18.128.153[x]", "internal"),
        ("Sending notification to dna-common-service for checking required subscriptions", "internal"),
        ("Cisco Catalyst Center 198.18.128.11 is reachable from device 198.18.128.153", "internal"),
        (
            "Provisioning complete notification received for device [1.1.1.1]. Resync will begin shortly.",
            "internal",
        ),
        ("LOGIN_USER_EVENT: 'mitch' logged in successfully.", "read"),
        ("Report 'mcp-test-inv-report' downloaded", "read"),
        ("custom resource role mcp-catc-rw retrieval succeeded for tenant", "read"),
        ("The request to run read-only commands in devices [198.18.128.153] was received", "read"),
        # real changes must stay visible
        ('Going to deploy template "mcp-test-ntp"', "change"),
        ("Successfully deployed template mcp-test-ntp.", "change"),
        ("Request to delete device 198.18.128.175 succeeded", "change"),
        ("The site Global/mcp-test-lab/mcp-test-fabric was deleted.", "change"),
        ("LOGIN_USER_EVENT: 'mitch' failed to log in.", "change"),
        ("Image cat9k.bin downloaded to device 10.0.0.1", "change"),
        ("Resync request for device 10.0.0.1 was received", "change"),
        ("Updating siteHierarchyId '[/a/b]' for device 10.0.0.1", "change"),
    ],
)
def test_audit_kind(text: str, kind: str) -> None:
    from catc_mcp.tools.activity import audit_kind

    assert audit_kind({"description": text}) == kind
