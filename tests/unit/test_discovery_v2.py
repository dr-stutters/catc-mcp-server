"""D58: discovery v2 (`discoverys/*`) reads, server-side paging and catc_stop_discovery (respx).

Payloads follow the 3.2.2 lab's live answers (2026-10-29, addresses swapped for documentation ones):
GET discoverys/jobs/summarys -> {"response": [{"id": "94", "name": ...,
"discoveryTypeDetails": {"type": "RANGE", "range": [{"ipAddressStart": ..., "ipAddressEnd": ...}]},
"jobId": "1793009614513", "status": "COMPLETED",
"startTime": ..., "endTime": ..., "lastUpdatedDate": ..., "reachableDevices": 2}], "version": "1.0"};
GET discoverys/count and .../discoveredNetworkDevices/count -> {"response": {"count": n}, "version": "1.0"};
a discovered device's validationStatuses say "NOT-PROVIDED" (hyphen) where the spec says NOT_PROVIDED.
"""

import json
from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client
from fastmcp.exceptions import ToolError

from catc_mcp.server import create_server
from catc_mcp.tools.discovery import count_of, device_row, job_row, targets_text, to_iso

from .conftest import make_settings
from .test_read_tools import call
from .test_write_tools import run, task_ok

V2 = "/dna/intent/api/v1/discoverys"
DISC_ID, JOB_ID = "94", "1793009614513"
JOB_PATH = f"{V2}/{DISC_ID}/jobs/{JOB_ID}"


def summary(i: int = 0, *, status: str = "COMPLETED", name: str | None = None) -> dict[str, Any]:
    return {
        "id": str(DISC_ID if i == 0 else 1000 + i),
        "name": name or ("mcp-disc" if i == 0 else f"mcp-disc-{i}"),
        "discoveryTypeDetails": {
            "type": "RANGE",
            "range": [{"ipAddressStart": "192.0.2.46", "ipAddressEnd": "192.0.2.47"}],
        },
        "jobId": JOB_ID if i == 0 else str(1793000000000 + i),
        "status": status,
        "startTime": 1793009614525,
        "endTime": 1793009621025 if status == "COMPLETED" else None,
        "lastUpdatedDate": 1793009609496,
        "reachableDevices": 2,
    }


def device(i: int) -> dict[str, Any]:
    return {
        "id": f"00000000-0000-0000-0000-{i:012d}",
        "managementIpAddress": f"198.51.100.{i % 250 + 1}",
        "hostname": f"sw{i}.example.com",
        "discoveryStatus": "SUCCESS",
        "status": "MANAGED",
        "reachabilityStatus": "REACHABLE",
        "validationStatuses": {
            "ping": "SUCCESS",
            "cli": "SUCCESS",
            "snmp": "SUCCESS",
            "http": "NOT-PROVIDED",
            "netconf": "SUCCESS",
        },
    }


def paged(rows: list[dict[str, Any]]) -> Any:
    """A v2 list handler: 1-based offset, limit, and the name/id filters."""

    def handler(request: httpx.Request) -> httpx.Response:
        q = request.url.params
        hit = rows
        if "id" in q:
            hit = [r for r in hit if r["id"] in q.get_list("id")]
        if "name" in q:
            hit = [r for r in hit if q["name"].lower() in r["name"].lower()]
        if "reachabilityStatus" in q:
            hit = [r for r in hit if r.get("reachabilityStatus") == q["reachabilityStatus"]]
        start = int(q.get("offset", 1)) - 1
        n = int(q.get("limit", 500))
        return httpx.Response(200, json={"response": hit[start : start + n], "version": "1.0"})

    return handler


def counted(rows: list[dict[str, Any]], key: str = "name") -> Any:
    def handler(request: httpx.Request) -> httpx.Response:
        q = request.url.params
        hit = [r for r in rows if key not in q or q[key].lower() in str(r.get(key, "")).lower()]
        return httpx.Response(200, json={"response": {"count": len(hit)}, "version": "1.0"})

    return handler


def mock_summaries(api: respx.MockRouter, rows: list[dict[str, Any]]) -> respx.Route:
    api.get(f"{V2}/count").mock(side_effect=counted(rows))
    return api.get(f"{V2}/jobs/summarys").mock(side_effect=paged(rows))


# --- pure helpers ---------------------------------------------------------------------------------


def test_helpers() -> None:
    assert count_of({"count": 15}) == 15 and count_of(7) == 7
    assert count_of(None) is None and count_of({"count": True}) is None
    assert to_iso(1793009614525) == "2026-10-26T10:13:34Z" and to_iso(None) is None and to_iso(-1) is None
    assert targets_text({"type": "RANGE", "range": [{"ipAddressStart": "a", "ipAddressEnd": "b"}]}) == "a-b"
    assert targets_text({"type": "CIDR", "cidrAddress": {"cidrPrefix": "192.0.2.0", "cidrSuffix": 24}}) == (
        "192.0.2.0/24"
    )
    assert (
        targets_text({"type": "CDP", "ipAddress": "192.0.2.1", "hopCount": 2}) == "192.0.2.1 (seed, 2 hop(s))"
    )
    assert targets_text({"type": "SINGLE", "ipAddress": "192.0.2.9"}) == "192.0.2.9"
    assert targets_text(None) is None
    row = job_row(summary())
    assert row["targets"] == "192.0.2.46-192.0.2.47" and row["job_id"] == JOB_ID and row["type"] == "RANGE"
    d = device_row(device(1))
    assert (
        d["http"] == "NOT_PROVIDED"
        and d["inventoryStatus"] == "MANAGED"
        and "reachabilityFailureReason" not in d
    )


# --- catc_list_discoveries ------------------------------------------------------------------------


async def test_list_discoveries_pages_on_the_server_past_500(api: respx.MockRouter) -> None:
    rows = [summary(i) for i in range(620)]
    route = mock_summaries(api, rows)
    out = await call("catc_list_discoveries", {"offset": 600, "limit": 50, "response_format": "json"})
    q = route.calls.last.request.url.params
    assert q["offset"] == "601" and q["limit"] == "50"
    assert out["total"] == 620 and out["returned"] == 20 and out.get("next_offset") is None
    assert out["results"][0]["name"] == "mcp-disc-600"
    first = await call("catc_list_discoveries", {"limit": 100, "response_format": "json"})
    assert route.calls.last.request.url.params["offset"] == "1"
    assert first["returned"] == 100 and first["next_offset"] == 100


async def test_list_discoveries_name_filter_and_count(api: respx.MockRouter) -> None:
    rows = [summary(0), summary(1, name="other"), summary(2, status="RUNNING")]
    route = mock_summaries(api, rows)
    out = await call("catc_list_discoveries", {"name": "mcp", "response_format": "json"})
    assert route.calls.last.request.url.params["name"] == "mcp"
    assert out["total"] == 2 and [r["name"] for r in out["results"]] == ["mcp-disc", "mcp-disc-2"]
    assert out["results"][1]["status"] == "RUNNING" and "ended" not in out["results"][1]


# --- catc_list_discovery_devices ------------------------------------------------------------------


async def test_discovery_devices_latest_job_paged(api: respx.MockRouter) -> None:
    mock_summaries(api, [summary()])
    devs = [device(i) for i in range(700)]
    route = api.get(f"{JOB_PATH}/discoveredNetworkDevices").mock(side_effect=paged(devs))
    api.get(f"{JOB_PATH}/discoveredNetworkDevices/count").respond(
        json={"response": {"count": 700}, "version": "1.0"}
    )
    out = await call(
        "catc_list_discovery_devices",
        {"discovery": "mcp-disc", "offset": 550, "limit": 100, "response_format": "json"},
    )
    q = route.calls.last.request.url.params
    assert q["offset"] == "551" and q["limit"] == "100"
    assert out["total"] == 700 and out["returned"] == 100 and out["next_offset"] == 650
    assert out["results"][0]["hostname"] == "sw550.example.com"
    assert out["discovery"] == "mcp-disc" and out["job_id"] == JOB_ID and out["job_status"] == "COMPLETED"


async def test_discovery_devices_by_id_job_and_reachability(api: respx.MockRouter) -> None:
    summaries = mock_summaries(api, [summary()])
    other_job = "1792000000000"
    api.get(f"{V2}/{DISC_ID}/jobs/{other_job}").respond(
        json={"response": {**summary(), "jobId": other_job, "status": "TERMINATED"}, "version": "1.0"}
    )
    path = f"{V2}/{DISC_ID}/jobs/{other_job}/discoveredNetworkDevices"
    devs = [
        device(1),
        {**device(2), "reachabilityStatus": "UNREACHABLE", "reachabilityFailureReason": "SSH timeout"},
    ]
    route = api.get(path).mock(side_effect=paged(devs))
    count = api.get(f"{path}/count").mock(side_effect=counted(devs, "reachabilityStatus"))
    out = await call(
        "catc_list_discovery_devices",
        {"discovery": DISC_ID, "job": other_job, "reachability": "UNREACHABLE", "response_format": "json"},
    )
    assert summaries.calls[0].request.url.params["id"] == DISC_ID
    assert route.calls.last.request.url.params["reachabilityStatus"] == "UNREACHABLE"
    assert count.calls.last.request.url.params["reachabilityStatus"] == "UNREACHABLE"
    assert out["total"] == 1 and out["results"][0]["reachabilityFailureReason"] == "SSH timeout"
    assert out["job_id"] == other_job and out["job_status"] == "TERMINATED"


async def test_discovery_devices_unknown_discovery(api: respx.MockRouter) -> None:
    mock_summaries(api, [summary(0), summary(1)])
    async with Client(create_server(make_settings())) as c:
        with pytest.raises(ToolError, match=r"No discovery 'mcp'.*similar: mcp-disc, mcp-disc-1"):
            await c.call_tool("catc_list_discovery_devices", {"discovery": "mcp"})


# --- catc_stop_discovery --------------------------------------------------------------------------


async def stop_flow(args: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any] | None]:
    async with Client(create_server(make_settings(mcp_enable_writes=True))) as c:
        preview = await run(c, "catc_stop_discovery", args)
        if preview.get("status") != "preview":
            return preview, None
        return preview, await run(c, "catc_stop_discovery", {**args, "confirm": preview["confirm"]})


async def test_stop_discovery_preview_then_confirm(api: respx.MockRouter) -> None:
    mock_summaries(api, [summary(status="RUNNING")])
    stop = api.post(f"{JOB_PATH}/stop").respond(
        202, json={"response": {"taskId": "t-stop", "url": "/api/v1/task/t-stop"}, "version": "1.0"}
    )
    task_ok(api, "t-stop", data="")
    api.get(JOB_PATH).respond(json={"response": {**summary(), "status": "TERMINATED"}, "version": "1.0"})
    preview, done = await stop_flow({"discovery": "mcp-disc"})
    assert preview["status"] == "preview"
    assert preview["action"] == f"Stop discovery mcp-disc (job {JOB_ID})"
    job = preview["preview"]["job"]
    assert job["status"] == "RUNNING" and job["targets"] == "192.0.2.46-192.0.2.47"
    assert preview["preview"]["path"] == f"{JOB_PATH}/stop"
    assert done is not None and stop.call_count == 1
    assert done["result"]["job_status"] == "TERMINATED" and done["result"]["job_id"] == JOB_ID


async def test_stop_discovery_refuses_a_job_that_is_not_running(api: respx.MockRouter) -> None:
    stop = api.post(f"{JOB_PATH}/stop")
    for status in ("COMPLETED", "TERMINATED", "QUEUED"):
        mock_summaries(api, [summary(status=status)])
        preview, done = await stop_flow({"discovery": "mcp-disc"})
        assert preview["status"] == "blocked" and done is None
        assert f"is {status}, not RUNNING" in preview["blockers"][0]
    assert not stop.called


async def test_stop_discovery_named_job(api: respx.MockRouter) -> None:
    mock_summaries(api, [summary(status="COMPLETED")])
    running = "1793009999999"
    api.get(f"{V2}/{DISC_ID}/jobs/{running}").respond(
        json={"response": {**summary(), "jobId": running, "status": "RUNNING"}, "version": "1.0"}
    )
    async with Client(create_server(make_settings(mcp_enable_writes=True))) as c:
        preview = await run(c, "catc_stop_discovery", {"discovery": "mcp-disc", "job": running})
    assert preview["status"] == "preview" and preview["preview"]["path"].endswith(f"/jobs/{running}/stop")


async def test_stop_discovery_is_write_tier(api: respx.MockRouter) -> None:
    async with Client(create_server(make_settings())) as c:
        assert "catc_stop_discovery" not in {t.name for t in await c.list_tools()}


# --- #319: several ranges go out as Multi Range -----------------------------------------------------


async def create_flow(
    api: respx.MockRouter, args: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Preview + confirm catc_create_discovery; returns (preview, result, POST body)."""
    api.get("/dna/intent/api/v1/globalCredentials").respond(
        json={"response": [{"id": "c1", "type": "CLI", "description": "lab", "username": "u"}]}
    )
    api.get("/dna/intent/api/v1/discovery/count").respond(json={"response": 0})
    post = api.post("/dna/intent/api/v1/discovery").respond(202, json={"response": {"taskId": "t-d"}})
    api.get("/dna/intent/api/v1/task/t-d").respond(json={"response": {"data": DISC_ID, "progress": DISC_ID}})
    async with Client(create_server(make_settings(mcp_enable_writes=True))) as c:
        preview = await run(c, "catc_create_discovery", args)
        assert preview["status"] == "preview"
        done = await run(c, "catc_create_discovery", {**args, "confirm": preview["confirm"]})
    return preview, done, json.loads(post.calls.last.request.content)


THREE = ["192.0.2.1-192.0.2.254", "198.51.100.1-198.51.100.254", "203.0.113.1-203.0.113.254"]


async def test_create_discovery_several_ranges_send_multi_range(api: respx.MockRouter) -> None:
    preview, done, sent = await create_flow(api, {"name": "mcp-disc", "ip_ranges": THREE})
    assert sent["discoveryType"] == "Multi Range"
    assert sent["ipAddressList"] == ",".join(THREE)
    assert preview["action"].startswith("Start Multi Range discovery mcp-disc on 192.0.2.1-")
    assert preview["preview"]["note"] == "3 ranges: sent as Multi Range"
    assert preview["preview"]["body"]["discoveryType"] == "Multi Range"
    assert done["status"] == "applied" and done["result"]["discovery_id"] == DISC_ID


async def test_create_discovery_comma_joined_ranges_count_too(api: respx.MockRouter) -> None:
    _, _, sent = await create_flow(api, {"name": "mcp-disc", "ip_ranges": [",".join(THREE[:2])]})
    assert sent["discoveryType"] == "Multi Range"


async def test_create_discovery_one_range_stays_range(api: respx.MockRouter) -> None:
    preview, _, sent = await create_flow(api, {"name": "mcp-disc", "ip_ranges": THREE[:1]})
    assert sent["discoveryType"] == "Range" and sent["ipAddressList"] == THREE[0]
    assert preview["action"].startswith("Start Range discovery") and "note" not in preview["preview"]


async def test_create_discovery_single_unchanged(api: respx.MockRouter) -> None:
    preview, _, sent = await create_flow(
        api, {"name": "mcp-disc", "ip_ranges": ["192.0.2.46"], "discovery_type": "Single"}
    )
    assert sent["discoveryType"] == "Range" and sent["ipAddressList"] == "192.0.2.46-192.0.2.46"
    assert preview["action"].startswith("Start Single discovery") and "note" not in preview["preview"]
