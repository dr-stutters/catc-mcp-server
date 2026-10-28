"""catc_write_memory (D65) over POST network-device-config/write-memory, then the per-device results from
GET network-device-config/task?parentTaskId= (respx; payloads shaped from the 3.2.2 spec: deviceId list in,
taskId out; per-device taskStatus / failureMessage / errorCode / taskType COPY_RUNNING_TO_STARTUP)."""

import json
from typing import Any

import httpx
import respx

from .test_read_tools import DEVICE
from .test_safety import DEV2, preview
from .test_write_tools import preview_then_apply, task_ok

WRITE = "/dna/intent/api/v1/network-device-config/write-memory"
CONFIG_TASK = "/dna/intent/api/v1/network-device-config/task"


def mock_inventory(api: respx.MockRouter, devices: list[dict[str, Any]]) -> None:
    def query(request: httpx.Request) -> httpx.Response:
        ip = request.url.params.get("managementIpAddress")
        return httpx.Response(200, json={"response": [d for d in devices if d["managementIpAddress"] == ip]})

    api.get("/dna/intent/api/v1/network-device").mock(side_effect=query)


def config_row(dev: dict[str, Any], status: str = "SUCCESS", **extra: Any) -> dict[str, Any]:
    return {
        "deviceId": dev["id"],
        "deviceIpAddress": dev["managementIpAddress"],
        "hostName": dev["hostname"],
        "parentTaskId": "wm1",
        "taskId": f"child-{dev['managementIpAddress']}",
        "taskStatus": status,
        "taskType": "COPY_RUNNING_TO_STARTUP",
        "startTime": 1761600000000,
        "completionTime": 1761600004000,
        **extra,
    }


def mock_write(api: respx.MockRouter, rows: list[list[dict[str, Any]]]) -> tuple[respx.Route, respx.Route]:
    post = api.post(WRITE).respond(
        202, json={"response": {"taskId": "wm1", "url": "/api/v1/task/wm1"}, "version": "1.0"}
    )
    task_ok(api, "wm1", data="", progress="write memory")
    tasks = api.get(CONFIG_TASK).mock(
        side_effect=[httpx.Response(200, json={"response": r, "version": "1.0"}) for r in rows]
    )
    return post, tasks


async def test_preview_then_apply_per_device_success(api: respx.MockRouter) -> None:
    mock_inventory(api, [DEVICE, DEV2])
    post, tasks = mock_write(api, [[config_row(DEVICE), config_row(DEV2)]])
    out, done = await preview_then_apply("catc_write_memory", {"devices": ["10.0.0.11", "10.0.0.12"]})
    assert out["status"] == "preview" and out["blast_radius"] == 2  # write tier: no dangerous needed
    assert out["action"] == "Write memory (running -> startup config) on 2 device(s)"
    assert out["preview"]["body"] == {"deviceId": [DEVICE["id"], DEV2["id"]]}
    assert "warning" not in out["preview"]
    assert post.call_count == 1  # only the apply posted
    assert json.loads(post.calls.last.request.content) == {"deviceId": [DEVICE["id"], DEV2["id"]]}
    assert tasks.calls.last.request.url.params["parentTaskId"] == "wm1"
    res = done["result"]
    assert res["parent_task_id"] == "wm1" and res["saved"] == 2 and res["failed"] == 0
    assert res["devices"][0] == {
        "device": "edge-sw1.lab.local (10.0.0.11)",
        "saved": True,
        "status": "SUCCESS",
        "task_id": "child-10.0.0.11",
    }
    assert "next" not in res


async def test_per_device_failure_is_reported(api: respx.MockRouter) -> None:
    mock_inventory(api, [DEVICE, DEV2])
    failed = config_row(
        DEV2, "FAILURE", errorCode="NCSP10250", failureMessage="Device is unreachable", detailMessage="ssh"
    )
    mock_write(api, [[config_row(DEVICE), failed]])
    _, done = await preview_then_apply("catc_write_memory", {"devices": ["10.0.0.11", "10.0.0.12"]})
    res = done["result"]
    assert res["saved"] == 1 and res["failed"] == 1
    row = res["devices"][1]
    assert row["saved"] is False and row["error"] == "Device is unreachable" and row["detail"] == "ssh"
    assert "catc_compare_device_configs(compare='startup')" in res["next"]


async def test_waits_for_running_rows(api: respx.MockRouter) -> None:
    mock_inventory(api, [DEVICE])
    running = config_row(DEVICE, "IN_PROGRESS", completionTime=None)
    _, tasks = mock_write(api, [[], [running], [config_row(DEVICE)]])
    _, done = await preview_then_apply("catc_write_memory", {"devices": ["10.0.0.11"]})
    assert tasks.call_count == 3 and done["result"]["saved"] == 1


async def test_device_without_a_result(api: respx.MockRouter) -> None:
    mock_inventory(api, [DEVICE, DEV2])
    mock_write(api, [[config_row(DEVICE)]])
    _, done = await preview_then_apply("catc_write_memory", {"devices": ["10.0.0.11", "10.0.0.12"]})
    row = done["result"]["devices"][1]
    assert row["saved"] is False and "no result" in row["error"]


async def test_failed_parent_task_still_reads_devices(api: respx.MockRouter) -> None:
    mock_inventory(api, [DEVICE])
    api.post(WRITE).respond(202, json={"response": {"taskId": "wm1"}, "version": "1.0"})
    api.get("/dna/intent/api/v1/task/wm1").respond(
        json={"response": {"isError": True, "failureReason": "1 of 1 failed", "endTime": 1}}
    )
    api.get(CONFIG_TASK).respond(
        json={"response": [config_row(DEVICE, "FAILURE", failureMessage="Startup config is locked")]}
    )
    _, done = await preview_then_apply("catc_write_memory", {"devices": ["10.0.0.11"]})
    res = done["result"]
    assert res["failed"] == 1 and res["devices"][0]["error"] == "Startup config is locked"
    assert "1 of 1 failed" in res["note"]


async def test_unreachable_device_is_named(api: respx.MockRouter) -> None:
    mock_inventory(api, [{**DEVICE, "reachabilityStatus": "Unreachable"}])
    out = await preview("catc_write_memory", {"devices": ["10.0.0.11"]})
    assert out["status"] == "preview" and "edge-sw1.lab.local (10.0.0.11)" in out["preview"]["warning"]


async def test_device_limit(api: respx.MockRouter) -> None:
    mock_inventory(api, [DEVICE, DEV2])
    out = await preview(
        "catc_write_memory", {"devices": ["10.0.0.11", "10.0.0.12"]}, max_devices_per_change=1
    )
    assert out["status"] == "blocked" and "CATC_MAX_DEVICES_PER_CHANGE=1" in " ".join(out["blockers"])


async def test_hidden_when_read_only(api: respx.MockRouter) -> None:
    from fastmcp import Client

    from catc_mcp.server import create_server

    from .conftest import make_settings

    async with Client(create_server(make_settings())) as c:
        assert "catc_write_memory" not in {t.name for t in await c.list_tools()}
