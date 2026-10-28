"""catc_apply_telemetry_settings (D122) over POST telemetrySettings/apply {deviceIds} (one request per
device), the preview reading each device's site (GET networkDevices/{id}/assignedToSite) and that site's
effective telemetry (GET sites/{id}/telemetrySettings?_inherited=true). Payloads from the 3.2.2 spec:
deviceIds in, taskId out; telemetry parts carry inheritedSiteId/inheritedSiteName when set on a parent
(shape checked against a live Global read 2026-10-28)."""

import json
from typing import Any

import httpx
import pytest
import respx
from fastmcp.exceptions import ToolError

from .test_read_tools import AREA, BLDG, DEVICE, GLOBAL
from .test_safety import DEV2, preview
from .test_write_tools import mock_sites, preview_then_apply, task_ok

APPLY = "/dna/intent/api/v1/telemetrySettings/apply"
TELEMETRY = {
    "applicationVisibility": {
        "collector": {"collectorType": "Builtin"},
        "enableOnWiredAccessDevices": False,
        "inheritedSiteId": GLOBAL["id"],
        "inheritedSiteName": "Global",
    },
    "wiredDataCollection": {"enableWiredDataCollection": False},
    "wirelessTelemetry": {"enableWirelessTelemetry": True},
    "snmpTraps": {
        "useBuiltinTrapServer": True,
        "inheritedSiteId": GLOBAL["id"],
        "inheritedSiteName": "Global",
    },
    "syslogs": {"useBuiltinSyslogServer": True, "externalSyslogServers": ["192.0.2.50"]},
}


def mock_inventory(api: respx.MockRouter, devices: list[dict[str, Any]]) -> None:
    def query(request: httpx.Request) -> httpx.Response:
        q = request.url.params
        if "id" in q:
            ids = q["id"].split(",")
            return httpx.Response(200, json={"response": [d for d in devices if d["id"] in ids]})
        ip = q.get("managementIpAddress")
        return httpx.Response(200, json={"response": [d for d in devices if d["managementIpAddress"] == ip]})

    api.get("/dna/intent/api/v1/network-device").mock(side_effect=query)


def mock_assigned(api: respx.MockRouter, devices: list[dict[str, Any]], site: dict[str, Any] = BLDG) -> None:
    for d in devices:
        api.get(f"/dna/intent/api/v1/networkDevices/{d['id']}/assignedToSite").respond(
            json={
                "response": {
                    "deviceId": d["id"],
                    "siteId": site["id"],
                    "siteNameHierarchy": site["nameHierarchy"],
                    "siteType": site["type"],
                },
                "version": "1.0",
            }
        )


def mock_telemetry(api: respx.MockRouter, site: dict[str, Any] = BLDG) -> respx.Route:
    return api.get(f"/dna/intent/api/v1/sites/{site['id']}/telemetrySettings").respond(
        json={"response": TELEMETRY, "version": "1.0"}
    )


def mock_apply(api: respx.MockRouter, tasks: dict[str, str]) -> respx.Route:
    """tasks: device id -> task id; each POST answers with that device's task."""

    def post(request: httpx.Request) -> httpx.Response:
        dev = json.loads(request.content)["deviceIds"][0]
        return httpx.Response(
            202,
            json={"response": {"taskId": tasks[dev], "url": f"/api/v1/task/{tasks[dev]}"}, "version": "1.0"},
        )

    return api.post(APPLY).mock(side_effect=post)


async def test_preview_then_apply_per_device(api: respx.MockRouter) -> None:
    mock_inventory(api, [DEVICE, DEV2])
    mock_assigned(api, [DEVICE, DEV2])
    tele = mock_telemetry(api)
    post = mock_apply(api, {DEVICE["id"]: "t1", DEV2["id"]: "t2"})
    task_ok(api, "t1", data="", progress="Telemetry settings updated")
    task_ok(api, "t2", data="", progress="Telemetry settings updated")
    out, done = await preview_then_apply(
        "catc_apply_telemetry_settings", {"devices": ["10.0.0.11", "10.0.0.12"]}
    )
    assert out["status"] == "preview" and out["blast_radius"] == 2  # write tier
    assert out["action"] == "Apply site telemetry settings to 2 device(s)"
    p = out["preview"]
    assert p["device_count"] == 2 and p["targets"] == {"by": "devices"}
    assert p["devices"][0] == {"device": "edge-sw1.lab.local (10.0.0.11)", "site": "Global/AU/SYD-1"}
    assert len(p["site_telemetry"]) == 1 and tele.call_count >= 1  # read once per site
    assert tele.calls.last.request.url.params["_inherited"] == "true"
    site = p["site_telemetry"][0]
    assert site["site"] == "Global/AU/SYD-1" and site["devices"] == 2
    t = site["telemetry"]
    assert t["syslogs"] == {
        "useBuiltinSyslogServer": True,
        "externalSyslogServers": ["192.0.2.50"],
        "source": "local",
    }
    assert t["snmpTraps"]["source"] == "inherited from Global" and "inheritedSiteId" not in t["snmpTraps"]
    assert "warning" not in p
    assert post.call_count == 2  # only the apply posted, one request per device
    bodies = sorted(json.loads(c.request.content)["deviceIds"][0] for c in post.calls)
    assert bodies == sorted([DEVICE["id"], DEV2["id"]])
    res = done["result"]
    assert res["applied"] == 2 and res["failed"] == 0 and "next" not in res
    assert res["devices"][0]["device"] == "edge-sw1.lab.local (10.0.0.11)"
    assert res["devices"][0]["applied"] is True and res["devices"][0]["task_id"] == "t1"
    assert res["verify"]["tool"] == "catc_run_show_commands"
    assert res["verify"]["devices"] == ["edge-sw1.lab.local", "edge-sw2"]
    assert "show logging | include Logging to" in res["verify"]["commands"]
    assert "show flow exporter" in res["verify"]["commands"]


async def test_task_failure_is_reported_per_device(api: respx.MockRouter) -> None:
    mock_inventory(api, [DEVICE, DEV2])
    mock_assigned(api, [DEVICE, DEV2])
    mock_telemetry(api)
    mock_apply(api, {DEVICE["id"]: "t1", DEV2["id"]: "t2"})
    task_ok(api, "t1", data="")
    api.get("/dna/intent/api/v1/task/t2").respond(
        json={"response": {"isError": True, "failureReason": "Device is unreachable", "endTime": 1}}
    )
    _, done = await preview_then_apply(
        "catc_apply_telemetry_settings", {"devices": ["10.0.0.11", "10.0.0.12"]}
    )
    res = done["result"]
    assert res["applied"] == 1 and res["failed"] == 1
    bad = res["devices"][1]
    assert bad["applied"] is False and "Device is unreachable" in bad["error"]
    assert res["verify"]["devices"] == ["edge-sw1.lab.local"]
    assert "catc_apply_telemetry_settings again" in res["next"]


async def test_device_limit_refuses_before_reading_sites(api: respx.MockRouter) -> None:
    mock_inventory(api, [DEVICE, DEV2])
    tele = mock_telemetry(api)
    out = await preview(
        "catc_apply_telemetry_settings", {"devices": ["10.0.0.11", "10.0.0.12"]}, max_devices_per_change=1
    )
    assert out["status"] == "blocked" and "CATC_MAX_DEVICES_PER_CHANGE=1" in " ".join(out["blockers"])
    assert tele.call_count == 0


async def test_unassigned_device_is_blocked(api: respx.MockRouter) -> None:
    mock_inventory(api, [DEVICE])
    api.get(f"/dna/intent/api/v1/networkDevices/{DEVICE['id']}/assignedToSite").respond(
        json={"response": {"deviceId": DEVICE["id"]}, "version": "1.0"}
    )
    out = await preview("catc_apply_telemetry_settings", {"devices": ["10.0.0.11"]})
    assert out["status"] == "blocked"
    assert (
        "Not assigned to a site" in out["blockers"][0] and "catc_assign_devices_to_site" in out["blockers"][0]
    )


async def test_site_target_and_unreachable_warning(api: respx.MockRouter) -> None:
    down = {**DEV2, "reachabilityStatus": "Unreachable"}
    mock_sites(api, [GLOBAL, AREA, BLDG])
    mock_inventory(api, [DEVICE, down])
    api.get("/dna/intent/api/v1/networkDevices/assignedToSite").mock(
        side_effect=lambda r: httpx.Response(
            200,
            json={
                "response": [{"deviceId": DEVICE["id"]}, {"deviceId": down["id"]}]
                if r.url.params.get("siteId") == BLDG["id"]
                else []
            },
        )
    )
    mock_assigned(api, [DEVICE, down])
    mock_telemetry(api)
    out = await preview("catc_apply_telemetry_settings", {"site": "Global/AU/SYD-1"})
    assert out["status"] == "preview" and out["blast_radius"] == 2
    assert out["preview"]["targets"]["by"] == "site"
    assert "edge-sw2 (10.0.0.12)" in out["preview"]["warning"]


async def test_exactly_one_target(api: respx.MockRouter) -> None:
    with pytest.raises(ToolError, match="exactly one target"):
        await preview("catc_apply_telemetry_settings", {})


async def test_update_site_settings_points_at_telemetry_apply(api: respx.MockRouter) -> None:
    mock_sites(api, [GLOBAL, AREA, BLDG])
    path = f"/dna/intent/api/v1/sites/{BLDG['id']}/telemetrySettings"
    api.get(path).respond(json={"response": {"syslogs": {"useBuiltinSyslogServer": True}}})
    api.put(path).respond(202, json={"response": {"taskId": "s1"}})
    task_ok(api, "s1", data="")
    out, done = await preview_then_apply(
        "catc_update_site_settings", {"site": "Global/AU/SYD-1", "syslog_servers": ["192.0.2.50"]}
    )
    assert "catc_apply_telemetry_settings" in out["preview"]["note"]
    assert "catc_apply_telemetry_settings" in done["result"]["next"]
