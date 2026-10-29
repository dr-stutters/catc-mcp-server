"""D66 (#113): image readiness, update history, add-on images and distribution servers (respx).

Shapes: the 3.2.2 lab appliance's live answers (2026-10-29, read-only) for networkDeviceImages/{id},
networkDeviceImageUpdates/count and distributionServerSettings (address changed to a documentation one);
the lab had run no upgrade, so the validation result, custom validation, update and add-on rows are
synthetic, built from the 3.2.2 spec schema."""

from typing import Any

import httpx
import pytest
import respx
from fastmcp.exceptions import ToolError

from catc_mcp.tools.image_readiness import details, group_runs, verdict_of

from .test_read_tools import DEV_ID, DEVICE, call, mock_device_lookup
from .test_write_tools import preview_then_apply

NDI = "/dna/intent/api/v1/networkDeviceImages"
RESULTS = f"{NDI}/validationResults"
UPDATES = "/dna/intent/api/v1/networkDeviceImageUpdates"
IMG_ID = "ffffffff-0000-4000-8000-000000000001"
ADDON_ID = "ffffffff-0000-4000-8000-000000000002"
RUN_OLD = "aaaaaaaa-0000-4000-8000-000000000001"
RUN_NEW = "aaaaaaaa-0000-4000-8000-000000000002"
RUN_DIST = "aaaaaaaa-0000-4000-8000-000000000003"
TASK_ID = "bbbbbbbb-0000-4000-8000-000000000001"
J = {"response_format": "json"}

RECORD = {  # live shape
    "id": DEV_ID,
    "managementAddress": "192.0.2.11",
    "networkDeviceImageStatus": "UNKNOWN",
    "networkDeviceUpdateStatus": "UNKNOWN",
    "networkDeviceImageCompatibilityStatus": "COMPATIBLE",
    "installedImages": [{"name": "CAT9K[17.09.04]", "version": "17.9.4", "imageType": "SYSTEM"}],
    "networkDevice": {
        "id": "286315874",
        "productName": "Cisco Catalyst 9300 Switch",
        "productNameOrdinal": 286315874,
    },
}


def res(
    run: str, name: str, status: str, start: int, op: str = "READINESS_CHECK", **kw: Any
) -> dict[str, Any]:
    return {
        "id": f"{run[:-4]}{start % 10000:04d}",
        "parentId": run,
        "name": name,
        "networkDeviceId": DEV_ID,
        "operationType": op,
        "type": "PRE_VALIDATION",
        "status": status,
        "startTime": start,
        "endTime": start + 4000,
        **kw,
    }


RESULT_ROWS = [
    res(RUN_OLD, "Flash check", "FAILED", 1793000000000),
    res(
        RUN_NEW,
        "Flash check",
        "FAILED",
        1793100000000,
        resultDetails=[
            {"key": "EXPECTED", "value": "1200 MB free"},
            {"key": "ACTUAL", "value": "800 MB free"},
            {"key": "ACTION", "value": "Clean up flash"},
        ],
    ),
    res(RUN_NEW, "Startup config check", "SUCCESS", 1793100001000),
    res(
        RUN_NEW,
        "Config register check",
        "WARNING",
        1793100002000,
        resultDetails={"key": "ACTUAL", "value": "0x2142"},
    ),
    res(RUN_DIST, "CPU check", "SUCCESS", 1792900000000, op="DISTRIBUTION"),
]
CUSTOM = {
    "id": "cccccccc-0000-4000-8000-000000000001",
    "name": "mcp-bgp-neighbors",
    "category": "CUSTOM",
    "cli": "show ip bgp summary",
    "operationType": "ACTIVATION",
    "type": "PRE_VALIDATION",
    "productSeriesOrdinals": [286315863],
}
IMAGE = {
    "id": IMG_ID,
    "name": "cat9k_iosxe.17.12.04.SPA.bin",
    "version": "17.12.4",
    "imported": True,
    "integrityStatus": "VERIFIED",
    "isAddonImage": False,
    "imageType": "SYSTEM",
    "productNames": [{"productName": "Cisco Catalyst 9300 Switch", "productNameOrdinal": 286315874}],
}
ADDON = {
    "id": ADDON_ID,
    "name": "cat9k_iosxe.17.12.04.CSCwx00001.SPA.smu.bin",
    "version": "17.12.4",
    "imageType": "SMU",
    "isAddonImage": True,
    "imported": True,
    "integrityStatus": "VERIFIED",
}


def mock_results(api: respx.MockRouter, rows: list[dict[str, Any]]) -> respx.Route:
    def listing(request: httpx.Request) -> httpx.Response:
        q = request.url.params
        out = [r for r in rows if q.get("networkDeviceId", r["networkDeviceId"]) == r["networkDeviceId"]]
        if "operationType" in q:
            out = [r for r in out if r["operationType"] == q["operationType"]]
        start = int(q.get("offset", "1")) - 1
        return httpx.Response(200, json={"response": out[start : start + int(q.get("limit", "500"))]})

    return api.get(RESULTS).mock(side_effect=listing)


def mock_device(api: respx.MockRouter, rows: list[dict[str, Any]] | None = None) -> respx.Route:
    mock_device_lookup(api)
    api.get(f"{NDI}/{DEV_ID}").respond(json={"response": RECORD, "version": "1.0"})
    api.get(f"{NDI}/validations").respond(json={"response": [CUSTOM], "version": "1.0"})
    return mock_results(api, RESULT_ROWS if rows is None else rows)


def test_details_and_verdicts() -> None:
    assert details({"key": "ACTUAL", "value": "x"}) == {"ACTUAL": "x"}
    assert details([{"key": "EXPECTED", "value": "a"}, {"key": "ACTION", "value": "b"}]) == {
        "EXPECTED": "a",
        "ACTION": "b",
    }
    assert details(None) is None
    assert verdict_of(["SUCCESS", "SKIPPED"]) == "READY"
    assert verdict_of(["SUCCESS", "WARNING"]) == "READY_WITH_WARNINGS"
    assert verdict_of(["STARTED", "SUCCESS"]) == "IN_PROGRESS"
    assert verdict_of(["ABORTED", "WARNING"]) == "NOT_READY"
    assert verdict_of([]) == "NO_CHECKS"


def test_group_runs_newest_first_failed_first() -> None:
    runs = group_runs(RESULT_ROWS)
    assert [r["run_id"] for r in runs] == [RUN_NEW, RUN_OLD, RUN_DIST]
    new = runs[0]
    assert new["verdict"] == "NOT_READY" and new["counts"] == {"FAILED": 1, "SUCCESS": 1, "WARNING": 1}
    assert [c["status"] for c in new["checks"]] == ["FAILED", "WARNING", "SUCCESS"]
    assert new["checks"][0]["details"]["ACTUAL"] == "800 MB free"
    assert new["start"].endswith("Z")


async def test_readiness_latest_check_and_target_image(api: respx.MockRouter) -> None:
    route = mock_device(api)
    api.get("/dna/intent/api/v1/images").respond(json={"response": [IMAGE]})
    api.get(f"/dna/intent/api/v1/images/{IMG_ID}/addonImages").respond(json={"response": [ADDON]})
    out = await call("catc_image_readiness", {"device": "edge-sw1", "image": IMAGE["name"]})
    assert route.calls.last.request.url.params["networkDeviceId"] == DEV_ID
    assert out["verdict"] == "NOT_READY"
    assert "failed: Flash check" in out["summary"] and "warnings: Config register check" in out["summary"]
    assert out["latest_by_operation"]["READINESS_CHECK"]["run_id"] == RUN_NEW
    assert out["latest_by_operation"]["DISTRIBUTION"]["verdict"] == "READY"
    assert out["image_status"]["compatibility"] == "COMPATIBLE"
    assert out["image_status"]["product"] == "Cisco Catalyst 9300 Switch"
    assert out["custom_validations"][0]["cli"] == "show ip bgp summary"
    target = out["target_image"]
    assert target["applies_to_device"] is True and target["issues"] == []
    assert target["addon_images"][0]["imageType"] == "SMU"


async def test_readiness_no_check_and_wrong_image(api: respx.MockRouter) -> None:
    mock_device(api, rows=[])
    other = {
        **IMAGE,
        "productNames": [{"productName": "Cisco Catalyst 9500 Switch", "productNameOrdinal": 1}],
        "version": "17.9.4",
        "imported": False,
    }
    api.get("/dna/intent/api/v1/images").respond(json={"response": [other]})
    api.get(f"/dna/intent/api/v1/images/{IMG_ID}/addonImages").respond(json={"response": []})
    out = await call(
        "catc_image_readiness",
        {"device": DEV_ID, "image": IMG_ID, "include_custom_validations": False},
    )
    assert out["verdict"] == "NO_READINESS_CHECK" and "catc_run_image_readiness_check" in out["summary"]
    assert "custom_validations" not in out
    issues = out["target_image"]["issues"]
    assert out["target_image"]["applies_to_device"] is False
    assert any("not for Cisco Catalyst 9300 Switch" in i for i in issues)
    assert any("not imported" in i for i in issues) and any("already runs" in i for i in issues)


async def test_readiness_image_status_unavailable(api: respx.MockRouter) -> None:
    mock_device(api)
    api.get(f"{NDI}/{DEV_ID}").respond(500, json={"response": {"message": "boom"}})
    out = await call("catc_image_readiness", {"device": "edge-sw1"})
    assert "image_status" not in out and any("Image status unavailable" in n for n in out["notes"])
    assert out["verdict"] == "NOT_READY"


async def test_run_readiness_check_preview_then_apply(api: respx.MockRouter) -> None:
    mock_device(api, rows=[r for r in RESULT_ROWS if r["parentId"] == RUN_NEW])
    post = api.post(f"{NDI}/{DEV_ID}/readinessChecks").respond(
        202, json={"response": {"taskId": TASK_ID, "url": f"/api/v1/task/{TASK_ID}"}, "version": "1.0"}
    )
    api.get(f"/dna/intent/api/v1/task/{TASK_ID}").respond(
        json={
            "response": {
                "endTime": 1,
                "isError": False,
                "progress": "done",
                "resultLocation": f"{RESULTS}?id={RUN_NEW}",
            }
        }
    )
    preview, done = await preview_then_apply("catc_run_image_readiness_check", {"device": "edge-sw1"})
    assert preview["status"] == "preview" and preview["preview"]["path"].endswith("/readinessChecks")
    assert "no configuration change" in preview["preview"]["effect"]
    assert post.call_count == 1
    result = done["result"]
    assert result["verdict"] == "NOT_READY" and result["task"]["task_id"] == TASK_ID
    assert [c["name"] for c in result["checks"]][0] == "Flash check"


async def test_run_readiness_check_blocked_when_unreachable(api: respx.MockRouter) -> None:
    mock_device(api)
    down = {**DEVICE, "reachabilityStatus": "Unreachable"}
    api.get(f"/dna/intent/api/v1/network-device/{DEV_ID}").respond(json={"response": down})
    post = api.post(f"{NDI}/{DEV_ID}/readinessChecks")
    preview, done = await preview_then_apply("catc_run_image_readiness_check", {"device": DEV_ID})
    assert done is None and preview["status"] == "blocked"
    assert any("Unreachable" in b for b in preview["blockers"])
    assert not post.called


async def test_run_readiness_check_is_write_tier(api: respx.MockRouter) -> None:
    mock_device(api)
    with pytest.raises(ToolError):
        await call("catc_run_image_readiness_check", {"device": "edge-sw1"})


async def test_update_history(api: respx.MockRouter) -> None:
    mock_device_lookup(api)
    rows = [
        {
            "id": "dddddddd-0000-4000-8000-000000000001",
            "parentId": "eeeeeeee-0000-4000-8000-000000000001",
            "networkDeviceId": DEV_ID,
            "hostName": "edge-sw1.lab.local",
            "managementAddress": "192.0.2.11",
            "type": "DISTRIBUTION",
            "status": "FAILURE",
            "updateImageVersion": "17.12.4",
            "startTime": 1793100000000,
            "endTime": 1793100060000,
        }
    ]
    route = api.get(UPDATES).respond(json={"response": rows, "version": "1.0"})
    count = api.get(f"{UPDATES}/count").respond(json={"response": {"count": 1}, "version": "1.0"})
    out = await call("catc_image_update_history", {**J, "device": "edge-sw1", "status": "FAILURE"})
    q = route.calls.last.request.url.params
    assert q["networkDeviceId"] == DEV_ID and q["status"] == "FAILURE" and q["order"] == "desc"
    assert "sortBy" not in count.calls.last.request.url.params
    assert out["total"] == 1
    row = out["results"][0]
    assert row["duration_s"] == 60.0 and row["type"] == "DISTRIBUTION" and row["start"].endswith("Z")


async def test_update_history_empty_live_shape(api: respx.MockRouter) -> None:
    api.get(UPDATES).respond(json={"response": [], "version": "1.0"})
    api.get(f"{UPDATES}/count").respond(json={"response": {"count": 0}, "version": "1.0"})
    out = await call("catc_image_update_history", J)
    assert out["results"] == [] and out["total"] == 0


async def test_addon_images(api: respx.MockRouter) -> None:
    api.get("/dna/intent/api/v1/images").respond(json={"response": [IMAGE]})
    api.get(f"/dna/intent/api/v1/images/{IMG_ID}/addonImages").respond(json={"response": [ADDON]})
    out = await call("catc_list_addon_images", {**J, "image": IMAGE["name"]})
    assert out["results"][0]["name"].endswith(".smu.bin")


async def test_distribution_servers_live_shape(api: respx.MockRouter) -> None:
    api.get("/dna/intent/api/v1/images/distributionServerSettings").respond(
        json={
            "response": [
                {
                    "id": "1c6a4d93-0000-4000-8000-000000000001",
                    "rootLocation": "/opt/images",
                    "portNumber": 22,
                    "serverAddress": "198.51.100.11",
                    "username": "sftpuser",
                }
            ],
            "version": "1.0",
        }
    )
    out = await call("catc_list_image_distribution_servers", {})
    assert out["servers"][0]["serverAddress"] == "198.51.100.11"
    assert "local distribution server" in out["note"]
