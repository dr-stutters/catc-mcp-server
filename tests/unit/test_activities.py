"""D120 (#236): Catalyst Center activities (respx). The rows follow the 3.2.2 lab appliance's live answers
(2026-10-28, GET /activities, /activities/count, /activities/{id}, /triggeredJobs; ids and device ids
replaced, addresses changed to documentation ones): type DEFAULT, recurring rows with endTime 0, a one-off
row whose endTime is before its startTime, and a failed job's failureReason. The PENDING row (scheduled
in the future) and the RUNNING one follow the spec."""

from typing import Any

import httpx
import pytest
import respx
from fastmcp.exceptions import ToolError

from catc_mcp.tools import activities
from catc_mcp.tools.activities import activity_row, in_window, section

from .test_read_tools import call

ACT = "/dna/intent/api/v1/activities"
J = {"response_format": "json"}
NOW = 1793200000000  # 2026-10-28T...Z: fixed so the sections don't move

BACKUP_ID = "019dcff2-0000-7000-8000-000000000001"
ADVISORY_ID = "019dcff9-0000-7000-8000-000000000002"
BUGSCAN_ID = "01a18107-0000-7000-8000-000000000003"
DEPLOY_OK_ID = "045f23d8-0000-4000-8000-000000000004"
DEPLOY_FAIL_ID = "35aef70d-0000-4000-8000-000000000005"
PENDING_ID = "77777777-0000-4000-8000-000000000006"
RUNNING_ID = "88888888-0000-4000-8000-000000000007"
DEVICE = "710f83de-0000-4000-8000-0000000000aa"

BACKUP = {
    "recurring": True,
    "description": "Weekly backup of config collections for configuration archive",
    "startTime": 1777849200000,
    "id": BACKUP_ID,
    "endTime": 0,
    "type": "DEFAULT",
    "status": "SUCCESS",
}
ADVISORY = {
    "recurring": True,
    "description": "Scan network for Security Advisories",
    "startTime": 1777340280000,
    "id": ADVISORY_ID,
    "endTime": 0,
    "type": "DEFAULT",
    "status": "SUCCESS",
}
BUGSCAN = {  # live: endTime a few seconds before startTime
    "recurring": False,
    "description": "Scan for Network Bugs",
    "startTime": 1793166114538,
    "id": BUGSCAN_ID,
    "endTime": 1793166109762,
    "type": "DEFAULT",
    "status": "SUCCESS",
}
DEPLOY_OK = {
    "recurring": False,
    "description": f"Deploy Intended Config Features on {DEVICE}",
    "startTime": 1792325686462,
    "id": DEPLOY_OK_ID,
    "endTime": 1792325686484,
    "type": "DEFAULT",
    "status": "SUCCESS",
}
DEPLOY_FAIL = {
    "recurring": False,
    "description": f"Deploy Intended Config Features on {DEVICE}",
    "startTime": 1792325760813,
    "id": DEPLOY_FAIL_ID,
    "endTime": 1792325760831,
    "type": "DEFAULT",
    "status": "FAILED",
}
PENDING = {
    "recurring": False,
    "description": "Deploy template mcp-banner",
    "startTime": NOW + 2 * 3600_000,
    "id": PENDING_ID,
    "type": "TASK",
    "status": "PENDING",
}
RUNNING = {
    "recurring": False,
    "description": "Provision device",
    "startTime": NOW - 60_000,
    "id": RUNNING_ID,
    "type": "TASK",
    "status": "RUNNING",
}
ALL = [BACKUP, ADVISORY, BUGSCAN, DEPLOY_OK, DEPLOY_FAIL, PENDING, RUNNING]
FAILED_JOB = {
    "taskUrl": "/dna/intent/api/v1/tasks/01a14ef0-0000-7000-8000-0000000000bb",
    "description": f"Deploy Intended Config Features on {DEVICE}",
    "id": "c9a005a6-0000-4000-8000-0000000000cc",
    "taskId": "01a14ef0-0000-7000-8000-0000000000bb",
    "status": "FAILURE",
    "failureReason": "Unable to push configuration to device 192.0.2.10. Device response - Validation "
    "failed node-(1):dbm:wireless:FT Adaptive is not allowed when both WPA2 and WPA3 are enabled",
}
BACKUP_JOBS = [  # live: recurring runs carry no task id
    {
        "description": "Weekly backup of config collections for configuration archive",
        "id": "6f61dc81-0000-4000-8000-0000000000dd",
        "status": "SUCCESS",
    },
    {
        "description": "Weekly backup of config collections for configuration archive",
        "id": "91d4d430-0000-4000-8000-0000000000ee",
        "status": "SUCCESS",
    },
]


@pytest.fixture(autouse=True)
def fixed_now(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(activities, "now_ms", lambda: NOW)


def lab(api: respx.MockRouter, rows: list[dict[str, Any]] | None = None) -> respx.Route:
    rows = ALL if rows is None else rows

    def listing(request: httpx.Request) -> httpx.Response:
        q = request.url.params
        out = [r for r in rows if "status" not in q or r["status"] == q["status"]]
        if "recurring" in q:
            out = [r for r in out if str(r["recurring"]).lower() == q["recurring"]]
        if "description" in q:  # live: an exact match
            out = [r for r in out if r["description"] == q["description"]]
        start = int(q.get("offset", "1")) - 1
        return httpx.Response(200, json={"response": out[start : start + int(q.get("limit", "500"))]})

    route = api.get(ACT).mock(side_effect=listing)
    api.get(f"{ACT}/count").respond(json={"response": {"count": len(rows)}, "version": "1.0"})
    return route


async def test_list_splits_sections_failed_first(api: respx.MockRouter) -> None:
    lab(api)
    out = await call("catc_list_activities", J)
    assert out["counts"] == {"upcoming": 1, "in_progress": 1, "recurring": 2, "finished": 3}
    assert out["total_on_appliance"] == 7 and out["failed"] == 1
    assert [r["id"] for r in out["finished"]] == [DEPLOY_FAIL_ID, BUGSCAN_ID, DEPLOY_OK_ID]
    assert out["finished"][0]["failed"] is True
    up = out["upcoming"][0]
    assert up["id"] == PENDING_ID and up["when"] == "in 2h00m" and up["start"].endswith("Z")
    rec = {r["description"] for r in out["recurring"]}
    assert "Weekly backup of config collections for configuration archive" in rec
    backup = next(r for r in out["recurring"] if r["id"] == BACKUP_ID)
    assert backup["schedule_start"] == "2026-05-03T23:00:00Z" and "end" not in backup
    assert out["in_progress"][0]["status"] == "RUNNING"


async def test_list_times_are_iso_and_bad_durations_dropped(api: respx.MockRouter) -> None:
    lab(api)
    out = await call("catc_list_activities", J)
    bug = next(r for r in out["finished"] if r["id"] == BUGSCAN_ID)
    assert "duration_s" not in bug  # end before start on the appliance
    ok = next(r for r in out["finished"] if r["id"] == DEPLOY_OK_ID)
    assert ok["duration_s"] == 0.0 and ok["end"].endswith("Z")


async def test_list_server_filters(api: respx.MockRouter) -> None:
    route = lab(api)
    out = await call("catc_list_activities", {**J, "status": "FAILED", "recurring": False, "type": "DEFAULT"})
    q = route.calls.last.request.url.params
    assert q["status"] == "FAILED" and q["recurring"] == "false" and q["type"] == "DEFAULT"
    assert out["counts"]["finished"] == 1 and out["filters"]["status"] == "FAILED"


async def test_list_description_filter_is_substring(api: respx.MockRouter) -> None:
    route = lab(api)
    out = await call("catc_list_activities", {**J, "description_filter": "deploy intended"})
    assert "description" not in route.calls.last.request.url.params
    assert out["counts"]["finished"] == 2 and out["counts"]["recurring"] == 0


async def test_list_window(api: respx.MockRouter) -> None:
    lab(api)
    out = await call("catc_list_activities", {**J, "since": "2026-10-28T00:00Z"})
    ids = {r["id"] for s in ("upcoming", "in_progress", "finished") for r in out[s]}
    assert ids == {PENDING_ID, RUNNING_ID, BUGSCAN_ID}
    assert out["counts"]["recurring"] == 2  # schedules keep running


async def test_list_rejects_bad_window(api: respx.MockRouter) -> None:
    lab(api)
    with pytest.raises(ToolError, match="needs a UTC offset"):
        await call("catc_list_activities", {**J, "since": "2026-10-28T00:00"})
    with pytest.raises(ToolError, match="since is after until"):
        await call("catc_list_activities", {**J, "since": "2026-10-28T00:00Z", "until": "2026-10-27T00:00Z"})


async def test_list_limit_and_empty_notes(api: respx.MockRouter) -> None:
    lab(api)
    out = await call("catc_list_activities", {**J, "limit": 1})
    assert len(out["finished"]) == 1 and any("finished: showing 1-1 of 3" in n for n in out["notes"])
    lab(api, rows=[])
    out = await call("catc_list_activities", J)
    assert "No activities match." in out["notes"]


async def test_get_activity_with_failed_job(api: respx.MockRouter) -> None:
    api.get(f"{ACT}/{DEPLOY_FAIL_ID}").respond(json={"response": DEPLOY_FAIL, "version": "1.0"})
    api.get(f"{ACT}/{DEPLOY_FAIL_ID}/triggeredJobs").respond(
        json={"response": [FAILED_JOB], "version": "1.0"}
    )
    api.get(f"{ACT}/{DEPLOY_FAIL_ID}/triggeredJobs/count").respond(json={"response": {"count": 1}})
    out = await call("catc_get_activity", {"activity": DEPLOY_FAIL_ID})
    assert out["section"] == "finished" and out["status"] == "FAILED"
    assert out["triggered_jobs_count"] == 1 and out["triggered_jobs_failed"] == 1
    job = out["triggered_jobs"][0]
    assert job["task_id"] == FAILED_JOB["taskId"] and "WPA3" in job["failure_reason"]


async def test_get_recurring_activity_runs(api: respx.MockRouter) -> None:
    api.get(f"{ACT}/{BACKUP_ID}").respond(json={"response": BACKUP})
    api.get(f"{ACT}/{BACKUP_ID}/triggeredJobs").respond(json={"response": BACKUP_JOBS})
    api.get(f"{ACT}/{BACKUP_ID}/triggeredJobs/count").respond(json={"response": {"count": 2}})
    out = await call("catc_get_activity", {"activity": BACKUP_ID})
    assert out["section"] == "recurring" and out["triggered_jobs_count"] == 2
    assert all("task_id" not in j for j in out["triggered_jobs"])
    assert any("recurring schedule" in n for n in out["notes"])


async def test_get_activity_falls_back_to_spec_path(api: respx.MockRouter) -> None:
    api.get(f"{ACT}/{PENDING_ID}").respond(404, json={"message": "BAPI not found"})
    spec = api.get(f"/dna/intent/api/v1/intent/api/v1/activities/{PENDING_ID}").respond(
        json={"response": PENDING}
    )
    api.get(f"{ACT}/{PENDING_ID}/triggeredJobs").respond(json={"response": []})
    api.get(f"{ACT}/{PENDING_ID}/triggeredJobs/count").respond(json={"response": {"count": 0}})
    out = await call("catc_get_activity", {"activity": PENDING_ID})
    assert spec.called and out["section"] == "upcoming" and out["triggered_jobs"] == []


async def test_get_activity_by_description(api: respx.MockRouter) -> None:
    lab(api)
    api.get(f"{ACT}/{BACKUP_ID}/triggeredJobs").respond(json={"response": BACKUP_JOBS})
    api.get(f"{ACT}/{BACKUP_ID}/triggeredJobs/count").respond(json={"response": {"count": 2}})
    out = await call("catc_get_activity", {"activity": BACKUP["description"]})
    assert out["id"] == BACKUP_ID
    with pytest.raises(ToolError, match="2 activities are described as"):
        await call("catc_get_activity", {"activity": DEPLOY_OK["description"]})
    with pytest.raises(ToolError, match="No activity described exactly"):
        await call("catc_get_activity", {"activity": "nothing like this"})


async def test_get_activity_not_found(api: respx.MockRouter) -> None:
    api.get(f"{ACT}/{RUNNING_ID}").respond(404, json={"message": "BAPI not found"})
    api.get(f"/dna/intent/api/v1/intent/api/v1/activities/{RUNNING_ID}").respond(404, json={})
    with pytest.raises(ToolError, match=f"No activity {RUNNING_ID}"):
        await call("catc_get_activity", {"activity": RUNNING_ID})


def test_helpers() -> None:
    assert section({"status": "SUCCESS", "startTime": NOW + 1000}, NOW) == "finished"
    assert section({"status": "READY", "startTime": NOW - 1000}, NOW) == "in_progress"
    assert in_window(BACKUP, NOW, None) and not in_window(BACKUP, None, 1777000000000)
    assert not in_window(DEPLOY_OK, NOW, None)
    assert "end" not in activity_row({**BUGSCAN, "endTime": 0}, NOW)


async def test_list_offset_and_markdown(api: respx.MockRouter) -> None:
    lab(api)
    out = await call("catc_list_activities", {**J, "limit": 1, "offset": 1})
    assert [r["id"] for r in out["finished"]] == [BUGSCAN_ID]
    text = await call("catc_list_activities", {})
    assert isinstance(text, str) and "| section |" in text and "recurring" in text and DEPLOY_FAIL_ID in text
