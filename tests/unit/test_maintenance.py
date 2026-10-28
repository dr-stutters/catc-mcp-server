"""D73: device maintenance windows (respx). The empty list is the 3.2.2 lab appliance's live answer
(2026-10-27, GET networkDeviceMaintenanceSchedules?limit=5 -> {"response": [], "version": "1.0"}); the
windows below follow the 3.2.2 spec (status inside maintenanceSchedule, times in epoch ms)."""

import json
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client
from fastmcp.exceptions import ToolError

from catc_mcp._core import InvalidRequest
from catc_mcp._core.errors import TaskFailed, ValidationFailed
from catc_mcp.server import create_server
from catc_mcp.tools import maintenance
from catc_mcp.tools.maintenance import (
    duration_text,
    is_started_refusal,
    now_ms,
    overlaps,
    schedule_blockers,
    started_blocker,
    to_iso,
    to_ms,
    window_row,
)

from .conftest import make_settings
from .test_read_tools import BLDG, DEV_ID, DEVICE, GLOBAL, mock_device_lookup
from .test_write_tools import mock_sites, run, task_ok

PATH = "/dna/intent/api/v1/networkDeviceMaintenanceSchedules"
WIN_ID = "dddddddd-1111-2222-3333-444444444444"
OTHER_DEV = "22222222-3333-4444-5555-666666666666"
# 2099-01-10T11:00Z .. 13:00Z: far enough ahead that "in the future" holds forever.
START_ISO, END_ISO = "2099-01-10T22:00+11:00", "2099-01-11T00:00+11:00"
START_MS, END_MS = 4071726000000, 4071733200000


def window(
    status: str = "UPCOMING",
    *,
    wid: str = WIN_ID,
    start: int = START_MS,
    end: int = END_MS,
    devices: list[str] | None = None,
    recurrence: dict[str, Any] | None = None,
    description: str = "mcp-chg1 uplink swap",
) -> dict[str, Any]:
    sched: dict[str, Any] = {
        "startId": "a1a1a1a1-0000-0000-0000-000000000001",
        "endId": "a1a1a1a1-0000-0000-0000-000000000002",
        "startTime": start,
        "endTime": end,
        "status": status,
    }
    if recurrence:
        sched["recurrence"] = recurrence
    return {
        "id": wid,
        "description": description,
        "maintenanceSchedule": sched,
        "networkDeviceIds": devices if devices is not None else [DEV_ID],
    }


def mock_windows(api: respx.MockRouter, rows: list[dict[str, Any]]) -> respx.Route:
    def handler(request: httpx.Request) -> httpx.Response:
        q = request.url.params
        out = rows
        if q.get("status"):
            out = [w for w in out if w["maintenanceSchedule"]["status"] == q["status"]]
        if q.get("networkDeviceIds"):
            out = [w for w in out if q["networkDeviceIds"] in w["networkDeviceIds"]]
        if int(q.get("offset", 1)) > 1:
            out = []
        return httpx.Response(200, json={"response": out, "version": "1.0"})

    for w in rows:
        api.get(f"{PATH}/{w['id']}").respond(json={"response": w, "version": "1.0"})
    return api.get(PATH).mock(side_effect=handler)


async def flow(name: str, args: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any] | None]:
    async with Client(create_server(make_settings(mcp_enable_writes=True))) as c:
        preview = await run(c, name, args)
        if preview.get("status") != "preview":
            return preview, None
        return preview, await run(c, name, {**args, "confirm": preview["confirm"]})


# --- pure helpers ---------------------------------------------------------------------------------


def test_time_conversion_round_trips() -> None:
    assert to_ms(START_ISO, "start") == START_MS
    assert to_ms("2099-01-10T11:00:00Z", "start") == START_MS
    assert to_iso(START_MS) == "2099-01-10T11:00:00Z"
    assert to_iso(None) is None and to_iso("x") is None
    assert duration_text(END_MS - START_MS) == "2h"
    assert duration_text(DAY + 90 * 60_000) == "1d 1h 30m"


DAY = 86_400_000


def test_time_needs_an_offset() -> None:
    with pytest.raises(InvalidRequest, match="UTC offset"):
        to_ms("2099-01-10T22:00", "start")
    with pytest.raises(InvalidRequest, match="ISO 8601"):
        to_ms("next tuesday", "end")


def test_recurrence_validation() -> None:
    now = START_MS - DAY
    assert schedule_blockers(START_MS, END_MS, None, None, now=now) == []
    assert schedule_blockers(START_MS, END_MS, 7, END_MS + 30 * DAY, now=now) == []
    assert any("after the start" in b for b in schedule_blockers(END_MS, START_MS, None, None, now=now))
    assert any("not in the future" in b for b in schedule_blockers(START_MS, END_MS, None, None, now=END_MS))
    # Started windows: the past start is fine, the end still has to be ahead.
    assert schedule_blockers(START_MS, END_MS, None, None, started=True, now=START_MS + 1) == []
    long = schedule_blockers(START_MS, START_MS + 2 * DAY, 1, START_MS + 30 * DAY, now=now)
    assert any("longer than the 1-day repeat interval" in b for b in long)
    assert any("needs recurrence_end" in b for b in schedule_blockers(START_MS, END_MS, 7, None, now=now))
    assert any(
        "needs recurrence_days" in b for b in schedule_blockers(START_MS, END_MS, None, END_MS + DAY, now=now)
    )
    assert any("after the window's end" in b for b in schedule_blockers(START_MS, END_MS, 7, END_MS, now=now))


# --- list -----------------------------------------------------------------------------------------


async def test_list_empty_is_the_live_answer(api: respx.MockRouter) -> None:
    api.get(PATH).respond(json={"response": [], "version": "1.0"})
    async with Client(create_server(make_settings())) as c:
        out = await run(c, "catc_list_maintenance_windows", {"response_format": "json"})
    assert out["results"] == [] and out["note"] == "No maintenance windows."


async def test_list_rows_iso_times_and_hostnames(api: respx.MockRouter) -> None:
    mock_device_lookup(api)
    rec = {"interval": 7, "recurrenceEndTime": END_MS + 60 * DAY}
    route = mock_windows(api, [window("IN_PROGRESS", recurrence=rec), window("COMPLETED", wid="w2")])
    async with Client(create_server(make_settings())) as c:
        out = await run(
            c, "catc_list_maintenance_windows", {"status": "IN_PROGRESS", "response_format": "json"}
        )
    assert route.calls.last.request.url.params["status"] == "IN_PROGRESS"
    [row] = out["results"]
    assert row["start"] == "2099-01-10T11:00:00Z" and row["end"] == "2099-01-10T13:00:00Z"
    assert row["duration"] == "2h" and row["repeats_every_days"] == 7
    assert row["devices"] == ["edge-sw1.lab.local"] and row["device_count"] == 1
    assert "maintenance mode" in out["note"]


async def test_list_by_device_passes_the_id(api: respx.MockRouter) -> None:
    mock_device_lookup(api)
    route = mock_windows(api, [window(), window(wid="w2", devices=[OTHER_DEV])])
    async with Client(create_server(make_settings())) as c:
        out = await run(
            c, "catc_list_maintenance_windows", {"device": "10.0.0.11", "response_format": "json"}
        )
    assert route.calls.last.request.url.params["networkDeviceIds"] == DEV_ID
    assert [r["id"] for r in out["results"]] == [WIN_ID]


async def test_list_by_site_filters_on_site_devices(api: respx.MockRouter) -> None:
    mock_device_lookup(api)
    mock_sites(api, [GLOBAL, BLDG])
    api.get("/dna/intent/api/v1/networkDevices/assignedToSite").respond(
        json={"response": [{"deviceId": DEV_ID, "siteId": BLDG["id"]}]}
    )
    mock_windows(api, [window(), window(wid="w2", devices=[OTHER_DEV])])
    async with Client(create_server(make_settings())) as c:
        out = await run(
            c, "catc_list_maintenance_windows", {"site": "Global/AU/SYD-1", "response_format": "json"}
        )
    assert [r["id"] for r in out["results"]] == [WIN_ID] and out["site"] == "Global/AU/SYD-1"


# --- schedule -------------------------------------------------------------------------------------


async def test_schedule_preview_then_apply(api: respx.MockRouter) -> None:
    mock_device_lookup(api)
    listed = mock_windows(api, [])
    post = api.post(PATH).respond(202, json={"response": {"taskId": "t1", "url": "/task/t1"}})
    task_ok(api, "t1")
    args = {"devices": ["edge-sw1"], "start": START_ISO, "end": END_ISO, "description": "mcp-chg1"}
    preview, done = await flow("catc_schedule_maintenance", args)
    assert preview["status"] == "preview" and post.call_count == 1  # only the apply posted
    p = preview["preview"]
    assert p["devices"] == ["edge-sw1.lab.local (10.0.0.11)"] and p["duration"] == "2h"
    assert p["start"] == "2099-01-10T11:00:00Z"
    effects = " ".join(preview["side_effects"])
    assert "no health" in effects and "full duration" in effects
    assert "can't be cancelled or given a new end time" in effects and "end_now=true" in effects
    assert preview.get("blast_radius") == 1
    sent = json.loads(post.calls.last.request.content)
    assert sent == {
        "description": "mcp-chg1",
        "maintenanceSchedule": {"startTime": START_MS, "endTime": END_MS},
        "networkDeviceIds": [DEV_ID],
    }
    assert "id" not in sent and "status" not in sent  # read-only in the spec despite `required`
    assert done is not None and done["status"] == "applied"
    assert listed.called


async def test_schedule_recurring_body(api: respx.MockRouter) -> None:
    mock_device_lookup(api)
    mock_windows(api, [])
    post = api.post(PATH).respond(202, json={"response": {"taskId": "t2"}})
    task_ok(api, "t2")
    args = {
        "devices": ["edge-sw1"],
        "start": START_ISO,
        "end": END_ISO,
        "description": "mcp-weekly",
        "recurrence_days": 7,
        "recurrence_end": "2099-03-01T00:00Z",
    }
    preview, _ = await flow("catc_schedule_maintenance", args)
    assert preview["preview"]["repeats"]["every_days"] == 7
    sent = json.loads(post.calls.last.request.content)
    until = int(datetime(2099, 3, 1, tzinfo=UTC).timestamp() * 1000)
    assert sent["maintenanceSchedule"]["recurrence"] == {"interval": 7, "recurrenceEndTime": until}


async def test_schedule_refuses_past_start(api: respx.MockRouter) -> None:
    mock_device_lookup(api)
    mock_windows(api, [])
    post = api.post(PATH)
    args = {"devices": ["edge-sw1"], "start": "2020-01-01T00:00Z", "end": END_ISO, "description": "x"}
    preview, _ = await flow("catc_schedule_maintenance", args)
    assert preview["status"] == "blocked" and not post.called
    assert any("not in the future" in b for b in preview["blockers"])


async def test_schedule_warns_on_overlap(api: respx.MockRouter) -> None:
    mock_device_lookup(api)
    mock_windows(api, [window(description="mcp-other", start=START_MS + 3_600_000, end=END_MS + 3_600_000)])
    args = {"devices": ["edge-sw1"], "start": START_ISO, "end": END_ISO, "description": "mcp-chg2"}
    async with Client(create_server(make_settings(mcp_enable_writes=True))) as c:
        preview = await run(c, "catc_schedule_maintenance", args)
    assert preview["status"] == "preview"
    assert preview["preview"]["overlapping_windows"][0].startswith("mcp-other")


async def test_schedule_needs_one_target(api: respx.MockRouter) -> None:
    async with Client(create_server(make_settings(mcp_enable_writes=True))) as c:
        with pytest.raises(ToolError, match="exactly one target"):
            await run(
                c, "catc_schedule_maintenance", {"start": START_ISO, "end": END_ISO, "description": "x"}
            )


# --- update / cancel ------------------------------------------------------------------------------


async def test_update_moves_end_and_keeps_devices(api: respx.MockRouter) -> None:
    mock_device_lookup(api)
    mock_windows(api, [window()])
    put = api.put(f"{PATH}/{WIN_ID}").respond(202, json={"response": {"taskId": "t3"}})
    task_ok(api, "t3")
    preview, done = await flow(
        "catc_update_maintenance_window", {"window": "mcp-chg1 uplink swap", "end": "2099-01-11T01:00+11:00"}
    )
    assert preview["status"] == "preview"
    assert preview["preview"]["before"]["end"] == "2099-01-10T13:00:00Z"
    assert preview["preview"]["after"]["end"] == "2099-01-10T14:00:00Z"
    sent = json.loads(put.calls.last.request.content)
    assert sent["networkDeviceIds"] == [DEV_ID] and sent["description"] == "mcp-chg1 uplink swap"
    assert sent["maintenanceSchedule"] == {"startTime": START_MS, "endTime": END_MS + 3_600_000}
    assert done is not None and done["status"] == "applied"


# The two refusals recorded live on Catalyst Center 3.2.2 (run96, #258) for a started window.
DELETE_REFUSAL = f"The maintenance window is in progress with ID {WIN_ID} and cannot be deleted."
PUT_REFUSAL = (
    "Invalid input request: NCIM90982: The maintenance window has already started and cannot be updated."
)
RULE = (
    "Catalyst Center does not let a started window be cancelled or changed; it ends at 2099-01-10T13:00:00Z"
)


@pytest.mark.parametrize(
    "args",
    [
        {"end": "2099-01-10T23:30+11:00"},  # shorten: the case that failed live
        {"end": "2099-01-11T01:00+11:00"},  # extend
        {"start": START_ISO},
        {"description": "mcp-renamed"},
    ],
)
async def test_update_running_window_is_blocked(api: respx.MockRouter, args: dict[str, Any]) -> None:
    mock_device_lookup(api)
    mock_windows(api, [window("IN_PROGRESS", start=1_000, end=END_MS)])
    put = api.put(f"{PATH}/{WIN_ID}")
    preview, _ = await flow("catc_update_maintenance_window", {"window": WIN_ID, **args})
    assert preview["status"] == "blocked" and not put.called
    assert len(preview["blockers"]) == 1 and RULE in preview["blockers"][0]
    assert "NCIM90982" in preview["blockers"][0] and "end_now=true" in preview["blockers"][0]
    assert "instead of" not in " ".join(preview.get("side_effects") or [])


async def test_update_maps_the_started_refusal(api: respx.MockRouter) -> None:
    """The window started between preview and confirm: the 400 NCIM90982 comes back in plain words."""
    mock_device_lookup(api)
    mock_windows(api, [window()])
    api.put(f"{PATH}/{WIN_ID}").respond(
        400, json={"response": {"errorCode": "Bad request", "message": PUT_REFUSAL}, "version": "1.0"}
    )
    async with Client(create_server(make_settings(mcp_enable_writes=True))) as c:
        args = {"window": WIN_ID, "end": "2099-01-11T01:00+11:00"}
        preview = await run(c, "catc_update_maintenance_window", args)
        with pytest.raises(ToolError) as exc:
            await run(c, "catc_update_maintenance_window", {**args, "confirm": preview["confirm"]})
    assert RULE in str(exc.value) and "NCIM90982: The maintenance window has already started" in str(
        exc.value
    )


async def test_update_other_errors_pass_through(api: respx.MockRouter) -> None:
    mock_device_lookup(api)
    mock_windows(api, [window()])
    api.put(f"{PATH}/{WIN_ID}").respond(400, json={"response": {"message": "bad endTime"}})
    async with Client(create_server(make_settings(mcp_enable_writes=True))) as c:
        args = {"window": WIN_ID, "end": "2099-01-11T01:00+11:00"}
        preview = await run(c, "catc_update_maintenance_window", args)
        with pytest.raises(ToolError) as exc:
            await run(c, "catc_update_maintenance_window", {**args, "confirm": preview["confirm"]})
    assert "bad endTime" in str(exc.value) and "started window" not in str(exc.value)


def ended_window(status: str | None, start: int = START_MS) -> dict[str, Any]:
    """The recorded shape after end_now (Catalyst Center 3.2.2, run96 #269): endTime stays -1, the status
    reads null for a few seconds and then COMPLETED."""
    w = window("IN_PROGRESS", start=start, end=-1)
    w["maintenanceSchedule"]["status"] = status
    w["maintenanceSchedule"]["recurrence"] = None
    return w


def end_now_routes(
    api: respx.MockRouter, after: list[dict[str, Any]], start: int = 1_000
) -> tuple[respx.Route, respx.Route]:
    """IN_PROGRESS before the PUT; after it, the re-reads answer `after` in order (the last one repeats)."""
    put = api.put(f"{PATH}/{WIN_ID}").respond(202, json={"response": {"taskId": "t6"}})
    reads: list[int] = []

    def reread(request: httpx.Request) -> httpx.Response:
        if not put.called:
            w = window("IN_PROGRESS", start=start, end=END_MS)
        else:
            w = after[min(len(reads), len(after) - 1)]
            reads.append(1)
        return httpx.Response(200, json={"response": w, "version": "1.0"})

    get = api.get(f"{PATH}/{WIN_ID}").mock(side_effect=reread)
    task_ok(api, "t6")
    return put, get


@pytest.fixture
def no_wait(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(maintenance, "END_NOW_POLL", 0)


async def test_update_end_now_sends_minus_one(api: respx.MockRouter, no_wait: None) -> None:
    mock_device_lookup(api)
    put, _ = end_now_routes(api, [ended_window("COMPLETED", start=1_000)])
    preview, done = await flow("catc_update_maintenance_window", {"window": WIN_ID, "end_now": True})
    assert preview["status"] == "preview" and "leave maintenance mode now" in preview["side_effects"][0]
    sent = json.loads(put.calls.last.request.content)
    assert sent["maintenanceSchedule"] == {"startTime": 1_000, "endTime": -1}
    assert sent["description"] == "mcp-chg1 uplink swap" and sent["networkDeviceIds"] == [DEV_ID]
    assert done is not None and done["status"] == "applied"
    assert done["result"]["window"]["status"] == "COMPLETED" and "warnings" not in done["result"]


async def test_end_now_rereads_until_completed(api: respx.MockRouter, no_wait: None) -> None:
    """Recorded: the immediate re-read has status null and endTime -1, a few seconds later COMPLETED."""
    mock_device_lookup(api)
    start = now_ms() - 30 * 60_000
    _, get = end_now_routes(
        api, [ended_window(None, start), ended_window(None, start), ended_window("COMPLETED", start)], start
    )
    _, done = await flow("catc_update_maintenance_window", {"window": WIN_ID, "end_now": True})
    assert done is not None and done["status"] == "applied"
    res = done["result"]
    row = res["window"]
    assert row["status"] == "COMPLETED" and row["end"] is None and row["ended_early"] is True
    assert "1969" not in json.dumps(res)
    assert row["duration"] in ("30m", "31m")  # start to the time the end was sent, not "0m"
    sent = datetime.fromisoformat(res["ended_at"].replace("Z", "+00:00"))
    assert abs(sent.timestamp() * 1000 - now_ms()) < 60_000
    assert "note" not in res and "warnings" not in res
    assert get.call_count >= 4  # preview + apply's own read + three re-reads after the PUT


async def test_end_now_says_ending_while_status_is_null(api: respx.MockRouter, no_wait: None) -> None:
    mock_device_lookup(api)
    _, get = end_now_routes(api, [ended_window(None)])
    before = get.call_count
    _, done = await flow("catc_update_maintenance_window", {"window": WIN_ID, "end_now": True})
    assert done is not None
    res = done["result"]
    assert res["window"]["status"] is None and res["window"]["ended_early"] is True
    assert res["window"]["end"] is None and "COMPLETED within seconds" in res["note"]
    assert "warnings" not in res
    assert get.call_count - before >= maintenance.END_NOW_READS  # bounded: gave up after ~10 s


async def test_list_shows_ended_early_not_1969(api: respx.MockRouter) -> None:
    mock_device_lookup(api)
    mock_windows(api, [ended_window("COMPLETED"), window()])
    async with Client(create_server(make_settings())) as c:
        out = await run(c, "catc_list_maintenance_windows", {"response_format": "json"})
        text = await c.call_tool("catc_list_maintenance_windows", {})
    ended, upcoming = out["results"]
    assert ended.get("end") is None and ended["ended_early"] is True and "duration" not in ended
    assert upcoming["end"] == "2099-01-10T13:00:00Z" and "ended_early" not in upcoming
    assert "end_now" in out["ended_early"]
    md = text.content[0].text  # type: ignore[union-attr]
    assert "1969" not in md and "ended_early" in md


async def test_cancel_preview_of_an_ended_window(api: respx.MockRouter) -> None:
    mock_device_lookup(api)
    mock_windows(api, [ended_window("COMPLETED")])
    async with Client(create_server(make_settings(mcp_enable_writes=True))) as c:
        preview = await run(c, "catc_cancel_maintenance", {"window": WIN_ID})
    row = preview["preview"]["window"]
    assert preview["status"] == "preview" and row["status"] == "COMPLETED"
    assert row["end"] is None and row["ended_early"] is True and "duration" not in row
    assert "1969" not in json.dumps(preview)


def test_overlaps_ignores_an_ended_window() -> None:
    """endTime -1 is below any start, so an ended window never counts as overlapping."""
    ended = ended_window(None, start=START_MS - DAY)
    assert overlaps([ended], START_MS, END_MS) == []
    assert overlaps([ended_window("COMPLETED", start=1_000)], 0, END_MS) == []
    assert overlaps([window("IN_PROGRESS")], START_MS, END_MS)  # a real window still does


def test_window_row_ended_early() -> None:
    row = window_row(ended_window(None))
    assert row["end"] is None and row["ended_early"] is True and "duration" not in row
    assert row["status"] is None
    assert window_row(window())["duration"] == "2h" and "ended_early" not in window_row(window())


async def test_update_end_now_only_for_running(api: respx.MockRouter) -> None:
    mock_device_lookup(api)
    mock_windows(api, [window()])
    put = api.put(f"{PATH}/{WIN_ID}")
    preview, _ = await flow("catc_update_maintenance_window", {"window": WIN_ID, "end_now": True})
    assert preview["status"] == "blocked" and not put.called
    assert "catc_cancel_maintenance" in preview["blockers"][0]
    async with Client(create_server(make_settings(mcp_enable_writes=True))) as c:
        with pytest.raises(ToolError, match="nothing else"):
            await run(
                c, "catc_update_maintenance_window", {"window": WIN_ID, "end_now": True, "end": END_ISO}
            )


def update_routes(api: respx.MockRouter, kept_description: str) -> respx.Route:
    """The window, then (after the PUT) the window as Catalyst Center 3.2.2 keeps it: the end moved to
    14:30Z and a weekly repeat, the description as `kept_description`."""
    rec = {"interval": 7, "recurrenceEndTime": END_MS + 30 * DAY}
    put = api.put(f"{PATH}/{WIN_ID}").respond(202, json={"response": {"taskId": "t7"}})

    def reread(request: httpx.Request) -> httpx.Response:
        w = (
            window(end=END_MS + 5_400_000, recurrence=rec, description=kept_description)
            if put.called
            else window()
        )
        return httpx.Response(200, json={"response": w, "version": "1.0"})

    api.get(f"{PATH}/{WIN_ID}").mock(side_effect=reread)
    api.get(PATH).respond(json={"response": [], "version": "1.0"})
    task_ok(api, "t7")
    return put


UPDATE_ARGS = {
    "window": WIN_ID,
    "end": "2099-01-10T14:30Z",
    "description": "mcp-chg1 uplink swap (updated)",
    "recurrence_days": 7,
    "recurrence_end": "2099-02-09T13:00Z",
}


async def test_update_warns_when_description_is_kept(api: respx.MockRouter) -> None:
    # The recorded case (3.2.2, run96 #252): task SUCCESS, end + recurrence applied, old description kept.
    mock_device_lookup(api)
    put = update_routes(api, kept_description="mcp-chg1 uplink swap")
    preview, done = await flow("catc_update_maintenance_window", UPDATE_ARGS)
    assert preview["status"] == "preview"  # a note, not a blocker: the times still change
    assert "cancel it and schedule it again" in preview["side_effects"][0]
    assert json.loads(put.calls.last.request.content)["description"] == "mcp-chg1 uplink swap (updated)"
    assert done is not None and done["status"] == "applied"
    [warning] = done["result"]["warnings"]
    assert "did not apply the description" in warning and "mcp-chg1 uplink swap (updated)" in warning
    assert done["result"]["window"]["end"] == "2099-01-10T14:30:00Z"


async def test_update_no_warning_when_everything_applied(api: respx.MockRouter) -> None:
    mock_device_lookup(api)
    update_routes(api, kept_description="mcp-chg1 uplink swap (updated)")
    _, done = await flow("catc_update_maintenance_window", UPDATE_ARGS)
    assert done is not None and done["status"] == "applied" and "warnings" not in done["result"]


async def test_update_warns_when_the_end_is_kept(api: respx.MockRouter) -> None:
    mock_device_lookup(api)
    mock_windows(api, [window()])  # the re-read shows the old end
    api.put(f"{PATH}/{WIN_ID}").respond(202, json={"response": {"taskId": "t8"}})
    task_ok(api, "t8")
    _, done = await flow("catc_update_maintenance_window", {"window": WIN_ID, "end": "2099-01-11T00:30Z"})
    assert done is not None
    [warning] = done["result"]["warnings"]
    assert "end time" in warning and "2099-01-11T00:30:00Z" in warning


async def test_update_no_false_warning_without_a_description(api: respx.MockRouter) -> None:
    # A window with no description reads back as None; the body sends "": not a dropped rename.
    mock_device_lookup(api)
    w = window()
    del w["description"]
    put = api.put(f"{PATH}/{WIN_ID}").respond(202, json={"response": {"taskId": "t9"}})

    def reread(request: httpx.Request) -> httpx.Response:
        got = dict(w, maintenanceSchedule=dict(w["maintenanceSchedule"], endTime=END_MS + 5_400_000))
        return httpx.Response(200, json={"response": got if put.called else w, "version": "1.0"})

    api.get(f"{PATH}/{WIN_ID}").mock(side_effect=reread)
    api.get(PATH).respond(json={"response": [], "version": "1.0"})
    task_ok(api, "t9")
    _, done = await flow("catc_update_maintenance_window", {"window": WIN_ID, "end": "2099-01-10T14:30Z"})
    assert done is not None and done["status"] == "applied" and "warnings" not in done["result"]


async def test_update_description_only_is_blocked(api: respx.MockRouter) -> None:
    mock_device_lookup(api)
    mock_windows(api, [window()])
    put = api.put(f"{PATH}/{WIN_ID}")
    preview, _ = await flow("catc_update_maintenance_window", {"window": WIN_ID, "description": "mcp-new"})
    assert preview["status"] == "blocked" and not put.called
    assert any("cannot be updated" in b and "nothing to send" in b for b in preview["blockers"])


async def test_update_stop_repeating_drops_recurrence(api: respx.MockRouter) -> None:
    mock_device_lookup(api)
    mock_windows(api, [window(recurrence={"interval": 7, "recurrenceEndTime": END_MS + 60 * DAY})])
    put = api.put(f"{PATH}/{WIN_ID}").respond(202, json={"response": {"taskId": "t4"}})
    task_ok(api, "t4")
    await flow("catc_update_maintenance_window", {"window": WIN_ID, "stop_repeating": True})
    assert "recurrence" not in json.loads(put.calls.last.request.content)["maintenanceSchedule"]


async def test_cancel_upcoming(api: respx.MockRouter) -> None:
    mock_device_lookup(api)
    mock_windows(api, [window()])
    delete = api.delete(f"{PATH}/{WIN_ID}").respond(202, json={"response": {"taskId": "t5"}})
    task_ok(api, "t5")
    preview, done = await flow("catc_cancel_maintenance", {"window": WIN_ID})
    assert preview["preview"]["window"]["devices"] == ["edge-sw1.lab.local"]
    assert "raises issues" in preview["side_effects"][0]
    assert delete.call_count == 1 and done is not None and done["result"]["cancelled"] == WIN_ID


async def test_cancel_running_is_blocked(api: respx.MockRouter) -> None:
    # Recorded refusal (3.2.2, run96 #258): "The maintenance window is in progress ... cannot be deleted."
    mock_device_lookup(api)
    mock_windows(api, [window("IN_PROGRESS")])
    delete = api.delete(f"{PATH}/{WIN_ID}")
    preview, _ = await flow("catc_cancel_maintenance", {"window": WIN_ID})
    assert preview["status"] == "blocked" and not delete.called
    assert len(preview["blockers"]) == 1 and RULE in preview["blockers"][0]
    assert "end_now=true" in preview["blockers"][0]


async def test_cancel_maps_the_started_refusal(api: respx.MockRouter) -> None:
    """The window started between preview and confirm: the DELETE task's refusal comes back in plain words."""
    mock_device_lookup(api)
    mock_windows(api, [window()])
    api.delete(f"{PATH}/{WIN_ID}").respond(202, json={"response": {"taskId": "t6"}})
    api.get("/dna/intent/api/v1/task/t6").respond(
        json={"response": {"isError": True, "endTime": 1, "failureReason": DELETE_REFUSAL}}
    )
    async with Client(create_server(make_settings(mcp_enable_writes=True))) as c:
        preview = await run(c, "catc_cancel_maintenance", {"window": WIN_ID})
        with pytest.raises(ToolError) as exc:
            await run(c, "catc_cancel_maintenance", {"window": WIN_ID, "confirm": preview["confirm"]})
    assert RULE in str(exc.value) and "cannot be deleted" in str(exc.value)


def test_started_refusal_matching() -> None:
    assert is_started_refusal(TaskFailed(f"cancel maintenance failed: {DELETE_REFUSAL} (task id t6)"))
    assert is_started_refusal(ValidationFailed(f"Bad request: {PUT_REFUSAL}", 400))
    assert not is_started_refusal(TaskFailed("NCSP10011: device unreachable"))
    assert "it ends at its end time" in started_blocker(None)


async def test_schedule_says_a_started_window_is_locked(api: respx.MockRouter) -> None:
    mock_device_lookup(api)
    mock_windows(api, [])
    args = {"devices": ["edge-sw1"], "start": START_ISO, "end": END_ISO, "description": "mcp-chg3"}
    async with Client(create_server(make_settings(mcp_enable_writes=True))) as c:
        preview = await run(c, "catc_schedule_maintenance", args)
    assert any("can't be cancelled or given a new end time" in e for e in preview["side_effects"])


async def test_ambiguous_description(api: respx.MockRouter) -> None:
    mock_windows(api, [window(), window(wid="w2")])
    async with Client(create_server(make_settings(mcp_enable_writes=True))) as c:
        with pytest.raises(ToolError, match="use the id"):
            await run(c, "catc_cancel_maintenance", {"window": "mcp-chg1 uplink swap"})


async def test_writes_hidden_when_read_only() -> None:
    async with Client(create_server(make_settings())) as c:
        names = {t.name for t in await c.list_tools()}
    assert "catc_list_maintenance_windows" in names
    assert not names & {
        "catc_schedule_maintenance",
        "catc_update_maintenance_window",
        "catc_cancel_maintenance",
    }
    assert DEVICE["id"] == DEV_ID
