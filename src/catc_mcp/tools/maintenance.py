"""Device maintenance windows (roadmap D73): schedule, list, update and cancel the network-device
maintenance schedules (`/dna/intent/api/v1/networkDeviceMaintenanceSchedules`, Catalyst Center 3.2.2).

While a window is running Catalyst Center puts its devices in maintenance mode: Assurance stops computing
their health and raising their issues, so the alerts a change window would otherwise produce (link flaps,
reachability, the health dip) stay quiet, and so do real problems on those devices. The API speaks epoch
milliseconds; these tools take and return ISO 8601 with a UTC offset. Writes return an Intent API task.

The spec quirks (3.2.2): the create body lists `id` and a top-level `status` as required, but `id` is
read-only and `status` only exists inside `maintenanceSchedule` (read-only too): neither is sent.
`networkDeviceIds` is set at creation only; an update keeps the devices (cancel and schedule again to
change them). The list filter takes at most 25 device ids.
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import contextlib
from datetime import UTC, datetime
from typing import Annotated, Any, Literal

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field

from catc_mcp._core import (
    Confirm,
    InvalidRequest,
    NotFound,
    Plan,
    ResponseFormat,
    ToolRegistrar,
    UpstreamError,
    get_client,
    list_result,
    preview_or_apply,
)
from catc_mcp._core.http import Page, fetch_all
from catc_mcp.client import CatcApp, safe_id
from catc_mcp.common import ensure_list, inventory_names, is_uuid, resolve_device, resolve_site
from catc_mcp.safety import resolve_targets, site_devices

PATH = "/dna/intent/api/v1/networkDeviceMaintenanceSchedules"
STATUSES = ("UPCOMING", "IN_PROGRESS", "COMPLETED", "FAILED")
Status = Literal["UPCOMING", "IN_PROGRESS", "COMPLETED", "FAILED"]
MAX_DEVICES = 500  # spec: networkDeviceIds maxItems
MAX_INTERVAL_DAYS = 365
DAY_MS = 86_400_000
# What every schedule/update preview says about maintenance mode.
GOES_DARK = (
    "While the window runs, Catalyst Center puts these devices in maintenance mode: Assurance computes no "
    "health for them and raises no issues, so real problems on them stay quiet too, not only the ones the "
    "change causes."
)
RUNS_FULL = (
    "A started window runs for its full duration: the devices leave maintenance mode at the end time, not "
    "when the change is done. Pick an end time that covers the change and its verification, no more."
)

IsoTime = Annotated[
    str,
    Field(
        description="ISO 8601 with a UTC offset, e.g. 2026-10-30T22:00+11:00 or 2026-10-30T11:00Z",
        min_length=10,
        max_length=40,
    ),
]


# --- time ----------------------------------------------------------------------------------------


def to_ms(value: str, what: str) -> int:
    """ISO 8601 with an offset -> epoch milliseconds (InvalidRequest when there is no offset)."""
    text = value.strip()
    if text.endswith(("z", "Z")):
        text = text[:-1] + "+00:00"
    try:
        when = datetime.fromisoformat(text)
    except ValueError as exc:
        raise InvalidRequest(f"{what} must be ISO 8601, e.g. 2026-10-30T22:00+11:00 ({value!r}).") from exc
    if when.tzinfo is None:
        raise InvalidRequest(f"{what} needs a UTC offset, e.g. 2026-10-30T22:00+11:00 ({value!r}).")
    return int(when.timestamp() * 1000)


def to_iso(ms: Any) -> str | None:
    """Epoch milliseconds -> ISO 8601 UTC ('...Z'); None for a missing or bad value."""
    try:
        when = datetime.fromtimestamp(float(ms) / 1000, tz=UTC)
    except (TypeError, ValueError, OverflowError, OSError):
        return None
    return when.isoformat(timespec="seconds").replace("+00:00", "Z")


def now_ms() -> int:
    return int(datetime.now(UTC).timestamp() * 1000)


def duration_text(ms: int) -> str:
    minutes = max(ms, 0) // 60_000
    days, rest = divmod(minutes, 1440)
    hours, mins = divmod(rest, 60)
    parts = [f"{days}d" if days else "", f"{hours}h" if hours else "", f"{mins}m" if mins else ""]
    return " ".join(p for p in parts if p) or "0m"


def schedule_blockers(
    start: int,
    end: int,
    recurrence_days: int | None,
    recurrence_end: int | None,
    *,
    started: bool = False,
    now: int | None = None,
) -> list[str]:
    """Why Catalyst Center would refuse these times (empty when they are fine). `started`: the window is
    already running, so its start time is in the past and is not checked."""
    now = now_ms() if now is None else now
    out: list[str] = []
    if end <= start:
        out.append("The end time must be after the start time.")
    if not started and start <= now:
        out.append(f"The start time {to_iso(start)} is not in the future (now {to_iso(now)}).")
    if end <= now:
        out.append(f"The end time {to_iso(end)} is not in the future (now {to_iso(now)}).")
    if recurrence_days is None and recurrence_end is not None:
        out.append("recurrence_end needs recurrence_days (the repeat interval in days).")
    if recurrence_days is not None:
        if not 1 <= recurrence_days <= MAX_INTERVAL_DAYS:
            out.append(f"recurrence_days must be 1-{MAX_INTERVAL_DAYS}.")
        elif recurrence_days * DAY_MS <= end - start:
            out.append(
                f"The window lasts {duration_text(end - start)}, longer than the {recurrence_days}-day "
                "repeat interval: Catalyst Center needs the interval longer than the window."
            )
        if recurrence_end is None:
            out.append("A recurring window needs recurrence_end (when the repeats stop).")
        elif recurrence_end <= end:
            out.append("recurrence_end must be after the window's end time.")
    return out


# --- records -------------------------------------------------------------------------------------


def sched(w: dict[str, Any]) -> dict[str, Any]:
    s = w.get("maintenanceSchedule")
    return s if isinstance(s, dict) else {}


def window_status(w: dict[str, Any]) -> str:
    return str(sched(w).get("status") or w.get("status") or "")


def device_ids(w: dict[str, Any]) -> list[str]:
    return [str(i) for i in ensure_list(w.get("networkDeviceIds")) if i]


def window_row(w: dict[str, Any], names: dict[str, str] | None = None) -> dict[str, Any]:
    s = sched(w)
    ids = device_ids(w)
    row: dict[str, Any] = {
        "id": w.get("id"),
        "description": w.get("description"),
        "status": window_status(w) or None,
        "start": to_iso(s.get("startTime")),
        "end": to_iso(s.get("endTime")),
    }
    with contextlib.suppress(KeyError, TypeError, ValueError):
        row["duration"] = duration_text(int(s["endTime"]) - int(s["startTime"]))
    rec = s.get("recurrence")
    if isinstance(rec, dict) and rec.get("interval"):
        row["repeats_every_days"] = rec.get("interval")
        row["repeats_until"] = to_iso(rec.get("recurrenceEndTime"))
    row["device_count"] = len(ids)
    if names is not None:
        row["devices"] = [names.get(i, f"{i} (not in inventory)") for i in ids]
    else:
        row["device_ids"] = ids
    for key in ("startId", "endId"):
        if s.get(key):
            row[key] = s[key]  # activity ids (GET /dna/intent/api/v1/activities/{id})
    if row["status"] == "FAILED":
        row["note"] = (
            "Catalyst Center could not change the devices' management state; the startId/endId activities "
            "say why (catc_api_call GET /dna/intent/api/v1/activities/<id>)."
        )
    return row


def brief(devs: list[dict[str, Any]]) -> list[str]:
    return [f"{d.get('hostname') or d.get('id')} ({d.get('managementIpAddress')})" for d in devs]


async def get_window(app: CatcApp, ref: str) -> dict[str, Any]:
    """A maintenance window by id, or by its exact description when that is unique."""
    ref = ref.strip()
    if is_uuid(ref):
        try:
            w = await app.get_response(f"{PATH}/{safe_id(ref, 'maintenance window id')}")
        except NotFound:
            w = None
        if isinstance(w, dict) and w.get("id"):
            return w
        raise NotFound(f"No maintenance window with id {ref}. List them with catc_list_maintenance_windows.")
    page = await fetch_all(app.pager, app.api, PATH, {}, cap=2000)
    found = [
        w
        for w in page.items
        if isinstance(w, dict) and str(w.get("description") or "").strip().lower() == ref.lower()
    ]
    if len(found) == 1:
        return found[0]
    if found:
        ids = ", ".join(str(w.get("id")) for w in found[:10])
        raise InvalidRequest(f"{len(found)} maintenance windows are described {ref!r} ({ids}); use the id.")
    raise NotFound(
        f"No maintenance window with id or description {ref!r}. List them with catc_list_maintenance_windows."
    )


async def windows_for(app: CatcApp, ids: list[str]) -> list[dict[str, Any]]:
    """Every UPCOMING or IN_PROGRESS window that includes any of these devices (for overlap warnings)."""
    out: dict[str, dict[str, Any]] = {}
    wanted = set(ids)
    for status in ("UPCOMING", "IN_PROGRESS"):
        page = await fetch_all(app.pager, app.api, PATH, {"status": status}, cap=2000)
        for w in page.items:
            if isinstance(w, dict) and wanted & set(device_ids(w)):
                out[str(w.get("id"))] = w
    return list(out.values())


def overlaps(windows: list[dict[str, Any]], start: int, end: int, skip: str | None = None) -> list[str]:
    hits: list[str] = []
    for w in windows:
        if skip and str(w.get("id")) == skip:
            continue
        s = sched(w)
        try:
            ws, we = int(s["startTime"]), int(s["endTime"])
        except (KeyError, TypeError, ValueError):
            continue
        if ws < end and start < we:
            hits.append(
                f"{w.get('description') or w.get('id')} ({to_iso(ws)} to {to_iso(we)}, "
                f"{window_status(w) or 'status unknown'})"
            )
    return hits


def recurrence_body(days: int | None, until: int | None) -> dict[str, Any] | None:
    if days is None or until is None:
        return None
    return {"interval": days, "recurrenceEndTime": until}


async def find_created(app: CatcApp, first_device: str, start: int, end: int) -> dict[str, Any] | None:
    try:
        rows = ensure_list(await app.get_response(PATH, {"networkDeviceIds": first_device, "limit": 500}))
    except UpstreamError:
        return None
    for w in rows:
        if not isinstance(w, dict):
            continue
        s = sched(w)
        if str(s.get("startTime")) == str(start) and str(s.get("endTime")) == str(end):
            return w
    return None


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="List maintenance windows")
    async def catc_list_maintenance_windows(
        ctx: Context,
        device: Annotated[
            str | None, Field(description="Only windows including this device (hostname, IP, serial or id)")
        ] = None,
        site: Annotated[
            str | None,
            Field(
                description="Only windows including a device under this site (path or id; child sites too)"
            ),
        ] = None,
        status: Annotated[
            Status | None,
            Field(
                description="UPCOMING (scheduled), IN_PROGRESS (devices in maintenance now), COMPLETED (for "
                "a recurring window: the latest occurrence) or FAILED (the devices' state change failed)"
            ),
        ] = None,
        limit: Annotated[int, Field(ge=1, le=500)] = 50,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """Catalyst Center device maintenance windows: description, status (UPCOMING, IN_PROGRESS,
        COMPLETED, FAILED), start and end in ISO 8601 UTC, duration, recurrence (every N days until a
        date), and the devices by hostname. Devices in an IN_PROGRESS window are in maintenance mode:
        Assurance raises no issues and computes no health for them, so a quiet catc_list_issues on them
        means nothing until the window ends. Filter by device, site (child sites included) or status.
        Schedule one with catc_schedule_maintenance."""
        app: CatcApp = get_client(ctx)
        if device and site:
            raise InvalidRequest("Give device or site, not both.")
        params: dict[str, Any] = {}
        if status:
            params["status"] = status
        extra: dict[str, Any] = {}
        if site:
            s = await resolve_site(app, site)
            wanted = {str(d["id"]) for d in await site_devices(app, s) if d.get("id")}
            extra["site"] = s.get("nameHierarchy")
            everything = await fetch_all(app.pager, app.api, PATH, params, cap=2000)
            rows = [w for w in everything.items if isinstance(w, dict) and wanted & set(device_ids(w))]
            page = Page(items=rows[offset : offset + limit], offset=offset, total=len(rows))
        else:
            if device:
                d = await resolve_device(app, device)
                params["networkDeviceIds"] = str(d["id"])
                extra["device"] = d.get("hostname") or d.get("managementIpAddress")
            page = await app.pager.fetch_page(app.api, PATH, params, limit=limit, offset=offset, max_page=500)
        windows = [w for w in page.items if isinstance(w, dict)]
        names = await inventory_names(app, [i for w in windows for i in device_ids(w)])
        page.items = [window_row(w, names) for w in windows]
        if any(r.get("status") == "IN_PROGRESS" for r in page.items):
            extra["note"] = (
                "Devices in an IN_PROGRESS window are in maintenance mode: no health and no issues for them "
                "until it ends."
            )
        if not page.items and offset == 0:
            extra["note"] = "No maintenance windows" + (f" with status {status}" if status else "") + "."
        return list_result(
            page,
            fmt=response_format,
            columns=["description", "status", "start", "end", "repeats_every_days", "device_count", "id"],
            extra=extra or None,
        )

    @reg.write(title="Schedule maintenance window")
    async def catc_schedule_maintenance(
        ctx: Context,
        start: IsoTime,
        end: IsoTime,
        description: Annotated[
            str,
            Field(
                min_length=1,
                max_length=255,
                description="What the window is for, with the change number, e.g. 'mcp-chg1234 uplink swap'",
            ),
        ],
        devices: Annotated[
            list[str] | None,
            Field(max_length=MAX_DEVICES, description="Devices (hostname, IP, serial or id)"),
        ] = None,
        site: Annotated[
            str | None, Field(description="Every device under this site (path or id; child sites too)")
        ] = None,
        tag: Annotated[str | None, Field(description="Every device with this tag")] = None,
        recurrence_days: Annotated[
            int | None,
            Field(
                ge=1,
                le=MAX_INTERVAL_DAYS,
                description="Repeat every N days (e.g. 7 for a weekly window); longer than the window itself",
            ),
        ] = None,
        recurrence_end: Annotated[
            str | None,
            Field(description="When the repeats stop (ISO 8601 with offset); with recurrence_days"),
        ] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Schedule a Catalyst Center maintenance window for devices (a list, every device under a site, or
        a tag), optionally repeating every N days, so a planned change doesn't raise an alert storm.
        Times are ISO 8601 with an offset. Preview-first: the preview lists every device the window covers
        (the blast radius), the times in UTC and the duration, other windows on those devices that overlap,
        and warns that health and issues go dark for those devices and that a started window runs to its
        end time. Refused when the start is in the past, the end is before the start, or a recurrence is
        shorter than the window. Check with catc_list_maintenance_windows; change it with
        catc_update_maintenance_window, remove it with catc_cancel_maintenance."""
        app: CatcApp = get_client(ctx)
        start_ms, end_ms = to_ms(start, "start"), to_ms(end, "end")
        until_ms = to_ms(recurrence_end, "recurrence_end") if recurrence_end else None
        devs, targeting = await resolve_targets(app, devices, site, tag)
        if not devs:
            raise InvalidRequest(f"No devices to put in maintenance ({targeting}).")
        blockers = schedule_blockers(start_ms, end_ms, recurrence_days, until_ms)
        if len(devs) > MAX_DEVICES:
            blockers.append(
                f"{len(devs)} devices is more than one window takes ({MAX_DEVICES}); split it by site or tag."
            )
        ids = sorted(str(d["id"]) for d in devs)
        existing = await windows_for(app, ids)
        clash = overlaps(existing, start_ms, end_ms)
        body: dict[str, Any] = {
            "description": description,
            "maintenanceSchedule": {"startTime": start_ms, "endTime": end_ms},
            "networkDeviceIds": ids,
        }
        rec = recurrence_body(recurrence_days, until_ms)
        if rec:
            body["maintenanceSchedule"]["recurrence"] = rec
        side_effects = [GOES_DARK, RUNS_FULL, "Nothing changes in the devices' configuration."]
        if rec:
            side_effects.append(
                f"It repeats every {recurrence_days} day(s) until {to_iso(until_ms)}: every occurrence "
                "silences these devices the same way."
            )
        details: dict[str, Any] = {
            "devices": brief(devs),
            "targets": targeting,
            "start": to_iso(start_ms),
            "end": to_iso(end_ms),
            "duration": duration_text(end_ms - start_ms),
            "method": "POST",
            "path": PATH,
            "body": body,
        }
        if rec:
            details["repeats"] = {"every_days": recurrence_days, "until": to_iso(until_ms)}
        if clash:
            details["overlapping_windows"] = clash
            side_effects.append(
                "These devices already have an overlapping window (overlapping_windows); Catalyst Center may "
                "refuse the new one."
            )
        plan = Plan(
            f"Schedule maintenance {description!r} for {len(devs)} device(s), {to_iso(start_ms)} to "
            f"{to_iso(end_ms)}" + (f", every {recurrence_days} day(s)" if rec else ""),
            details=details,
            side_effects=side_effects,
            fingerprint={"devices": ids, "existing": sorted(str(w.get("id")) for w in existing)},
            blockers=blockers,
            blast_radius=len(devs),
        )

        async def apply() -> Any:
            job = await app.run_job("POST", PATH, body, ctx=ctx, what="schedule maintenance")
            out: dict[str, Any] = {"task": job}
            made = await find_created(app, ids[0], start_ms, end_ms)
            if made:
                names = {str(d["id"]): str(d.get("hostname") or d["id"]) for d in devs}
                out["window"] = window_row(made, names)
            else:
                out["check_with"] = "catc_list_maintenance_windows(status='UPCOMING')"
            return out

        return await preview_or_apply(
            ctx,
            tool="catc_schedule_maintenance",
            args={
                "start": start,
                "end": end,
                "description": description,
                "devices": devices,
                "site": site,
                "tag": tag,
                "recurrence_days": recurrence_days,
                "recurrence_end": recurrence_end,
            },
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.write(title="Update maintenance window")
    async def catc_update_maintenance_window(
        ctx: Context,
        window: Annotated[str, Field(description="Maintenance window id, or its exact description")],
        start: Annotated[str | None, Field(description="New start (ISO 8601 with offset)")] = None,
        end: Annotated[str | None, Field(description="New end (ISO 8601 with offset)")] = None,
        description: Annotated[
            str | None, Field(min_length=1, max_length=255, description="New description")
        ] = None,
        recurrence_days: Annotated[
            int | None, Field(ge=1, le=MAX_INTERVAL_DAYS, description="New repeat interval in days")
        ] = None,
        recurrence_end: Annotated[
            str | None, Field(description="New end of the repeats (ISO 8601 with offset)")
        ] = None,
        stop_repeating: Annotated[
            bool, Field(description="Make a recurring window a one-off (drops the recurrence)")
        ] = False,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Change a maintenance window's start, end, description or recurrence (times ISO 8601 with an
        offset). The devices can't be changed (Catalyst Center sets them at creation): cancel and schedule
        again for that. Preview-first: before and after times, the devices it covers, overlaps with other
        windows on those devices. A running (IN_PROGRESS) window keeps its start; moving its end changes
        when the devices come out of maintenance. COMPLETED or FAILED one-off windows are refused."""
        app: CatcApp = get_client(ctx)
        if stop_repeating and (recurrence_days is not None or recurrence_end is not None):
            raise InvalidRequest("Give stop_repeating or a new recurrence, not both.")
        if (
            not any(v is not None for v in (start, end, description, recurrence_days, recurrence_end))
            and not stop_repeating
        ):
            raise InvalidRequest("Nothing to change: give start, end, description or a recurrence change.")
        w = await get_window(app, window)
        wid = str(w.get("id"))
        s = sched(w)
        status = window_status(w)
        try:
            cur_start, cur_end = int(s["startTime"]), int(s["endTime"])
        except (KeyError, TypeError, ValueError) as exc:
            raise InvalidRequest(f"Maintenance window {wid} has no start/end time to update.") from exc
        cur_rec = s.get("recurrence") if isinstance(s.get("recurrence"), dict) else None
        new_start = to_ms(start, "start") if start else cur_start
        new_end = to_ms(end, "end") if end else cur_end
        if stop_repeating:
            days, until = None, None
        else:
            days = recurrence_days if recurrence_days is not None else (cur_rec or {}).get("interval")
            until = (
                to_ms(recurrence_end, "recurrence_end")
                if recurrence_end
                else (cur_rec or {}).get("recurrenceEndTime")
            )
            days = int(days) if days is not None else None
            until = int(until) if until is not None else None
        started = status == "IN_PROGRESS"
        blockers = schedule_blockers(new_start, new_end, days, until, started=started)
        if started and start and new_start != cur_start:
            blockers.append(
                "The window is already running (IN_PROGRESS): its start can't move. Change the end, or "
                "cancel it and schedule a new one."
            )
        if status in ("COMPLETED", "FAILED") and not cur_rec:
            blockers.append(f"The window is {status}; schedule a new one instead.")
        ids = device_ids(w)
        names = await inventory_names(app, ids)
        existing = await windows_for(app, ids) if ids else []
        clash = overlaps(existing, new_start, new_end, skip=wid)
        body: dict[str, Any] = {
            "description": description if description is not None else (w.get("description") or ""),
            "maintenanceSchedule": {"startTime": new_start, "endTime": new_end},
            # Read-only on update, but the 3.2.2 schema requires it: send the window's own devices back.
            "networkDeviceIds": ids,
        }
        rec = recurrence_body(days, until)
        if rec:
            body["maintenanceSchedule"]["recurrence"] = rec
        before = window_row(w, names)
        after = {
            "description": body["description"],
            "start": to_iso(new_start),
            "end": to_iso(new_end),
            "duration": duration_text(new_end - new_start),
            "repeats_every_days": days if rec else None,
            "repeats_until": to_iso(until) if rec else None,
        }
        side_effects = [GOES_DARK, RUNS_FULL]
        if started and new_end != cur_end:
            side_effects.append(
                f"The window is running: the devices now leave maintenance mode at {to_iso(new_end)} instead "
                f"of {to_iso(cur_end)}."
            )
        details: dict[str, Any] = {
            "before": before,
            "after": after,
            "method": "PUT",
            "path": f"{PATH}/{wid}",
            "body": body,
        }
        if clash:
            details["overlapping_windows"] = clash
        plan = Plan(
            f"Update maintenance window {w.get('description') or wid} ({len(ids)} device(s))",
            details=details,
            side_effects=side_effects,
            fingerprint={"window": wid, "schedule": s, "description": w.get("description")},
            blockers=blockers,
            blast_radius=len(ids),
        )

        async def apply() -> Any:
            job = await app.run_job(
                "PUT", f"{PATH}/{safe_id(wid, 'maintenance window id')}", body, ctx=ctx, what="update"
            )
            out: dict[str, Any] = {"task": job}
            try:
                out["window"] = window_row(await get_window(app, wid), names)
            except UpstreamError as err:
                out["window"] = {"unavailable": str(err)[:200]}
            return out

        return await preview_or_apply(
            ctx,
            tool="catc_update_maintenance_window",
            args={
                "window": window,
                "start": start,
                "end": end,
                "description": description,
                "recurrence_days": recurrence_days,
                "recurrence_end": recurrence_end,
                "stop_repeating": stop_repeating,
            },
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.write(title="Cancel maintenance window", destructive=True)
    async def catc_cancel_maintenance(
        ctx: Context,
        window: Annotated[str, Field(description="Maintenance window id, or its exact description")],
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Delete a maintenance window (and every future occurrence of a recurring one). Preview-first: the
        window, its status, times and devices. Cancelling an UPCOMING window means its devices are never
        silenced, so a change made then raises issues and pages as usual. For a running (IN_PROGRESS)
        window the preview warns that the devices may stay in maintenance mode until the end time; check
        with catc_list_maintenance_windows and catc_device_360 afterwards."""
        app: CatcApp = get_client(ctx)
        w = await get_window(app, window)
        wid = str(w.get("id"))
        ids = device_ids(w)
        names = await inventory_names(app, ids)
        row = window_row(w, names)
        status = window_status(w)
        side_effects = ["Nothing changes in the devices' configuration."]
        if status == "UPCOMING":
            side_effects.insert(
                0,
                "The devices won't be in maintenance mode at that time: a change made then raises issues and "
                "health alerts as usual.",
            )
        elif status == "IN_PROGRESS":
            side_effects.insert(
                0,
                f"The window is running now. {RUNS_FULL.split(':')[0]}: the devices may stay in maintenance "
                f"mode until {row.get('end')} even after the cancel; check catc_device_360 afterwards.",
            )
        if row.get("repeats_every_days"):
            side_effects.append("Every future occurrence of this recurring window goes too.")
        plan = Plan(
            f"Cancel maintenance window {w.get('description') or wid} "
            f"({len(ids)} device(s), {status or '?'})",
            details={"window": row, "method": "DELETE", "path": f"{PATH}/{wid}"},
            side_effects=side_effects,
            fingerprint={"window": wid, "status": status, "schedule": sched(w)},
            blast_radius=len(ids),
        )

        async def apply() -> Any:
            job = await app.run_job(
                "DELETE",
                f"{PATH}/{safe_id(wid, 'maintenance window id')}",
                ctx=ctx,
                what="cancel maintenance",
            )
            return {"cancelled": wid, "description": w.get("description"), "task": job}

        return await preview_or_apply(
            ctx,
            tool="catc_cancel_maintenance",
            args={"window": window},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )
