"""Catalyst Center activities (roadmap D120, #236): what the scheduler ran, runs, or will run.

`GET /dna/intent/api/v1/activities` lists the appliance's activities: recurring system jobs (the weekly
config-archive backup, the security-advisory scan), one-off jobs it ran on its own (bug and advisory scans,
"Deploy Intended Config Features on <device>", IP-SLA sessions) and scheduled user work. Each has a
description, status, type, recurring flag and epoch-ms start/end. `/activities/count` gives the total;
`/activities/{id}/triggeredJobs` (+ `/count`) the jobs one activity started, each with its task id.

Checked live on the 3.2.2 lab appliance (2026-10-28, read-only):
- `type` is DEFAULT on every row, a value the spec's enum (TASK, WORK_ITEM) doesn't list.
- Recurring rows have endTime 0, and their startTime is when the schedule began, not the next run.
- One-off rows sometimes report an endTime a few seconds before startTime; no duration is given then.
- The status and recurring filters work server-side; description is an exact match only, and the
  startTime/endTime filters return nothing for windows that hold activities. So description_filter
  (substring) and since/until are applied here, over the whole list.
- GET one activity answers at `/dna/intent/api/v1/activities/{id}`; the spec's doubled prefix
  (`/dna/intent/api/v1/intent/api/v1/activities/{id}`) is a 404 ("BAPI not found"). The doubled path is
  kept as a fallback for releases that serve it.
- Triggered jobs carry a `failureReason` (not in the spec) when a job failed.
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import contextlib
from typing import Annotated, Any, Literal

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field

from catc_mcp._core import InvalidRequest, NotFound, ResponseFormat, ToolRegistrar, get_client
from catc_mcp._core.formatting import dumps, to_markdown
from catc_mcp._core.http import fetch_all
from catc_mcp.client import CatcApp, safe_id
from catc_mcp.common import ago, ensure_list, is_uuid
from catc_mcp.tools.maintenance import now_ms, to_iso, to_ms

ACTIVITIES = "/dna/intent/api/v1/activities"
# The spec's path for one activity; a 404 on 3.2.2 (see the module docstring).
ACTIVITY_SPEC_PATH = "/dna/intent/api/v1/intent/api/v1/activities"
CAP = 2000
JOB_CAP = 200

Status = Literal["PENDING", "RUNNING", "SUCCESS", "FAILED", "READY", "DISCARD_FAILED", "DISCARD_SUCCESS"]
FAILED = {"FAILED", "DISCARD_FAILED"}
FINISHED = {"SUCCESS", "FAILED", "DISCARD_FAILED", "DISCARD_SUCCESS"}
IN_PROGRESS = {"RUNNING", "READY"}
SECTIONS = ("upcoming", "in_progress", "recurring", "finished")


def _ms(v: Any) -> int | None:
    if isinstance(v, bool) or not isinstance(v, int | float) or v <= 0:
        return None
    return int(v)


def _from_now(ms: int, now: int) -> str:
    """'in 2h05m' for a future epoch-ms time."""
    text = ago(now - (ms - now), now) or "0s ago"
    return "in " + text.removesuffix(" ago")


def section(a: dict[str, Any], now: int) -> str:
    """upcoming / in_progress / recurring / finished for one activity."""
    status = str(a.get("status") or "").upper()
    if a.get("recurring") is True:
        return "recurring"
    if status in IN_PROGRESS:
        return "in_progress"
    start = _ms(a.get("startTime"))
    if status == "PENDING" or (status not in FINISHED and start is not None and start > now):
        return "upcoming"
    return "finished"


def activity_row(a: dict[str, Any], now: int) -> dict[str, Any]:
    start, end = _ms(a.get("startTime")), _ms(a.get("endTime"))
    recurring = a.get("recurring") is True
    row: dict[str, Any] = {
        "description": a.get("description"),
        "status": a.get("status"),
        "failed": True if str(a.get("status") or "").upper() in FAILED else None,
        "type": a.get("type"),
        "recurring": recurring,
        ("schedule_start" if recurring else "start"): to_iso(start) if start else None,
        "end": to_iso(end) if end and not recurring else None,
        "duration_s": round((end - start) / 1000, 1) if start and end and end >= start else None,
        "id": a.get("id"),
        "originating_work_item": a.get("originatingWorkItemActivityId"),
    }
    if start and not recurring:
        row["when"] = ago(start, now) if start <= now else _from_now(start, now)
    return {k: v for k, v in row.items() if v is not None}


def job_row(j: dict[str, Any]) -> dict[str, Any]:
    row: dict[str, Any] = {
        "description": j.get("description"),
        "status": j.get("status"),
        "failure_reason": j.get("failureReason"),
        "task_id": j.get("taskId"),
        "task_url": j.get("taskUrl"),
        "id": j.get("id"),
    }
    return {k: v for k, v in row.items() if v not in (None, "")}


def in_window(a: dict[str, Any], since: int | None, until: int | None) -> bool:
    """One-off activities whose start (or end) falls in the window; recurring ones whose schedule began by
    `until` (they keep running, so `since` doesn't drop them)."""
    start, end = _ms(a.get("startTime")), _ms(a.get("endTime"))
    if a.get("recurring") is True:
        return until is None or start is None or start <= until
    times = [t for t in (start, end) if t is not None]
    if not times:
        return since is None and until is None
    return any((since is None or t >= since) and (until is None or t <= until) for t in times)


def _order(name: str, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    def start(a: dict[str, Any]) -> int:
        return _ms(a.get("startTime")) or 0

    if name == "upcoming":
        return sorted(rows, key=start)  # soonest first
    if name == "finished":
        # Failed first, newest first within each group.
        return sorted(rows, key=lambda a: (str(a.get("status") or "").upper() not in FAILED, -start(a)))
    return sorted(rows, key=lambda a: -start(a))


async def _count(app: CatcApp, path: str, params: dict[str, Any] | None = None) -> int | None:
    with contextlib.suppress(Exception):
        data = await app.get_response(path, params)
        if isinstance(data, dict) and isinstance(data.get("count"), int | float):
            return int(data["count"])
    return None


async def fetch_activity(app: CatcApp, activity: str) -> dict[str, Any]:
    """One activity by id (or exact description)."""
    key = activity.strip()
    if not key:
        raise InvalidRequest("Give an activity id (from catc_list_activities) or its exact description.")
    if is_uuid(key):
        aid = safe_id(key, "activity id")
        data: Any = None
        try:
            data = await app.get_response(f"{ACTIVITIES}/{aid}")
        except NotFound:
            # TODO(live): 3.2.2 answers only the single prefix; the doubled spec path is a fallback.
            with contextlib.suppress(NotFound):
                data = await app.get_response(f"{ACTIVITY_SPEC_PATH}/{aid}")
        if isinstance(data, list):
            data = data[0] if data else None
        if isinstance(data, dict) and data.get("id"):
            return data
        raise NotFound(f"No activity {aid}. List them with catc_list_activities.")
    rows = [
        a
        for a in ensure_list(await app.get_response(ACTIVITIES, {"description": key}))
        if isinstance(a, dict)
    ]
    if len(rows) == 1:
        return rows[0]
    if not rows:
        raise NotFound(
            f"No activity described exactly as {key!r}. "
            "Find it with catc_list_activities(description_filter=...) and pass its id."
        )
    now = now_ms()
    listed = "; ".join(
        f"{a.get('id')} ({a.get('status')}, {activity_row(a, now).get('start') or 'recurring'})"
        for a in _order("in_progress", rows)[:10]
    )
    raise InvalidRequest(f"{len(rows)} activities are described as {key!r}; pass one id: {listed}.")


COLUMNS = ["section", "status", "description", "start", "schedule_start", "end", "when", "id"]


def render(out: dict[str, Any], fmt: str) -> ToolResult:
    """JSON: the sections as lists; markdown: a header line and one table with a section column."""
    if fmt != "markdown":
        return ToolResult(content=dumps(out), structured_content=out)
    head = {k: v for k, v in out.items() if k not in SECTIONS and k != "notes"}
    header = ", ".join(f"{k}: {v}" for k, v in head.items())
    rows = [{"section": s, **r} for s in SECTIONS for r in out.get(s, [])]
    text = f"{header}\n\n{to_markdown(rows, columns=COLUMNS)}"
    if out.get("notes"):
        text += "\n\n" + "\n".join(f"- {n}" for n in out["notes"])
    return ToolResult(content=text)


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="List activities")
    async def catc_list_activities(
        ctx: Context,
        status: Annotated[
            Status | None,
            Field(
                description="Only this status (READY = a work item waiting for someone to act; "
                "DISCARD_* = a discarded preview)"
            ),
        ] = None,
        type: Annotated[  # noqa: A002 - the API's own filter name
            Literal["TASK", "WORK_ITEM", "DEFAULT"] | None,
            Field(description="Only this activity type (3.2.2 reports DEFAULT for its own jobs)"),
        ] = None,
        recurring: Annotated[
            bool | None, Field(description="true: only the recurring schedules; false: only one-off runs")
        ] = None,
        since: Annotated[
            str | None,
            Field(
                description="ISO 8601 with a UTC offset, e.g. 2026-10-27T18:00+11:00: one-off runs from then"
            ),
        ] = None,
        until: Annotated[
            str | None,
            Field(
                description="ISO 8601 with a UTC offset: one-off runs up to then (future times show upcoming)"
            ),
        ] = None,
        description_filter: Annotated[
            str | None,
            Field(description="Text in the description, e.g. 'backup', 'advisor', 'Deploy Intended'"),
        ] = None,
        limit: Annotated[int, Field(ge=1, le=500, description="Rows per section")] = 50,
        offset: Annotated[int, Field(ge=0, description="Rows to skip in each section")] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """Catalyst Center activities (the scheduler's jobs), split into upcoming (scheduled, not started
        yet), in progress (running, or a work item waiting for action), recurring (the schedules, e.g. the
        weekly config-archive backup and the security-advisory scan) and finished (failed first, then newest
        first). Each row: description, status, type, start/end in ISO 8601 UTC, duration, id. Answers "what
        will Catalyst Center run tonight?" before a maintenance window and "what ran on its own overnight?"
        after an outage. Recurring rows show when the schedule began; the API gives no next-run time. Then
        catc_get_activity(id) for one activity's triggered jobs and why they failed."""
        app: CatcApp = get_client(ctx)
        since_ms = to_ms(since, "since") if since else None
        until_ms = to_ms(until, "until") if until else None
        if since_ms is not None and until_ms is not None and since_ms > until_ms:
            raise InvalidRequest("since is after until.")
        params: dict[str, Any] = {}
        if status:
            params["status"] = status
        if type:
            params["type"] = type
        if recurring is not None:
            params["recurring"] = str(recurring).lower()
        page = await fetch_all(app.pager, app.api, ACTIVITIES, params, cap=CAP)
        total = await _count(app, f"{ACTIVITIES}/count", params)
        rows = [a for a in page.items if isinstance(a, dict)]
        if description_filter:
            needle = description_filter.strip().lower()
            rows = [a for a in rows if needle in str(a.get("description") or "").lower()]
        if since_ms is not None or until_ms is not None:
            rows = [a for a in rows if in_window(a, since_ms, until_ms)]
        now = now_ms()
        grouped: dict[str, list[dict[str, Any]]] = {s: [] for s in SECTIONS}
        for a in rows:
            grouped[section(a, now)].append(a)
        out: dict[str, Any] = {
            "counts": {s: len(grouped[s]) for s in SECTIONS},
            "failed": sum(1 for a in rows if str(a.get("status") or "").upper() in FAILED),
            "now": to_iso(now),
        }
        if total is not None:
            out["total_on_appliance"] = total
        filters = {
            k: v
            for k, v in {
                "status": status,
                "type": type,
                "recurring": recurring,
                "since": to_iso(since_ms) if since_ms is not None else None,
                "until": to_iso(until_ms) if until_ms is not None else None,
                "description_filter": description_filter,
            }.items()
            if v is not None
        }
        if filters:
            out["filters"] = filters
        notes: list[str] = []
        for name in SECTIONS:
            ordered = _order(name, grouped[name])
            shown = ordered[offset : offset + limit]
            out[name] = [activity_row(a, now) for a in shown]
            if len(ordered) > offset + limit:
                notes.append(
                    f"{name}: showing {offset + 1}-{offset + len(shown)} of {len(ordered)} "
                    "(raise limit or offset, or filter)."
                )
        if not page.complete:
            notes.append(f"The appliance has more than {CAP} activities; only the first {CAP} were read.")
        if not rows:
            notes.append("No activities match.")
        elif not grouped["upcoming"]:
            notes.append("Nothing is scheduled to run (no upcoming one-off activities).")
        if notes:
            out["notes"] = notes
        return render(out, response_format)

    @reg.read(title="Get activity")
    async def catc_get_activity(
        ctx: Context,
        activity: Annotated[
            str,
            Field(description="Activity id (from catc_list_activities) or its exact description"),
        ],
        limit: Annotated[int, Field(ge=1, le=JOB_CAP, description="Triggered jobs to show")] = 50,
    ) -> dict[str, Any]:
        """One Catalyst Center activity: description, status, type, recurring, start/end (ISO 8601 UTC) and
        the jobs it triggered (each run of a recurring schedule, or the job a one-off activity started), with
        each job's status, failure reason and task id (catc_get_task(task_id) for the task's own detail).
        Failed jobs are listed first. Answers "why did last night's deploy fail?"."""
        app: CatcApp = get_client(ctx)
        a = await fetch_activity(app, activity)
        aid = safe_id(str(a.get("id")), "activity id")
        now = now_ms()
        out: dict[str, Any] = {"section": section(a, now), **activity_row(a, now)}
        jobs_path = f"{ACTIVITIES}/{aid}/triggeredJobs"
        jobs: list[dict[str, Any]] = []
        complete = True
        try:
            page = await fetch_all(app.pager, app.api, jobs_path, cap=JOB_CAP)
            jobs = [j for j in page.items if isinstance(j, dict)]
            complete = page.complete
        except NotFound:
            out["triggered_jobs_note"] = "Catalyst Center has no triggered-jobs list for this activity."
        count = await _count(app, f"{jobs_path}/count")
        jobs.sort(key=lambda j: str(j.get("status") or "").upper() != "FAILURE")
        failed = sum(1 for j in jobs if str(j.get("status") or "").upper() == "FAILURE")
        out["triggered_jobs_count"] = count if count is not None else len(jobs)
        out["triggered_jobs_failed"] = failed
        out["triggered_jobs"] = [job_row(j) for j in jobs[:limit]]
        notes: list[str] = []
        if len(jobs) > limit or not complete:
            notes.append(f"Showing {min(limit, len(jobs))} of {out['triggered_jobs_count']} triggered jobs.")
        if out["recurring"] is True:
            notes.append(
                "A recurring schedule: schedule_start is when it began; triggered jobs are its runs "
                "(the API gives them no times)."
            )
        if notes:
            out["notes"] = notes
        return out
