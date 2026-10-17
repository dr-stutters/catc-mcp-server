"""Assurance analytics: health trends with their dips, top problem devices and clients, issue
recurrence, AI-driven insights and a per-site health report (D38)."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import asyncio
import time
from datetime import UTC, datetime
from typing import Annotated, Any, Literal

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field

from catc_mcp._core import InvalidRequest, NotFound, ToolRegistrar, UpstreamError, get_client, object_result
from catc_mcp._core.http import fetch_all
from catc_mcp.client import CatcApp, safe_id
from catc_mcp.common import PAGE_ISSUES, ago, norm_mac, resolve_device, resolve_site
from catc_mcp.tools.assurance import STALE_NOTE, issue_attrs, issue_row

Hours = Annotated[float, Field(gt=0, le=720, description="Look-back window in hours (default 24)")]

# Device and client scores are 1-10 (good 8-10, fair 4-7, poor 1-3); site/network series are the
# percentage of healthy devices or clients.
GOOD_SCORE = 8
GOOD_PERCENT = 90
PRIORITY_RANK = {"P1": 1, "P2": 2, "P3": 3, "P4": 4}
ISSUE_SCAN_CAP = 1000
ASYNC_TREND_WAIT = 30.0  # seconds to wait for a site-trend assurance task
MAX_POINTS = 24  # points shown per series; the summary and dips use every bucket

AI_UNAVAILABLE = (
    "AI Network Analytics needs Catalyst Center to reach the Cisco AI cloud and the feature enabled "
    "(System > Settings > External Services > Cisco AI Analytics); Catalyst Center does not report "
    "that setting over its REST API."
)


def as_dict(v: Any) -> dict[str, Any]:
    return v if isinstance(v, dict) else {}


def utc(ms: Any) -> str | None:
    if isinstance(ms, bool) or not isinstance(ms, int | float) or ms <= 0:
        return None
    return datetime.fromtimestamp(ms / 1000, tz=UTC).strftime("%Y-%m-%d %H:%M")


def num(v: Any) -> float | None:
    """A metric value as a float (the trend APIs send some as strings); None for no data / -1."""
    if isinstance(v, bool) or v is None:
        return None
    try:
        f = float(v)
    except (TypeError, ValueError):
        return None
    return None if f < 0 else f


def trend_buckets(body: Any) -> list[dict[str, Any]]:
    resp = body.get("response") if isinstance(body, dict) else body
    return [b for b in resp or [] if isinstance(b, dict)] if isinstance(resp, list) else []


def bucket_values(b: dict[str, Any]) -> dict[str, float | None]:
    """{'name' or 'name:FUNC': value} for one trend bucket's attributes and aggregateAttributes."""
    out: dict[str, float | None] = {}
    for a in b.get("attributes") or []:
        if isinstance(a, dict) and a.get("name"):
            out[str(a["name"])] = num(a.get("value"))
    for a in b.get("aggregateAttributes") or []:
        if isinstance(a, dict) and a.get("name"):
            out[f"{a['name']}:{str(a.get('function') or '').lower()}"] = num(a.get("value"))
    return out


def series(buckets: list[dict[str, Any]], key: str) -> list[tuple[int, float]]:
    """(timestamp, value) oldest first, skipping buckets without data."""
    pts = []
    for b in buckets:
        ts = b.get("timestamp")
        v = bucket_values(b).get(key)
        if isinstance(ts, int | float) and v is not None:
            pts.append((int(ts), v))
    return sorted(pts)


def healthy_percent(buckets: list[dict[str, Any]]) -> list[tuple[int, float]]:
    """% of devices in good health per bucket, from the good/fair/poor counts the network trend gives
    (sample sums per bucket, so only the ratio means anything)."""
    pts = []
    for b in buckets:
        v = bucket_values(b)
        good, fair, poor = (
            v.get(k) or 0.0 for k in ("goodDeviceCount", "fairDeviceCount", "poorDeviceCount")
        )
        total = good + fair + poor
        if isinstance(b.get("timestamp"), int | float) and total > 0:
            pts.append((int(b["timestamp"]), round(100 * good / total, 1)))
    return sorted(pts)


def summarize(
    pts: list[tuple[int, float]], *, dip_below: float, bucket_min: int, unit: str
) -> dict[str, Any]:
    """min/avg/latest, the worst moment and the dips (runs of buckets below `dip_below`) with when
    they started, how long they lasted and how low they went; plus up to MAX_POINTS points."""
    if not pts:
        return {"samples": 0, "note": "no data in this window"}
    vals = [v for _, v in pts]
    worst_ts, worst = min(pts, key=lambda p: (p[1], p[0]))
    out: dict[str, Any] = {
        "unit": unit,
        "min": worst,
        "avg": round(sum(vals) / len(vals), 1),
        "latest": vals[-1],
        "worst_at": utc(worst_ts),
        "samples": len(pts),
    }
    dips: list[dict[str, Any]] = []
    run: list[tuple[int, float]] = []
    for p in [*pts, (0, float("inf"))]:  # sentinel closes a trailing run
        if p[1] < dip_below:
            run.append(p)
            continue
        if run:
            ongoing = p[0] == 0
            dips.append(
                {
                    "start": utc(run[0][0]),
                    "end": None if ongoing else utc(p[0]),
                    "minutes": (run[-1][0] - run[0][0]) // 60000 + bucket_min,
                    "lowest": min(v for _, v in run),
                    **({"ongoing": True} if ongoing else {}),
                }
            )
            run = []
    out["dips"] = dips
    out["dip_threshold"] = f"below {dip_below:g}{'%' if unit == '%' else ''}"
    if len(vals) >= 4:
        half = len(vals) // 2
        first, second = sum(vals[:half]) / half, sum(vals[half:]) / (len(vals) - half)
        delta = second - first
        span = 100 if unit == "%" else 10
        out["direction"] = "worse" if delta < -0.05 * span else "better" if delta > 0.05 * span else "steady"
    step = max(1, -(-len(pts) // MAX_POINTS))
    shown = pts[::step]
    if shown[-1] != pts[-1]:
        shown.append(pts[-1])
    out["points"] = [f"{utc(ts)} {v:g}" for ts, v in shown]
    return out


def pick_interval(hours: float, choices: list[tuple[str, int]]) -> tuple[str, int]:
    """The finest interval that keeps the series at or under ~150 buckets."""
    for name, minutes in choices:
        if hours * 60 / minutes <= 150:
            return name, minutes
    return choices[-1]


NETWORK_INTERVALS = [("5MIN", 5), ("10MIN", 10), ("30MIN", 30), ("1HR", 60), ("7DAYS", 10080)]
SITE_INTERVALS = [("5MIN", 5), ("10MIN", 10), ("1HR", 60), ("1DAY", 1440)]
CLIENT_INTERVALS = SITE_INTERVALS
DEVICE_MINUTES = [(str(m), m) for m in (5, 10, 30, 60, 240, 1440)]


def window_ms(hours: float) -> tuple[int, int]:
    end = int(time.time() * 1000)
    return end - int(hours * 3_600_000), end


async def site_trend(
    app: CatcApp, site_id: str, attrs: list[str], start: int, end: int, interval: str
) -> list[dict[str, Any]]:
    """Site trend buckets. Catalyst Center answers this one asynchronously: it returns an assurance
    task, which is polled and then read back with its taskId."""
    path = f"/dna/data/api/v1/siteHealthSummaries/{safe_id(site_id, 'site id')}/trendAnalytics"
    body = await app.api.get(
        path,
        {
            "startTime": start,
            "endTime": end,
            "trendInterval": interval,
            "attribute": attrs,
            "timeSortOrder": "asc",
            "limit": 500,
        },
    )
    resp = body.get("response") if isinstance(body, dict) else None
    if isinstance(resp, list):
        return trend_buckets(body)
    task_id = resp.get("taskId") if isinstance(resp, dict) else None
    if not task_id:
        raise UpstreamError("Catalyst Center returned neither site trend data nor a task id")
    deadline = time.monotonic() + ASYNC_TREND_WAIT
    delay = 0.5
    while True:
        task = await app.get_response(f"/dna/data/api/v1/assuranceTasks/{safe_id(str(task_id), 'task id')}")
        status = str((task or {}).get("status") or "").upper() if isinstance(task, dict) else ""
        if status == "SUCCESS":
            break
        if status in ("FAILURE", "FAILED", "ERROR"):
            raise UpstreamError(f"site trend task failed: {(task or {}).get('failureReason') or status}")
        if time.monotonic() > deadline:
            raise UpstreamError(
                f"site trend task {task_id} still {status or 'pending'} after {ASYNC_TREND_WAIT:g}s"
            )
        await asyncio.sleep(delay)
        delay = min(delay * 2, 4)
    return trend_buckets(await app.api.get(path, {"taskId": task_id}))


async def site_trends(
    app: CatcApp, site: dict[str, Any], hours: float, dip_below: float | None
) -> dict[str, Any]:
    start, end = window_ms(hours)
    interval, minutes = pick_interval(hours, SITE_INTERVALS)
    buckets = await site_trend(
        app,
        str(site["id"]),
        [
            "networkDeviceGoodHealthPercentage",
            "clientGoodHealthPercentage",
            "issueCount",
            "p1IssueCount",
            "p2IssueCount",
        ],
        start,
        end,
        interval,
    )
    below = GOOD_PERCENT if dip_below is None else dip_below
    out: dict[str, Any] = {
        "interval": interval,
        "network_devices_healthy": summarize(
            series(buckets, "networkDeviceGoodHealthPercentage"),
            dip_below=below,
            bucket_min=minutes,
            unit="%",
        ),
    }
    clients = series(buckets, "clientGoodHealthPercentage")
    out["clients_healthy"] = (
        summarize(clients, dip_below=below, bucket_min=minutes, unit="%")
        if clients
        else {"samples": 0, "note": "no clients at this site in the window"}
    )
    bursts = issue_bursts(buckets, minutes)
    if bursts:
        out["issue_bursts"] = bursts
    return out


def issue_bursts(buckets: list[dict[str, Any]], minutes: int) -> list[dict[str, Any]]:
    """Runs of buckets in which the site raised issues (the site trend counts issues raised per bucket,
    not issues open): when, how long and how many were raised."""
    out: list[dict[str, Any]] = []
    run: list[tuple[int, dict[str, float | None]]] = []
    rows = sorted(
        (
            (int(b["timestamp"]), bucket_values(b))
            for b in buckets
            if isinstance(b.get("timestamp"), int | float)
        ),
        key=lambda r: r[0],
    )
    for ts, v in [*rows, (0, {})]:
        if (v.get("issueCount") or 0) > 0:
            run.append((ts, v))
            continue
        if run:
            out.append(
                {
                    "start": utc(run[0][0]),
                    "end": None if ts == 0 else utc(ts),
                    "minutes": (run[-1][0] - run[0][0]) // 60000 + minutes,
                    "issues_raised": int(sum(r[1].get("issueCount") or 0 for r in run)),
                    "p1_p2_raised": int(
                        sum((r[1].get("p1IssueCount") or 0) + (r[1].get("p2IssueCount") or 0) for r in run)
                    ),
                    **({"ongoing": True} if ts == 0 else {}),
                }
            )
            run = []
    return out


async def scan_issues(
    app: CatcApp, hours: float, *, site: str | None = None, extra: dict[str, Any] | None = None
) -> tuple[list[dict[str, Any]], bool]:
    """Every issue (any status) that occurred in the window, newest first, up to ISSUE_SCAN_CAP."""
    start, end = window_ms(hours)
    params: dict[str, Any] = {
        "startTime": start,
        "endTime": end,
        "sortBy": "mostRecentOccurredTime",
        "order": "desc",
        **(extra or {}),
    }
    if site:
        params["siteHierarchy"] = f"{site}*" if site.lower() != "global" else "Global*"
    full = await fetch_all(
        app.data_pager,
        app.api,
        "/dna/data/api/v1/assuranceIssues",
        params,
        cap=ISSUE_SCAN_CAP,
        max_page=PAGE_ISSUES,
    )
    return [i for i in full.items if isinstance(i, dict)], full.complete


def issue_brief(i: dict[str, Any], now_ms: float | None = None) -> dict[str, Any]:
    row = issue_row(i, now_ms)
    keep = ("priority", "name", "summary", "status", "last_seen", "id")
    return {k: row[k] for k in keep if row.get(k) not in (None, "")}


def worst_issue(issues: list[dict[str, Any]]) -> dict[str, Any]:
    """Active before resolved, then highest priority, then most recent."""
    return min(
        issues,
        key=lambda i: (
            str(i.get("status") or "").lower() != "active",
            PRIORITY_RANK.get(str(i.get("priority")), 9),
            -(i.get("mostRecentOccurredTime") or 0),
        ),
    )


def opening(i: dict[str, Any], now_ms: float) -> dict[str, Any]:
    """When one issue opened and closed (resolved/ignored: its updatedTime) and how long it was open
    (still active: until now)."""
    first = i.get("firstOccurredTime") or i.get("mostRecentOccurredTime")
    status = str(i.get("status") or "").lower()
    closed = i.get("updatedTime") if status in ("resolved", "ignored") else None
    ref = closed or (now_ms if status == "active" else i.get("mostRecentOccurredTime"))
    row: dict[str, Any] = {"opened": utc(first), "closed": utc(closed), "status": status or None}
    if isinstance(first, int | float) and isinstance(ref, int | float) and ref >= first:
        row["open_minutes"] = int((ref - first) // 60000)
    return {k: v for k, v in row.items() if v is not None}


def issue_periods(
    issues: list[dict[str, Any]], limit: int = 20, now_ms: float | None = None
) -> list[dict[str, Any]]:
    """When each issue in the window was open, oldest first: a health score does not always move
    (a router's score ignores a down link), the issues show the outage anyway."""
    now = now_ms if now_ms is not None else time.time() * 1000
    rows = []
    for i in sorted(issues, key=lambda i: i.get("firstOccurredTime") or 0)[-limit:]:
        head = {k: i[k] for k in ("priority", "name") if i.get(k)}
        rows.append({**head, **opening(i, now)})
    return rows


def recurrence(
    issues: list[dict[str, Any]], *, min_times: int, now_ms: float | None = None
) -> list[dict[str, Any]]:
    """Issues grouped by (name, entity): how many times each opened in the window, every opening with
    its duration, and whether it keeps coming back. Catalyst Center opens a new issue each time the
    condition returns after the previous one resolved, and counts repeats within one open issue
    (`occurrences`)."""
    groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for i in issues:
        key = (str(i.get("name") or ""), str(i.get("entityId") or i.get("deviceId") or ""))
        groups.setdefault(key, []).append(i)
    now = now_ms if now_ms is not None else time.time() * 1000
    out = []
    for (name, _entity), items in groups.items():
        items.sort(key=lambda i: i.get("firstOccurredTime") or i.get("mostRecentOccurredTime") or 0)
        openings = []
        occurrences = 0
        for i in items:
            count = (
                issue_attrs(i).get("_count")
                or i.get("occurrenceCount")
                or i.get("issue_occurence_count")
                or 1
            )
            try:
                occurrences += int(count)
            except (TypeError, ValueError):
                occurrences += 1
            openings.append({**opening(i, now), "id": i.get("issueId") or i.get("id")})
        times = len(items)
        if times < min_times and occurrences < min_times:
            continue
        newest = items[-1]
        row = issue_row(newest, now)
        g: dict[str, Any] = {
            "name": name,
            "device": row.get("device"),
            "summary": row.get("summary"),
            "priority": row.get("priority"),
            "times_opened": times,
            "occurrences": occurrences,
            "status_now": str(newest.get("status") or "").lower() or None,
            "last_seen": row.get("last_seen"),
        }
        starts = [
            float(i["firstOccurredTime"])
            for i in items
            if isinstance(i.get("firstOccurredTime"), int | float)
        ]
        if len(starts) >= 2:
            gaps = [(b - a) / 60000 for a, b in zip(starts, starts[1:], strict=False)]
            g["avg_minutes_between"] = int(sum(gaps) / len(gaps))
        g["openings"] = openings[-10:]
        if len(openings) > 10:
            g["openings_note"] = f"latest 10 of {len(openings)}"
        out.append({k: v for k, v in g.items() if v not in (None, "")})
    out.sort(
        key=lambda g: (-g["times_opened"], -g["occurrences"], PRIORITY_RANK.get(str(g.get("priority")), 9))
    )
    return out


DEVICE_SCAN_CAP = 2000
PAGE_QUERY = 500  # /dna/data/api/v1/networkDevices/query page.limit


async def post_all(
    app: CatcApp, path: str, body: dict[str, Any], *, sort: dict[str, Any], cap: int = DEVICE_SCAN_CAP
) -> list[dict[str, Any]]:
    """Every row of a POST .../query data API (1-based page.offset, up to `cap`)."""
    rows: list[dict[str, Any]] = []
    while len(rows) < cap:
        page = {"limit": PAGE_QUERY, "offset": len(rows) + 1, "sortBy": [sort]}
        data = await app.api.post(path, {**body, "page": page})
        batch = data.get("response") if isinstance(data, dict) else data
        batch = [r for r in batch if isinstance(r, dict)] if isinstance(batch, list) else []
        rows.extend(batch)
        if len(batch) < PAGE_QUERY:
            break
    return rows[:cap]


async def problem_devices(
    app: CatcApp, hours: float, *, site_path: str | None, limit: int, issues: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Devices whose health dipped below good in the window or that had issues, worst first, each with
    the issue behind it."""
    start, end = window_ms(hours)
    devices = await post_all(
        app,
        "/dna/data/api/v1/networkDevices/query",
        {
            "startTime": start,
            "endTime": end,
            "aggregateAttributes": [
                {"name": "overallHealthScore", "function": "min"},
                {"name": "overallHealthScore", "function": "avg"},
            ],
        },
        sort={"name": "overallHealthScore", "order": "asc", "function": "min"},
    )
    by_entity: dict[str, list[dict[str, Any]]] = {}
    for i in issues:
        if "device" in str(i.get("entityType") or "").lower() and i.get("entityId"):
            by_entity.setdefault(str(i["entityId"]), []).append(i)
    rows = []
    for d in devices:
        if not isinstance(d, dict):
            continue
        site = str(d.get("siteHierarchy") or "")
        if site_path and not (site == site_path or site.startswith(site_path.rstrip("/") + "/")):
            continue
        agg = {
            f"{a.get('name')}:{str(a.get('function') or '').lower()}": num(a.get("value"))
            for a in d.get("aggregateAttributes") or []
            if isinstance(a, dict)
        }
        metrics = as_dict(d.get("metricsDetails"))
        worst, avg, now = (
            agg.get("overallHealthScore:min"),
            agg.get("overallHealthScore:avg"),
            num(metrics.get("overallHealthScore")),
        )
        dev_issues = by_entity.get(str(d.get("id")), [])
        if not dev_issues and (worst is None or worst >= GOOD_SCORE) and (now is None or now >= GOOD_SCORE):
            continue
        row: dict[str, Any] = {
            "device": d.get("name"),
            "ip": d.get("managementIpAddress"),
            "site": site or None,
            "worst_health": worst,
            "avg_health": round(avg, 1) if avg is not None else None,
            "health_now": now,
            "issues": len(dev_issues),
        }
        if dev_issues:
            row["issue"] = issue_brief(worst_issue(dev_issues))
        if d.get("communicationState") and d["communicationState"] != "REACHABLE":
            row["reachability"] = d["communicationState"]
        rows.append({k: v for k, v in row.items() if v is not None})
    rows.sort(
        key=lambda r: (
            r.get("worst_health", 11),
            PRIORITY_RANK.get(str((r.get("issue") or {}).get("priority")), 9),
            -r.get("issues", 0),
        )
    )
    return rows[:limit]


async def problem_clients(
    app: CatcApp, hours: float, *, site_path: str | None, limit: int, issues: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Clients whose health dipped below good in the window, worst first, with their issue or last
    onboarding failure."""
    start, end = window_ms(hours)
    body: dict[str, Any] = {
        "startTime": start,
        "endTime": end,
        "attributes": [
            "macAddress",
            "ipv4Address",
            "type",
            "username",
            "name",
            "siteHierarchy",
            "overallScore",
            "connectionStatus",
            "latestFailureReason",
            "connectedNetworkDeviceName",
            "ssid",
        ],
        "aggregateAttributes": [
            {"name": "overallScore", "function": "min"},
            {"name": "overallScore", "function": "avg"},
        ],
        "page": {
            "limit": 100,
            "offset": 1,
            "sortBy": [{"name": "overallScore", "order": "asc", "function": "min"}],
        },
    }
    if site_path:
        body["filters"] = [{"key": "siteHierarchy", "operator": "like", "value": f"{site_path}*"}]
    resp = await app.api.post("/dna/data/api/v1/clients/query", body)
    items = resp.get("response") if isinstance(resp, dict) else resp
    by_mac: dict[str, list[dict[str, Any]]] = {}
    for i in issues:
        mac = str(i.get("entityId") or issue_attrs(i).get("macAddr") or issue_attrs(i).get("clientMac") or "")
        if "client" in str(i.get("entityType") or "").lower() and mac:
            by_mac.setdefault(mac.lower(), []).append(i)
    rows = []
    for c in items if isinstance(items, list) else []:
        if not isinstance(c, dict):
            continue
        agg = {
            f"{a.get('name')}:{str(a.get('function') or '').lower()}": num(a.get("value"))
            for a in c.get("aggregateAttributes") or []
            if isinstance(a, dict)
        }
        worst, avg = agg.get("overallScore:min"), agg.get("overallScore:avg")
        mac = str(c.get("macAddress") or "").lower()
        c_issues = by_mac.get(mac, [])
        fail = c.get("latestFailureReason")
        if not c_issues and (worst is None or worst >= GOOD_SCORE):
            continue
        health = as_dict(c.get("health"))
        row: dict[str, Any] = {
            "mac": c.get("macAddress"),
            "ip": c.get("ipv4Address"),
            "type": c.get("type"),
            "user": c.get("username") if c.get("username") != c.get("macAddress") else None,
            "device": c.get("connectedNetworkDeviceName")
            or (c.get("connectedNetworkDevice") or {}).get("connectedNetworkDeviceName"),
            "ssid": c.get("ssid") or (c.get("connection") or {}).get("ssid"),
            "site": c.get("siteHierarchy"),
            "worst_health": worst,
            "avg_health": round(avg, 1) if avg is not None else None,
            "health_now": num(c.get("overallScore") if "overallScore" in c else health.get("overallScore")),
            "status": c.get("connectionStatus"),
            "issues": len(c_issues),
        }
        if c_issues:
            row["issue"] = issue_brief(worst_issue(c_issues))
        elif fail not in (None, "", "SUCCESS"):
            row["last_failure"] = fail
        rows.append({k: v for k, v in row.items() if v not in (None, "")})
    rows.sort(key=lambda r: (r.get("worst_health", 11), -r.get("issues", 0)))
    return rows[:limit]


async def ai_insights(app: CatcApp, hours: float, site_id: str | None) -> dict[str, Any]:
    """AI-driven issues in the window, or why there are none to show."""
    start, end = window_ms(hours)
    params: dict[str, Any] = {"startTime": start, "endTime": end}
    if site_id:
        params["siteId"] = site_id
        params["aiDriven"] = "Yes"
    data = await app.get_response("/dna/intent/api/v1/issues", params)
    rows = [
        i
        for i in (data if isinstance(data, list) else [])
        if isinstance(i, dict) and str(i.get("aiDriven") or "").lower() in ("yes", "true")
    ]
    if not rows:
        return {
            "status": "unavailable",
            "reason": f"no AI-driven issues in the last {hours:g}h. {AI_UNAVAILABLE}",
        }
    return {
        "status": "available",
        "insights": [
            {
                k: v
                for k, v in {
                    "priority": i.get("priority"),
                    "issue": i.get("name"),
                    "status": i.get("status"),
                    "occurrences": i.get("issue_occurence_count"),
                    "last_seen": ago(i.get("last_occurence_time")),
                    "device": i.get("deviceId") or None,
                    "client": i.get("clientMac") or None,
                    "id": i.get("issueId"),
                }.items()
                if v not in (None, "")
            }
            for i in rows[:25]
        ],
    }


async def no_data_on_404(call: Any) -> Any:
    """Catalyst Center answers a per-device/client trend with 404 when it has no data for it yet
    (e.g. while the device resyncs); that is an empty series, not an error."""
    try:
        return await call
    except NotFound:
        return {"response": []}


def section(result: Any) -> Any:
    """A gathered section, or {'unavailable': reason} when Catalyst Center refused it."""
    if isinstance(result, UpstreamError | InvalidRequest):
        return {"unavailable": str(result)[:300]}
    if isinstance(result, BaseException):
        raise result
    return result


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="Health trend")
    async def catc_health_trend(
        ctx: Context,
        scope: Annotated[
            Literal["network", "site", "device", "client"],
            Field(description="What to trend: the whole network, one site, one device or one client"),
        ] = "network",
        target: Annotated[
            str | None,
            Field(description="Site (name hierarchy or id), device (hostname, IP or id) or client MAC"),
        ] = None,
        hours: Hours = 24,
        dip_below: Annotated[
            float | None,
            Field(
                ge=0,
                le=100,
                description="Count a bucket as a dip below this value (default: 8 for device/client "
                "scores 1-10, 90 for network/site % healthy)",
            ),
        ] = None,
    ) -> ToolResult:
        """Health over a time window: min, average, latest, the worst moment and the dips (when each
        started, how long it lasted, how low it went), whether it is getting worse, and a short series
        of points. Network and site trend the % of healthy devices (a site also its clients and when
        issues were raised); device and client trend the 1-10 health score plus the issues open in the
        window, since a score doesn't always move (a router's ignores a down link). Use it for "is this
        site getting worse?" and "when did it dip?"."""
        app: CatcApp = get_client(ctx)
        if scope != "network" and not target:
            raise InvalidRequest(f"Give target: the {scope} to trend.")
        start, end = window_ms(hours)
        out: dict[str, Any] = {"scope": scope, "window_hours": hours}
        if scope == "network":
            interval, minutes = pick_interval(hours, NETWORK_INTERVALS)
            body = await app.api.post(
                "/dna/data/api/v1/networkDevices/trendAnalytics",
                {
                    "startTime": start,
                    "endTime": end,
                    "trendInterval": interval,
                    "attributes": ["goodDeviceCount", "fairDeviceCount", "poorDeviceCount"],
                    "page": {"limit": 500, "offset": 1, "timestampOrder": "asc"},
                },
            )
            out["interval"] = interval
            out["network_devices_healthy"] = summarize(
                healthy_percent(trend_buckets(body)),
                dip_below=GOOD_PERCENT if dip_below is None else dip_below,
                bucket_min=minutes,
                unit="%",
            )
        elif scope == "site":
            site = await resolve_site(app, str(target))
            out["site"] = site.get("nameHierarchy") or target
            out.update(await site_trends(app, site, hours, dip_below))
        elif scope == "device":
            dev = await resolve_device(app, str(target))
            label, minutes = pick_interval(hours, DEVICE_MINUTES)
            body = await no_data_on_404(
                app.api.post(
                    f"/dna/data/api/v1/networkDevices/{safe_id(str(dev['id']), 'device id')}/trendAnalytics",
                    {
                        "startTime": start,
                        "endTime": end,
                        "trendIntervalInMinutes": minutes,
                        "aggregateAttributes": [
                            {"name": "overallHealthScore", "function": "min"},
                            {"name": "overallHealthScore", "function": "avg"},
                        ],
                        "page": {"limit": 500, "offset": 1, "timestampOrder": "asc"},
                    },
                )
            )
            out["device"] = dev.get("hostname") or target
            out["interval"] = f"{label}MIN"
            out["health"] = summarize(
                series(trend_buckets(body), "overallHealthScore:min"),
                dip_below=GOOD_SCORE if dip_below is None else dip_below,
                bucket_min=minutes,
                unit="score 1-10",
            )
            issues, _ = await scan_issues(app, hours, extra={"networkDeviceId": dev["id"]})
            out["issue_periods"] = issue_periods(issues)
        else:
            mac = norm_mac(str(target))
            interval, minutes = pick_interval(hours, CLIENT_INTERVALS)
            body = await no_data_on_404(
                app.api.post(
                    f"/dna/data/api/v1/clients/{safe_id(mac, 'client MAC')}/trendAnalytics",
                    {
                        "startTime": start,
                        "endTime": end,
                        "trendInterval": interval,
                        "aggregateAttributes": [
                            {"name": "overallScore", "function": "min"},
                            {"name": "overallScore", "function": "avg"},
                        ],
                        "page": {"limit": 500, "timestampOrder": "asc"},
                    },
                )
            )
            out["client"] = mac
            out["interval"] = interval
            out["health"] = summarize(
                series(trend_buckets(body), "overallScore:min"),
                dip_below=GOOD_SCORE if dip_below is None else dip_below,
                bucket_min=minutes,
                unit="score 1-10",
            )
            issues, _ = await scan_issues(app, hours, extra={"macAddress": mac})
            out["issue_periods"] = issue_periods(issues)
        return object_result(out)

    @reg.read(title="Top problem devices or clients")
    async def catc_top_problems(
        ctx: Context,
        kind: Annotated[Literal["devices", "clients"], Field(description="Devices or clients")] = "devices",
        site: Annotated[
            str | None, Field(description="Only this site and below (name hierarchy or id)")
        ] = None,
        hours: Hours = 24,
        limit: Annotated[int, Field(ge=1, le=50)] = 10,
    ) -> ToolResult:
        """The worst devices or clients over the window, each with the issue behind it. Each row has
        the lowest health reached (1-10), the average, health now, how many issues it had and the worst
        one (active first, then priority, then newest). Only devices/clients that dipped below good
        health or had issues are listed. Drill in with catc_health_trend, catc_get_issue or
        catc_device_360."""
        app: CatcApp = get_client(ctx)
        site_path = None
        if site:
            site_path = str((await resolve_site(app, site)).get("nameHierarchy") or site)
        issues, complete = await scan_issues(app, hours, site=site_path)
        fn = problem_devices if kind == "devices" else problem_clients
        rows = await fn(app, hours, site_path=site_path, limit=limit, issues=issues)
        out: dict[str, Any] = {"kind": kind, "window_hours": hours, "results": rows}
        if site_path:
            out["site"] = site_path
        if not rows:
            out["note"] = f"no {kind} dipped below good health or had issues in the last {hours:g}h"
        if any((r.get("issue") or {}).get("status") == "active" for r in rows):
            out["active_issues"] = STALE_NOTE
        if not complete:
            out["scan"] = f"only the newest {ISSUE_SCAN_CAP} issues were read; narrow by site or window"
        return object_result(out)

    @reg.read(title="Issue recurrence")
    async def catc_issue_recurrence(
        ctx: Context,
        hours: Annotated[
            float, Field(gt=0, le=720, description="Look-back window in hours (default 168, a week)")
        ] = 168,
        site: Annotated[
            str | None, Field(description="Only this site and below (name hierarchy or id)")
        ] = None,
        device: Annotated[
            str | None, Field(description="Only issues on this device (name, IP or id)")
        ] = None,
        min_times: Annotated[
            int, Field(ge=1, le=100, description="Report issues that opened or occurred at least this often")
        ] = 2,
        limit: Annotated[int, Field(ge=1, le=100)] = 20,
    ) -> ToolResult:
        """What keeps breaking: the same issue (name and device or client) opening and closing again in
        the window. Each row has how many times it opened, total occurrences, the average gap between
        openings, its status now and each opening with when it closed and how long it stayed open.
        Includes resolved issues."""
        app: CatcApp = get_client(ctx)
        site_path = str((await resolve_site(app, site)).get("nameHierarchy") or site) if site else None
        extra: dict[str, Any] = {}
        if device:
            extra["networkDeviceId"] = (await resolve_device(app, device))["id"]
        issues, complete = await scan_issues(app, hours, site=site_path, extra=extra)
        groups = recurrence(issues, min_times=min_times)
        out: dict[str, Any] = {
            "window_hours": hours,
            "issues_read": len(issues),
            "recurring": groups[:limit],
        }
        if len(groups) > limit:
            out["more"] = f"{len(groups) - limit} more recurring issue(s); raise limit"
        if any(g.get("status_now") == "active" for g in groups[:limit]):
            out["active_issues"] = STALE_NOTE
        if not groups:
            out["note"] = f"no issue opened or occurred {min_times}+ times in the last {hours:g}h"
        if not complete:
            out["scan"] = (
                f"only the newest {ISSUE_SCAN_CAP} issues were read; narrow by site, device or window"
            )
        return object_result(out)

    @reg.read(title="AI-driven insights")
    async def catc_ai_insights(
        ctx: Context,
        site: Annotated[str | None, Field(description="Only this site (name hierarchy or id)")] = None,
        hours: Hours = 24,
    ) -> ToolResult:
        """AI-driven issues from Cisco AI Network Analytics (baseline deviations Catalyst Center learns
        in the cloud) for the network or a site. Reports status 'unavailable' with the reason when there
        are none, e.g. the appliance has no cloud connectivity or the feature is off; never fails for
        that."""
        app: CatcApp = get_client(ctx)
        site_id = str((await resolve_site(app, site))["id"]) if site else None
        try:
            out = await ai_insights(app, hours, site_id)
        except UpstreamError as e:
            out = {"status": "unavailable", "reason": f"{str(e)[:200]}. {AI_UNAVAILABLE}"}
        return object_result({"window_hours": hours, **out})

    @reg.read(title="Site health report")
    async def catc_site_health_report(
        ctx: Context,
        site: Annotated[str, Field(description="Site name hierarchy or id, e.g. 'Global/AU/SYD-1'")],
        hours: Hours = 24,
    ) -> ToolResult:
        """One report on a site over a window: health now, the device and client trends with their
        dips and direction, when issues were raised, the worst devices and clients with the issue behind
        each, issues that keep coming back, AI-driven insights where available, and a one-line verdict.
        Answers "how is this site doing, and is it getting worse?". Sections Catalyst Center can't
        answer are marked unavailable."""
        app: CatcApp = get_client(ctx)
        s = await resolve_site(app, site)
        site_id, path = str(s["id"]), str(s.get("nameHierarchy") or site)
        issues_res, now_res, trend_res, ai_res = await asyncio.gather(
            scan_issues(app, hours, site=path),
            app.get_response(f"/dna/data/api/v1/siteHealthSummaries/{safe_id(site_id, 'site id')}"),
            site_trends(app, s, hours, None),
            ai_insights(app, hours, site_id),
            return_exceptions=True,
        )
        issues: list[dict[str, Any]] = []
        if isinstance(issues_res, tuple):
            issues = issues_res[0]
        dev_res: Any
        cli_res: Any
        dev_res, cli_res = await asyncio.gather(
            problem_devices(app, hours, site_path=path, limit=5, issues=issues),
            problem_clients(app, hours, site_path=path, limit=5, issues=issues),
            return_exceptions=True,
        )
        out: dict[str, Any] = {"site": path, "window_hours": hours}
        now = section(now_res)
        if isinstance(now, list):
            now = now[0] if now else {}
        out["now"] = site_now(now) if isinstance(now, dict) and "unavailable" not in now else now
        out["trend"] = section(trend_res)
        out["problem_devices"] = section(dev_res) or "none in the window"
        out["problem_clients"] = section(cli_res) or "none in the window"
        if isinstance(issues_res, tuple):
            active = [i for i in issues if str(i.get("status") or "").lower() == "active"]
            out["issues"] = {
                "in_window": len(issues),
                "active": len(active),
                "recurring": recurrence(issues, min_times=2)[:5],
            }
        else:
            out["issues"] = section(issues_res)
        ai = section(ai_res)
        if isinstance(ai_res, UpstreamError):
            ai = {"status": "unavailable", "reason": f"{ai['unavailable']}. {AI_UNAVAILABLE}"}
        out["ai_insights"] = ai
        out["verdict"] = verdict(out)
        return object_result(out)


SITE_NOW = {
    "networkDeviceCount": "devices",
    "networkDeviceGoodHealthPercentage": "devices_healthy_pct",
    "clientCount": "clients",
    "clientGoodHealthPercentage": "clients_healthy_pct",
    "issueCount": "open_issues",
    "p1IssueCount": "p1",
    "p2IssueCount": "p2",
    "p3IssueCount": "p3",
    "p4IssueCount": "p4",
}


def site_now(s: dict[str, Any]) -> dict[str, Any]:
    out = {short: s.get(key) for key, short in SITE_NOW.items() if s.get(key) not in (None, "")}
    if "devices" not in out:
        out["devices"] = sum(
            int(s.get(k) or 0) for k in ("routerDeviceCount", "switchDeviceCount", "wirelessDeviceCount")
        )
    return out


def verdict(report: dict[str, Any]) -> str:
    """One line: is the site worse, better or steady, and what to look at first."""
    trend = as_dict(report.get("trend"))
    dev = as_dict(trend.get("network_devices_healthy"))
    parts = []
    direction = dev.get("direction")
    if direction:
        parts.append(
            f"device health {direction} over the window (min {dev.get('min')}%, now {dev.get('latest')}%)"
        )
    dips = dev.get("dips") or []
    if dips:
        parts.append(f"{len(dips)} dip(s), longest {max(d['minutes'] for d in dips)} min")
    bursts = trend.get("issue_bursts") or []
    if bursts:
        parts.append(
            f"issues raised in {len(bursts)} period(s), longest {max(b['minutes'] for b in bursts)} min"
        )
    issues = as_dict(report.get("issues"))
    if issues.get("recurring"):
        top = issues["recurring"][0]
        parts.append(f"recurring: {top['name']} on {top.get('device') or 'n/a'} ({top['times_opened']}x)")
    devices = report.get("problem_devices")
    if isinstance(devices, list) and devices:
        d = devices[0]
        issue = (d.get("issue") or {}).get("name")
        parts.append(f"worst device {d.get('device')}" + (f" ({issue})" if issue else ""))
    return "; ".join(parts) if parts else "no dips, issues or problem devices in the window"
