"""On-demand activity lookups (D2): platform event notifications and a merged "what happened here
recently" view over issues, assurance events, notifications and the audit log.

Pull-only (core ADR-003): every call queries Catalyst Center for the window asked for. There is no
poller, buffer or subscription; the history available is what Catalyst Center keeps.
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import asyncio
import re
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Annotated, Any, Literal

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field
from stutters_mcp_core import (
    ResponseFormat,
    ToolRegistrar,
    UpstreamError,
    get_client,
    list_result,
)
from stutters_mcp_core.http import Page, fetch_all, page_of

from catc_mcp.client import CatcApp
from catc_mcp.common import (
    PAGE_AUDIT,
    PAGE_EVENTS,
    PAGE_ISSUES,
    PAGE_NOTIFICATIONS,
    resolve_device,
    resolve_site,
    window,
)

NOTIFICATIONS = "/dna/intent/api/v1/event/event-series"
ISSUES = "/dna/data/api/v1/assuranceIssues"
EVENTS = "/dna/data/api/v1/assuranceEvents"
AUDIT = "/dna/data/api/v1/event/event-series/audit-logs"

# How many notifications one call scans when filtering client-side (device/site/type), so a busy
# appliance can't turn one tool call into thousands of requests. Results say when they hit it.
NOTIFICATION_SCAN_CAP = 2000
# Per-source cap for catc_recent_activity.
SOURCE_CAP = 200
# Audit records scanned for text matches when a device/site scope is given.
AUDIT_SCAN_CAP = 1000
SOURCES = ("issue", "event", "notification", "audit")
Source = Literal["issue", "event", "notification", "audit"]


def ts_text(ms: Any) -> Any:
    if isinstance(ms, int | float) and ms > 0:
        return datetime.fromtimestamp(ms / 1000, tz=UTC).strftime("%Y-%m-%d %H:%M:%S")
    return ms


def _short(text: Any, n: int = 300) -> Any:
    if isinstance(text, str):
        text = " ".join(text.split())
    if isinstance(text, str) and len(text) > n:
        return text[: n - 3] + "..."
    return text


def _clean(row: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in row.items() if v not in (None, "", [], {})}


def _details(e: dict[str, Any]) -> dict[str, Any]:
    d = e.get("details")
    return d if isinstance(d, dict) else {}


def notification_device(e: dict[str, Any]) -> Any:
    d = _details(e)
    return d.get("deviceName") or d.get("managementIpAddr") or d.get("ipAddress") or d.get("hostname")


def notification_row(e: dict[str, Any]) -> dict[str, Any]:
    d = _details(e)
    return _clean(
        {
            "time": ts_text(e.get("timestamp")),
            "type": e.get("type"),
            "category": e.get("category"),
            "severity": e.get("severity"),
            "domain": "/".join(x for x in (e.get("domain"), e.get("subDomain")) if x),
            "name": e.get("name") or d.get("_name") or e.get("eventId"),
            "device": notification_device(e),
            "site": d.get("siteHierarchy") or d.get("areaName"),
            "description": _short(e.get("message") or e.get("description") or d.get("description")),
            "user": e.get("userName") if e.get("type") == "AUDIT_LOG" else None,
            "eventId": e.get("eventId"),
            "id": e.get("instanceId"),
        }
    )


def _haystack(e: dict[str, Any]) -> str:
    """Lower-cased text of the fields that name the device or site a notification is about."""
    d = _details(e)
    parts = [
        e.get("description"),
        e.get("message"),
        e.get("siteId"),
        *(d.get(k) for k in ("deviceName", "managementIpAddr", "ipAddress", "deviceId", "hostname")),
        *(d.get(k) for k in ("_key", "siteHierarchy", "areaName", "siteId", "networkDeviceId")),
    ]
    return " ".join(str(p) for p in parts if p).lower()


Matcher = list[re.Pattern[str]]


def _ip_pattern(ip: str) -> re.Pattern[str]:
    # Not part of a longer address on either side (10.0.0.11 vs 110.0.0.11 / 10.0.0.110);
    # a sentence-ending period is fine.
    return re.compile(r"(?<![\d.])" + re.escape(ip) + r"(?!\d|\.\d)")


def _name_pattern(name: str) -> re.Pattern[str]:
    # A whole hostname or id: r1 must not match r10 or mirror1.
    return re.compile(r"(?<![\w.-])" + re.escape(name) + r"(?![\w-]|\.\w)")


def _site_pattern(path: str) -> re.Pattern[str]:
    # The site or a site below it: Global/A matches Global/A and Global/A/B, not Global/A2.
    return re.compile(r"(?<![\w/-])" + re.escape(path) + r"(?![^/\s,;:\]\)\"'])")


def device_matcher(dev: dict[str, Any]) -> Matcher:
    out: Matcher = []
    if dev.get("managementIpAddress"):
        out.append(_ip_pattern(str(dev["managementIpAddress"]).lower()))
    for key in ("hostname", "id"):
        if dev.get(key):
            out.append(_name_pattern(str(dev[key]).lower()))
    return out


def site_matcher(site: dict[str, Any]) -> Matcher | None:
    """Patterns for a site; None for Global (everything is below it, so no text filter)."""
    path = str(site.get("nameHierarchy") or "")
    if path.lower() == "global":
        return None
    out: Matcher = []
    if path:
        out.append(_site_pattern(path.lower()))
    if site.get("id"):
        out.append(_name_pattern(str(site["id"]).lower()))
    return out


def matches(e: dict[str, Any], patterns: Matcher | None) -> bool:
    """True when the record's text names one of the patterns (None: no filter)."""
    if patterns is None:
        return True
    hay = _haystack(e)
    return any(p.search(hay) for p in patterns)


def in_scope(e: dict[str, Any], device: dict[str, Any] | None, site: dict[str, Any] | None) -> bool:
    """Device and site filters both apply (AND), like the API's deviceId + siteId."""
    if device is not None and not matches(e, device_matcher(device)):
        return False
    return site is None or matches(e, site_matcher(site))


async def fetch_notifications(
    app: CatcApp,
    hours: float,
    *,
    type_: str | None = None,
    category: str | None = None,
    domain: str | None = None,
    severity: int | None = None,
    include_audit: bool = False,
    device: dict[str, Any] | None = None,
    site: dict[str, Any] | None = None,
    cap: int = NOTIFICATION_SCAN_CAP,
) -> tuple[list[dict[str, Any]], bool]:
    """Notifications in the window, newest first, filtered; and whether the scan was complete."""
    params: dict[str, Any] = {**window(hours), "sortBy": "timestamp", "order": "desc"}
    if type_:
        params["type"] = type_
    if category:
        params["category"] = category
    if domain:
        params["domain"] = domain
    page = await fetch_all(
        app.audit_pager, app.api, NOTIFICATIONS, params, cap=cap, max_page=PAGE_NOTIFICATIONS
    )
    rows = [e for e in page.items if isinstance(e, dict)]
    if not include_audit and type_ is None:
        rows = [e for e in rows if e.get("type") != "AUDIT_LOG"]
    if severity is not None:
        rows = [e for e in rows if isinstance(e.get("severity"), int) and e["severity"] <= severity]
    rows = [e for e in rows if in_scope(e, device, site)]
    rows.sort(key=lambda e: _num(e.get("timestamp")), reverse=True)
    return rows, page.complete


# --- catc_recent_activity sources --------------------------------------------------------------


def _num(v: Any) -> float:
    try:
        return float(v)
    except (TypeError, ValueError):
        return 0.0


def _row(source: str, ms: Any, what: Any, **kw: Any) -> dict[str, Any]:
    row = _clean({"time": ts_text(ms), "source": source, "what": _short(what, 200), **kw})
    row["_ms"] = _num(ms)
    return row


async def _issues(app: CatcApp, hours: float, dev: dict[str, Any] | None, site: dict[str, Any] | None) -> Any:
    params: dict[str, Any] = {**window(hours), "sortBy": "mostRecentOccurredTime", "order": "desc"}
    if dev:
        params["networkDeviceId"] = dev["id"]
    if site:
        params["siteHierarchy"] = f"{site['nameHierarchy']}*"
    page = await fetch_all(app.data_pager, app.api, ISSUES, params, cap=SOURCE_CAP, max_page=PAGE_ISSUES)
    rows = [
        _row(
            "issue",
            i.get("mostRecentOccurredTime") or i.get("firstOccurredTime"),
            i.get("summary") or i.get("name"),
            severity=i.get("priority"),
            status=i.get("status"),
            site=i.get("siteHierarchy"),
            id=i.get("issueId") or i.get("id"),
        )
        for i in page.items
        if isinstance(i, dict)
    ]
    return rows, None if page.complete else f"capped at {SOURCE_CAP} rows"


async def _events(app: CatcApp, hours: float, dev: dict[str, Any] | None, site: dict[str, Any] | None) -> Any:
    hours = min(hours, 168)  # the assurance events API keeps 7 days
    if dev:
        families = [str(dev.get("family") or "Routers")]
    else:
        families = ["Routers", "Switches and Hubs", "Wireless Controller"]

    async def one(fam: str) -> Any:
        params: dict[str, Any] = {"deviceFamily": fam, **window(hours)}
        params.update(sortBy="timestamp", order="desc")
        if dev:
            params["networkDeviceId"] = dev["id"]
        if site:
            params["siteId"] = site["id"]
        return await fetch_all(app.data_pager, app.api, EVENTS, params, cap=SOURCE_CAP, max_page=PAGE_EVENTS)

    pages = await asyncio.gather(*(one(f) for f in families))
    rows = [
        _row(
            "event",
            e.get("timestamp"),
            e.get("details") or e.get("name"),
            device=e.get("networkDeviceName"),
            severity=e.get("severity"),
            type=e.get("messageType"),
            id=e.get("id"),
        )
        for page in pages
        for e in page.items
        if isinstance(e, dict)
    ]
    capped = [f for f, page in zip(families, pages, strict=True) if not page.complete]
    return rows, f"capped at {SOURCE_CAP} rows for {', '.join(capped)}" if capped else None


async def _notifications(
    app: CatcApp, hours: float, dev: dict[str, Any] | None, site: dict[str, Any] | None
) -> Any:
    found, complete = await fetch_notifications(app, hours, device=dev, site=site)
    rows = [
        _row(
            "notification",
            e.get("timestamp"),
            e.get("name") or e.get("eventId"),
            device=notification_device(e),
            severity=e.get("severity"),
            type=e.get("category"),
            details=_short(e.get("message") or e.get("description"), 200),
            id=e.get("instanceId"),
        )
        for e in found[:SOURCE_CAP]
    ]
    if not complete:
        return rows, f"scan stopped at the newest {NOTIFICATION_SCAN_CAP} notifications"
    return rows, f"capped at {SOURCE_CAP} rows" if len(found) > SOURCE_CAP else None


async def fetch_audit(
    app: CatcApp,
    params: dict[str, Any],
    *,
    device: dict[str, Any] | None = None,
    site: dict[str, Any] | None = None,
    cap: int = SOURCE_CAP,
) -> tuple[list[dict[str, Any]], bool, bool]:
    """Audit records for `params` (window, user, category...), newest first, plus `more` (records
    beyond `cap` may exist) and `scan_truncated` (the text scan stopped at AUDIT_SCAN_CAP).

    Catalyst Center tags few audit records with deviceId/siteId (3.2.2: template deploys, site
    settings and command runs carry neither), so a device or site scope also scans the window and
    keeps records whose text names the device (id, IP, hostname) or site (id, hierarchy)."""

    async def get(q: dict[str, Any], n: int) -> Any:
        return await fetch_all(app.audit_pager, app.api, AUDIT, q, cap=n, max_page=PAGE_AUDIT)

    if device is None and site is None:
        page = await get(params, cap)
        return [r for r in page.items if isinstance(r, dict)], not page.complete, False
    tagged_q = dict(params)
    if device is not None:
        tagged_q["deviceId"] = device["id"]
    if site is not None:
        tagged_q["siteId"] = site["id"]
    tagged, scan = await asyncio.gather(get(tagged_q, cap), get(params, AUDIT_SCAN_CAP))
    rows: dict[str, dict[str, Any]] = {}
    for r in [*tagged.items, *(e for e in scan.items if isinstance(e, dict) and in_scope(e, device, site))]:
        if isinstance(r, dict):
            rows.setdefault(str(r.get("instanceId") or id(r)), r)
    out = sorted(rows.values(), key=lambda r: _num(r.get("timestamp")), reverse=True)
    return out[:cap], (not tagged.complete) or len(out) > cap, not scan.complete


async def _audit(app: CatcApp, hours: float, dev: dict[str, Any] | None, site: dict[str, Any] | None) -> Any:
    params: dict[str, Any] = {
        **window(min(hours, 720)),
        "isSystemEvents": "true",
        "sortBy": "timestamp",
        "order": "desc",
    }
    found, more, truncated = await fetch_audit(app, params, device=dev, site=site)
    rows = [
        _row(
            "audit",
            r.get("timestamp"),
            r.get("description") or r.get("name"),
            user=r.get("userId") or r.get("userName"),
            severity=r.get("severity"),
            type=r.get("category"),
            id=r.get("instanceId"),
        )
        for r in found
    ]
    if truncated:
        return rows, f"text scan stopped at the newest {AUDIT_SCAN_CAP} audit records"
    return rows, f"capped at {SOURCE_CAP} rows" if more else None


SOURCE_FETCHERS: dict[str, Callable[..., Awaitable[Any]]] = {
    "issue": _issues,
    "event": _events,
    "notification": _notifications,
    "audit": _audit,
}


def merge(rows_by_source: dict[str, list[dict[str, Any]]], limit: int) -> list[dict[str, Any]]:
    """All rows newest first (ties keep source order), trimmed to `limit`, without the sort key."""
    merged = [r for src in SOURCES for r in rows_by_source.get(src, [])]
    merged.sort(key=lambda r: _num(r.get("_ms")), reverse=True)
    return [{k: v for k, v in r.items() if k != "_ms"} for r in merged[:limit]]


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="List event notifications")
    async def catc_list_event_notifications(
        ctx: Context,
        hours: Annotated[
            float, Field(gt=0, le=720, description="Look-back window in hours (default 24)")
        ] = 24,
        notification_type: Annotated[
            Literal["NETWORK", "SYSTEM", "APP", "INTEGRATIONS", "SECURITY", "AUDIT_LOG"] | None,
            Field(description="Only this notification type (default: everything except AUDIT_LOG)"),
        ] = None,
        category: Annotated[
            Literal["INFO", "WARN", "ERROR", "ALERT", "TASK_PROGRESS", "TASK_COMPLETE", "TASK_FAILURE"]
            | None,
            Field(description="Only this category"),
        ] = None,
        domain: Annotated[
            str | None,
            Field(description="Only this domain, e.g. 'Connectivity', 'Know Your Network', 'System'"),
        ] = None,
        severity: Annotated[
            int | None, Field(ge=1, le=5, description="Only severity this high or higher (1 = highest)")
        ] = None,
        device: Annotated[
            str | None, Field(description="Only notifications about this device (hostname, IP, serial or id)")
        ] = None,
        site: Annotated[
            str | None, Field(description="Only notifications about this site (hierarchy or id) or below it")
        ] = None,
        include_audit: Annotated[
            bool, Field(description="Also return AUDIT_LOG notifications (logins, API calls)")
        ] = False,
        limit: Annotated[int, Field(ge=1, le=500)] = 50,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """Catalyst Center platform event notifications, newest first: device unreachable, link and
        OSPF/BGP alerts raised as notifications, config-change (drift) events, provisioning, SWIM,
        licensing and system/service health. These are the events Catalyst Center can forward to
        webhooks or email; this tool reads them on demand from its event store. Audit records (logins,
        API calls) are left out unless include_audit=true or notification_type='AUDIT_LOG'
        (catc_list_audit_logs is the better view of those). Device and site filters match the
        notification text."""
        app: CatcApp = get_client(ctx)
        dev = await resolve_device(app, device) if device else None
        st = await resolve_site(app, site) if site else None
        rows, complete = await fetch_notifications(
            app,
            hours,
            type_=notification_type,
            category=category,
            domain=domain,
            severity=severity,
            include_audit=include_audit,
            device=dev,
            site=st,
        )
        page = page_of([notification_row(e) for e in rows], limit=limit, offset=offset)
        extra: dict[str, Any] = {}
        if not complete:
            page.total = None
            page.more = True
            extra["note"] = (
                f"Scanned the newest {NOTIFICATION_SCAN_CAP} notifications in the window only; "
                "narrow the window (hours) or add type/category/domain for older ones."
            )
        return list_result(
            page,
            fmt=response_format,
            columns=["time", "type", "category", "severity", "name", "device", "description", "id"],
            extra=extra or None,
        )

    @reg.read(title="Recent activity on a device or site")
    async def catc_recent_activity(
        ctx: Context,
        device: Annotated[
            str | None, Field(description="Device (hostname, IP, serial or id); omit for the whole network")
        ] = None,
        site: Annotated[
            str | None, Field(description="Site hierarchy or id (includes the sites below it)")
        ] = None,
        hours: Annotated[
            float,
            Field(gt=0, le=168, description="Look-back window in hours (default 1, max 7 days)"),
        ] = 1,
        sources: Annotated[
            list[Source] | None,
            Field(description="Sources to query (default all): issue, event, notification, audit"),
        ] = None,
        limit: Annotated[int, Field(ge=1, le=500)] = 100,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """What happened on this device or site recently? Queries Catalyst Center's assurance issues,
        assurance events (syslog, traps), platform event notifications and the audit log for the same
        window and scope, and merges them newest first with a `source` column. A source that fails is
        reported under `errors` and the others are still returned. Drill down with catc_get_issue,
        catc_list_events, catc_list_event_notifications or catc_list_audit_logs."""
        app: CatcApp = get_client(ctx)
        dev = await resolve_device(app, device) if device else None
        st = await resolve_site(app, site) if site else None
        wanted = list(dict.fromkeys(sources or SOURCES))
        results = await asyncio.gather(
            *(SOURCE_FETCHERS[s](app, hours, dev, st) for s in wanted), return_exceptions=True
        )
        rows_by_source: dict[str, list[dict[str, Any]]] = {}
        counts: dict[str, Any] = {}
        errors: dict[str, str] = {}
        partial: dict[str, str] = {}
        for src, res in zip(wanted, results, strict=True):
            if isinstance(res, BaseException):
                if not isinstance(res, Exception):
                    raise res
                errors[src] = _short(f"{type(res).__name__}: {res}", 300)
                continue
            rows, reason = res
            rows_by_source[src] = rows
            counts[src] = len(rows)
            if reason:
                partial[src] = reason
        if errors and not rows_by_source:
            raise UpstreamError(f"Every activity source failed: {errors}")
        merged = merge(rows_by_source, limit)
        scope = {
            "device": dev.get("hostname") if dev else None,
            "site": st.get("nameHierarchy") if st else None,
            "hours": hours,
        }
        out: dict[str, Any] = {
            "scope": {k: v for k, v in scope.items() if v is not None},
            "counts": counts,
        }
        if errors:
            out["errors"] = errors
        if partial:
            out["partial"] = partial
        total = sum(counts.values())
        if total > len(merged):
            out["note"] = (
                f"{total} rows found; showing the newest {len(merged)}. Raise limit or narrow hours."
            )
        return list_result(
            Page(merged, 0, None),
            fmt=response_format,
            columns=["time", "source", "what", "device", "severity", "type", "status", "user", "id"],
            extra=out,
        )
