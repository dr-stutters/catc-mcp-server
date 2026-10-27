"""On-demand activity lookups (D2): platform event notifications and a merged "what happened here
recently" view over issues, assurance events, notifications and the audit log.

Pull-only (core ADR-003): every call queries Catalyst Center for the window asked for. There is no
poller, buffer or subscription; the history available is what Catalyst Center keeps.
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import asyncio
import re
import time
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Annotated, Any, Literal

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field

from catc_mcp._core import (
    InvalidRequest,
    ResponseFormat,
    ToolRegistrar,
    UpstreamError,
    get_client,
    list_result,
)
from catc_mcp._core.http import Page, fetch_all, page_of
from catc_mcp.client import CatcApp
from catc_mcp.common import (
    PAGE_AUDIT,
    PAGE_EVENTS,
    PAGE_ISSUES,
    PAGE_NOTIFICATIONS,
    ensure_list,
    norm_mac,
    pick,
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


# Catalyst Center's own bookkeeping in the audit log: provisioning sub-flows and internal messaging
# (one provisioning writes ~60 of these), not changes anyone made. Found on 3.2.2-75131.
AUDIT_INTERNAL = re.compile(
    "|".join(
        [
            r"not applicable for the device",
            r"in Device Controllability has been initiated",
            r"^Finished executing .* flow",
            r"received a (request|response) message of type",
            r"^Sending (message|notification)",
            r"Telemetry Receiver is already configured",
            r"(Deleting existing|Configuring) Telemetry subscriptions",
            r"^Cisco Catalyst Center \S+ is reachable from device",
            r"^Provisioning complete notification received for device .* Resync will begin shortly",
            r"^Service request processing completed",
        ]
    ),
    re.IGNORECASE,
)
# Reads and sessions: logins, retrievals, downloads, show commands.
AUDIT_READ = re.compile(
    r"LOGIN_USER_EVENT: .* logged in successfully|logged out|retrieval succeeded|"
    r"^Report '.*' downloaded$|downloaded successfully|"
    r"request to run read-only commands|^Fetch(ed|ing)\b|^Get(ting)?\b",
    re.IGNORECASE,
)


def audit_kind(r: dict[str, Any]) -> str:
    """'internal' (Catalyst Center bookkeeping), 'read' (logins, reads) or 'change'."""
    text = str(r.get("description") or r.get("name") or "")
    if AUDIT_INTERNAL.search(text):
        return "internal"
    if AUDIT_READ.search(text):
        return "read"
    return "change"


def audit_device(r: dict[str, Any]) -> Any:
    """The device an audit record is about (Catalyst Center puts its management IP in
    network.deviceId), or None."""
    net = r.get("network")
    return net.get("deviceId") if isinstance(net, dict) and net.get("deviceId") else None


async def device_names_by_ip(app: CatcApp, ips: Any) -> dict[str, str]:
    """{management IP: hostname} for the IPs that are in the inventory (best effort)."""
    wanted = sorted({str(i) for i in ips if i})
    if not wanted:
        return {}
    try:
        found = await app.get_response("/dna/intent/api/v1/network-device", {"managementIpAddress": wanted})
    except UpstreamError:
        return {}
    return {
        str(d["managementIpAddress"]): str(d.get("hostname") or d["managementIpAddress"])
        for d in ensure_list(found)
        if isinstance(d, dict) and d.get("managementIpAddress")
    }


async def audit_rows(app: CatcApp, records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Audit records as readable rows: time (UTC), user, device, what, source IP, id."""
    names = await device_names_by_ip(app, [audit_device(r) for r in records])
    out = []
    for r in records:
        dev = audit_device(r)
        out.append(
            _clean(
                {
                    "time": ts_text(r.get("timestamp")),
                    "user": r.get("userId") or r.get("userName"),
                    "device": names.get(str(dev), dev) if dev else None,
                    "what": _short(r.get("description") or r.get("name"), 300),
                    "category": r.get("category") if r.get("category") not in (None, "INFO") else None,
                    "severity": r.get("severity") if r.get("severity") not in (None, 1, "1") else None,
                    "source": r.get("source") if r.get("source") not in (None, "NA") else None,
                    "id": r.get("instanceId"),
                }
            )
        )
    return out


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
    found, more, truncated = await fetch_audit(app, params, device=dev, site=site, cap=AUDIT_SCAN_CAP)
    kept = [r for r in found if audit_kind(r) == "change"]
    more = more or len(kept) > SOURCE_CAP
    kept = kept[:SOURCE_CAP]
    names = await device_names_by_ip(app, [audit_device(r) for r in kept])
    rows = [
        _row(
            "audit",
            r.get("timestamp"),
            r.get("description") or r.get("name"),
            device=names.get(str(audit_device(r)), audit_device(r)),
            user=r.get("userId") or r.get("userName"),
            type=r.get("category") if r.get("category") != "INFO" else None,
            severity=r.get("severity") if r.get("severity") not in (None, 1, "1") else None,
            id=r.get("instanceId"),
        )
        for r in kept
    ]
    notes = []
    if hidden := sum(1 for r in found if audit_kind(r) != "change"):
        notes.append(
            f"{hidden} audit records left out (logins, reads and Catalyst Center's internal provisioning "
            "steps; catc_list_audit_logs shows everything)"
        )
    if truncated:
        notes.append(f"text scan stopped at the newest {AUDIT_SCAN_CAP} audit records")
    elif more:
        notes.append(f"capped at {SOURCE_CAP} rows")
    return rows, "; ".join(notes) or None


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


# --- catc_client_timeline (D49) ------------------------------------------------------------------

CLIENT_DETAIL = "/dna/intent/api/v1/client-detail"
CLIENT_SOURCES = ("onboarding", "event", "issue")
ClientSource = Literal["onboarding", "event", "issue"]
EVENTS_MAX_HOURS = 168  # the assurance events API keeps 7 days
# client-detail's onboarding block: the time of the last completed step of each phase (epoch ms, 0 when
# Assurance has none: wired clients on 3.2.2 report 0 for all of them).
ONBOARDING_STEPS = (
    ("assocDoneTime", "Association done"),
    ("authDoneTime", "Authentication done"),
    ("dhcpDoneTime", "DHCP done"),
)
ROOT_CAUSES = ("latestRootCauseList", "assocRootcauseList", "aaaRootcauseList", "dhcpRootcauseList")


def since_hours(since: str, now_ms: float | None = None) -> float:
    """Hours between an ISO-8601 time (UTC when no offset is given) and now."""
    try:
        when = datetime.fromisoformat(since.strip())
    except ValueError:
        raise InvalidRequest(
            f"since {since!r} is not an ISO-8601 time; use e.g. '2026-10-27T09:30' (UTC) or "
            "'2026-10-27T19:30+10:00'."
        ) from None
    if when.tzinfo is None:
        when = when.replace(tzinfo=UTC)
    now = (now_ms if now_ms is not None else time.time() * 1000) / 1000
    hours = (now - when.timestamp()) / 3600
    if hours <= 0:
        raise InvalidRequest(f"since {since!r} is in the future.")
    if hours > EVENTS_MAX_HOURS:
        raise InvalidRequest(f"since {since!r} is more than 7 days ago (Assurance keeps 7 days of events).")
    return hours


def _detail_block(detail: dict[str, Any]) -> dict[str, Any]:
    d = detail.get("detail")
    return d if isinstance(d, dict) else {}


def _causes(onb: dict[str, Any]) -> dict[str, Any]:
    """The onboarding root-cause lists that say something other than SUCCESS."""
    out = {}
    for key in ROOT_CAUSES:
        vals = [v for v in ensure_list(onb.get(key)) if v and str(v).upper() != "SUCCESS"]
        if vals:
            out[key] = vals
    return out


def client_summary(detail: dict[str, Any]) -> dict[str, Any]:
    """Who the client is and where it connects, from client-detail's `detail` block."""
    d = _detail_block(detail)
    out = pick(
        d,
        [
            "hostName",
            "hostIpV4",
            "userId",
            "hostType",
            "connectionStatus",
            "clientConnection",
            "port",
            "ssid",
        ],
    )
    if d.get("vlanId") not in (None, -1, "-1"):
        out["vlanId"] = d["vlanId"]
    sec = d.get("security")
    if isinstance(sec, dict):
        out.update(pick(sec, ["selectedAuthzProfiles", "securityGroup", "authenticatingIse"]))
    if d.get("location"):
        out["location"] = d["location"]
    if seen := ts_text(d.get("lastUpdated")):
        out["last_updated"] = seen
    onb = d.get("onboarding")
    if isinstance(onb, dict) and (causes := _causes(onb)):
        out["onboarding_root_causes"] = causes
    return out


def onboarding_rows(detail: dict[str, Any], start_ms: float) -> list[dict[str, Any]]:
    """Timeline rows for the onboarding steps client-detail timestamps (inside the window only)."""
    d = _detail_block(detail)
    o = d.get("onboarding")
    onb: dict[str, Any] = o if isinstance(o, dict) else {}
    rows = []
    servers = {
        "authDoneTime": onb.get("aaaServerIp") or d.get("aaaServerIp"),
        "dhcpDoneTime": onb.get("dhcpServerIp") or d.get("dhcpServerIp"),
    }
    for key, what in ONBOARDING_STEPS:
        ms = _num(onb.get(key))
        if ms >= start_ms:
            rows.append(
                _row(
                    "onboarding",
                    ms,
                    what,
                    device=d.get("clientConnection"),
                    details=f"server {servers[key]}" if servers.get(key) else None,
                )
            )
    ms = _num(d.get("onboardingTime"))
    if ms >= start_ms:
        latest = [v for v in ensure_list(onb.get("latestRootCauseList")) if v]
        rows.append(
            _row(
                "onboarding",
                ms,
                "Onboarded",
                device=d.get("clientConnection"),
                result=", ".join(map(str, latest)) or None,
            )
        )
    return rows


def _event_what(e: dict[str, Any]) -> Any:
    name, details = e.get("name"), e.get("details")
    if name and details and details != name:
        return f"{name}: {details}"
    return name or details


def _is_roam(e: dict[str, Any]) -> bool:
    return bool(e.get("roamType")) or "roam" in str(e.get("name") or "").lower()


def client_event_rows(e: dict[str, Any]) -> list[dict[str, Any]]:
    """One assurance client event as a row, plus a `step` row per child event (the wireless
    onboarding steps: association, authentication, DHCP...)."""
    failure = e.get("failureCategory") or e.get("reasonDescription") or e.get("subReasonDescription")
    rows = [
        _row(
            "event",
            e.get("timestamp"),
            _event_what(e),
            type="roam" if _is_roam(e) else e.get("messageType"),
            result=e.get("resultStatus") or e.get("eventStatus"),
            failure=failure,
            device=e.get("networkDeviceName") or e.get("wlcName"),
            details=_short(
                "; ".join(
                    f"{k} {e[k]}"
                    for k in ("ssid", "apMac", "roamType", "vlanId", "ipv4", "username", "authServerIp")
                    if e.get(k) not in (None, "")
                ),
                200,
            ),
            id=e.get("id"),
        )
    ]
    for c in ensure_list(e.get("childEvents")):
        if isinstance(c, dict):
            rows.append(
                _row(
                    "step",
                    c.get("timestamp"),
                    f"{e.get('name') or 'event'} > {c.get('name') or c.get('details')}",
                    result=c.get("resultStatus"),
                    failure=c.get("failureCategory")
                    or c.get("reasonDescription")
                    or c.get("subReasonDescription"),
                    id=c.get("id"),
                )
            )
    return rows


async def client_events(app: CatcApp, mac: str, hours: float, host_type: str) -> Any:
    """Assurance events for the client: the Wired or Wireless Client family when client-detail said
    which, both otherwise."""
    kind = host_type.upper()
    families = (
        ["Wired Client"]
        if kind == "WIRED"
        else ["Wireless Client"]
        if kind == "WIRELESS"
        else ["Wired Client", "Wireless Client"]
    )

    async def one(fam: str) -> Page:
        params: dict[str, Any] = {
            "deviceFamily": fam,
            "clientMac": mac,
            **window(min(hours, EVENTS_MAX_HOURS)),
        }
        params.update(sortBy="timestamp", order="desc")
        return await fetch_all(app.data_pager, app.api, EVENTS, params, cap=SOURCE_CAP, max_page=PAGE_EVENTS)

    pages = await asyncio.gather(*(one(f) for f in families))
    rows = [r for page in pages for e in page.items if isinstance(e, dict) for r in client_event_rows(e)]
    capped = [f for f, page in zip(families, pages, strict=True) if not page.complete]
    return rows, f"capped at {SOURCE_CAP} events for {', '.join(capped)}" if capped else None


async def client_issues(app: CatcApp, mac: str, hours: float) -> Any:
    params: dict[str, Any] = {
        **window(hours),
        "macAddress": mac,
        "sortBy": "mostRecentOccurredTime",
        "order": "desc",
    }
    page = await fetch_all(app.data_pager, app.api, ISSUES, params, cap=SOURCE_CAP, max_page=PAGE_ISSUES)
    rows = []
    for i in page.items:
        if not isinstance(i, dict):
            continue
        first, last = i.get("firstOccurredTime"), i.get("mostRecentOccurredTime")
        rows.append(
            _row(
                "issue",
                last or first,
                i.get("summary") or i.get("name"),
                severity=i.get("priority"),
                status=i.get("status"),
                type=i.get("category"),
                details=f"first seen {ts_text(first)}" if first and first != last else None,
                id=i.get("issueId") or i.get("id"),
            )
        )
    return rows, None if page.complete else f"capped at {SOURCE_CAP} rows"


def merge_client(rows_by_source: dict[str, list[dict[str, Any]]], limit: int) -> list[dict[str, Any]]:
    """catc_client_timeline's rows newest first (event steps sit with their events)."""
    merged = [r for src in CLIENT_SOURCES for r in rows_by_source.get(src, [])]
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
        window and scope, and merges them newest first with a `source` column. Audit records are limited
        to changes (logins, reads and Catalyst Center's internal provisioning steps are counted, not
        listed). A source that fails is reported under `errors` and the others are still returned.
        For "what changed in the configuration" also see catc_compare_device_configs. Drill down with
        catc_get_issue, catc_list_events, catc_list_event_notifications or catc_list_audit_logs."""
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

    @reg.read(title="Client timeline")
    async def catc_client_timeline(
        ctx: Context,
        mac: Annotated[str, Field(description="Client MAC address (aa:bb:cc:dd:ee:ff or aabb.ccdd.eeff)")],
        hours: Annotated[
            float,
            Field(gt=0, le=168, description="Look-back window in hours (default 24, max 7 days)"),
        ] = 24,
        since: Annotated[
            str | None,
            Field(
                description="Start of the window as an ISO-8601 time instead of `hours`, e.g. "
                "'2026-10-27T09:30' (UTC) or '2026-10-27T19:30+10:00'; at most 7 days ago"
            ),
        ] = None,
        sources: Annotated[
            list[ClientSource] | None,
            Field(description="Sources to query (default all): onboarding, event, issue"),
        ] = None,
        limit: Annotated[int, Field(ge=1, le=500)] = 100,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """What happened to this client? One timeline, newest first, for one MAC: the onboarding steps
        Catalyst Center timestamps for it (association, authentication, DHCP, onboarded), its assurance
        events (ISE authentications, onboarding attempts with each step, roams, disconnects, with the
        result and failure reason) and its issues, merged by time with a `source` column. `client` says
        who and where it is now (IP, user, switch and port or SSID, VLAN, authorization profile, security
        group) and any onboarding root cause other than SUCCESS. The client half of catc_recent_activity.
        A source that fails is reported under `errors` and the others are still returned. ISE's own
        record of each login is in ise_get_auth_history (the catc_client_troubleshoot prompt merges the
        two); for the current state use catc_client_360."""
        app: CatcApp = get_client(ctx)
        m = norm_mac(mac)
        if since:
            hours = since_hours(since)
        wanted = list(dict.fromkeys(sources or CLIENT_SOURCES))
        start_ms = window(hours)["startTime"]
        sections: dict[str, Awaitable[Any]] = {
            # Like catc_client_360: the client as Assurance last saw it, a minute ago.
            "detail": app.api.get(
                CLIENT_DETAIL, {"macAddress": m, "timestamp": int(time.time() * 1000) - 60_000}
            )
        }
        if "issue" in wanted:
            sections["issue"] = client_issues(app, m, hours)
        results = dict(
            zip(sections, await asyncio.gather(*sections.values(), return_exceptions=True), strict=True)
        )
        detail = results.pop("detail")
        errors: dict[str, str] = {}
        out: dict[str, Any] = {"scope": {"mac": m, "hours": round(hours, 2)}}
        if isinstance(detail, BaseException):
            if not isinstance(detail, Exception):
                raise detail
            errors["client"] = _short(f"{type(detail).__name__}: {detail}", 300)
        if not isinstance(detail, dict):
            detail = {}
        host_type = str(_detail_block(detail).get("hostType") or "")
        if summary := client_summary(detail):
            out["client"] = summary
        if "event" in wanted:
            try:
                results["event"] = await client_events(app, m, hours, host_type)
            except Exception as e:  # noqa: BLE001 - reported per source like catc_recent_activity
                results["event"] = e
        rows_by_source: dict[str, list[dict[str, Any]]] = {}
        counts: dict[str, Any] = {}
        partial: dict[str, str] = {}
        if "onboarding" in wanted:
            if "client" in errors:
                errors["onboarding"] = errors["client"]
            else:
                rows_by_source["onboarding"] = onboarding_rows(detail, start_ms)
                counts["onboarding"] = len(rows_by_source["onboarding"])
        for src in ("event", "issue"):
            if src not in results:
                continue
            res = results[src]
            if isinstance(res, BaseException):
                if not isinstance(res, Exception):
                    raise res
                errors[src] = _short(f"{type(res).__name__}: {res}", 300)
                continue
            rows, reason = res
            rows_by_source[src] = rows
            counts[src] = sum(1 for r in rows if r.get("source") == src)
            if steps := sum(1 for r in rows if r.get("source") == "step"):
                counts["step"] = steps
            if reason:
                partial[src] = reason
        if not rows_by_source and errors:
            raise UpstreamError(f"Every timeline source failed: {errors}")
        merged = merge_client(rows_by_source, limit)
        out["counts"] = counts
        if errors:
            out["errors"] = errors
        if partial:
            out["partial"] = partial
        total = sum(len(v) for v in rows_by_source.values())
        if total > len(merged):
            out["note"] = (
                f"{total} rows found; showing the newest {len(merged)}. Raise limit or narrow hours."
            )
        elif not merged and "client" not in out:
            out["note"] = (
                "Catalyst Center has no data for this MAC in the window; check the MAC or widen hours."
            )
        return list_result(
            Page(merged, 0, None),
            fmt=response_format,
            columns=[
                "time",
                "source",
                "what",
                "result",
                "failure",
                "device",
                "type",
                "severity",
                "status",
                "details",
                "id",
            ],
            extra=out,
        )
