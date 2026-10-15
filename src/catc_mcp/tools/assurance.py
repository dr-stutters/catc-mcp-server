"""Assurance reads: network/device/client health, clients, issues, events."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import asyncio
import re
import time
from datetime import UTC, datetime
from typing import Annotated, Any, Literal

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field
from stutters_mcp_core import (
    InvalidRequest,
    ResponseFormat,
    ToolRegistrar,
    UpstreamError,
    get_client,
    list_result,
    object_result,
)
from stutters_mcp_core.http import fetch_all, page_of

from catc_mcp.client import CatcApp, safe_id
from catc_mcp.common import (
    PAGE_DEVICE_HEALTH,
    PAGE_EVENTS,
    PAGE_ISSUES,
    ago,
    inventory_names,
    is_uuid,
    norm_mac,
    pick,
    resolve_device,
    resolve_site,
    window,
)

HEALTH_SCAN_CAP = 5000

Hours = Annotated[float, Field(gt=0, le=720, description="Look-back window in hours (default 24)")]

ISSUE_FIELDS = [
    "id",
    "name",
    "summary",
    "priority",
    "severity",
    "status",
    "category",
    "deviceType",
    "entityType",
    "entityId",
    "siteHierarchy",
    "firstOccurredTime",
    "mostRecentOccurredTime",
    "occurrenceCount",
]


# Issue attributes that repeat the top level or are Catalyst Center internals.
ATTR_DROP = {
    "type",
    "scope",
    "needState",
    "ctProfileName",
    "timeInMillis",
    "timestring",
    "status",
    "priority",
    "severity",
    "category",
    "entityType",
    "eventSource",
    "siteHierarchy",
    "buildingName",
    "areaName",
    "deviceFamily",
    "criticality",
    "eventUniqueId",
    "floorName",
    "siteType",
}


PAGE_CLIENTS = 100  # /dna/data/api/v1/clients (app.data_pager); larger pages untested


def client_row(c: dict[str, Any], now_ms: float | None = None) -> dict[str, Any]:
    """One client from the data API, the fields an operator scans for."""

    def sub(key: str) -> dict[str, Any]:
        v = c.get(key)
        return v if isinstance(v, dict) else {}

    nd, cn, hl, ob = sub("connectedNetworkDevice"), sub("connection"), sub("health"), sub("onboarding")
    fail = ob.get("latestFailureReason")
    row = {
        "mac": c.get("macAddress"),
        "ip": c.get("ipv4Address"),
        "type": c.get("type"),
        "user": c.get("username") if c.get("username") != c.get("macAddress") else None,
        "name": c.get("name"),
        "os": c.get("osType"),
        "status": c.get("connectionStatus"),
        "health": hl.get("overallScore"),
        "device": nd.get("connectedNetworkDeviceName"),
        "port": nd.get("interfaceName"),
        "ssid": cn.get("ssid"),
        "band": cn.get("band"),
        "wlc": cn.get("wlcName"),
        "vlan": cn.get("vlanId"),
        "site": c.get("siteHierarchy"),
        "last_failure": fail if fail not in (None, "SUCCESS") else None,
        "last_seen": ago(c.get("lastUpdatedTime"), now_ms),
    }
    return {k: v for k, v in row.items() if v not in (None, "", -1)}


# camelCase id-like attribute keys (siteId, deviceUuid, siteHierarchyGraphId...), not ssid/bssid.
ID_KEY = re.compile(r"(?<=[a-z])(Id|Ids|IdList|Uuid|GraphId)$")


def issue_attrs(i: dict[str, Any]) -> dict[str, Any]:
    """additionalAttributes as a dict (the API sends a key/value list)."""
    raw = i.get("additionalAttributes")
    if isinstance(raw, dict):
        return raw
    return {
        str(a.get("key")): a.get("value")
        for a in raw or []
        if isinstance(a, dict) and a.get("value") not in (None, "", "null")
    }


def is_device_issue(i: dict[str, Any]) -> bool:
    kind = str(i.get("entityType") or "").lower()
    return "network" in kind and "device" in kind


def issue_row(i: dict[str, Any], now_ms: float | None = None) -> dict[str, Any]:
    """An issue with its id under `id` (the data API calls it `issueId`), the device it is about,
    readable UTC times and how long ago it last occurred."""
    row = pick({**i, "id": i.get("issueId") or i.get("id")}, ISSUE_FIELDS)
    attrs = issue_attrs(i)
    if is_device_issue(i):
        dev = attrs.get("nwDeviceName") or attrs.get("managementIpAddr")
        if dev:
            row["device"] = dev
    if attrs.get("_count") and "occurrenceCount" not in row:
        row["occurrenceCount"] = attrs["_count"]
    if seen := ago(i.get("mostRecentOccurredTime"), now_ms):
        row["last_seen"] = seen
    for key in ("firstOccurredTime", "mostRecentOccurredTime"):
        if isinstance(row.get(key), int | float):
            row[key] = datetime.fromtimestamp(row[key] / 1000, tz=UTC).strftime("%Y-%m-%d %H:%M:%S")
    return row


async def mark_unmanaged(
    app: CatcApp, raw: list[dict[str, Any]], rows: list[dict[str, Any]]
) -> list[str] | None:
    """Flag issue rows whose device is no longer in the inventory (Assurance keeps their issues) and
    fill in missing device names; returns the unmanaged device names, or None when the inventory
    lookup failed."""
    ids = [str(i["entityId"]) for i in raw if is_device_issue(i) and is_uuid(str(i.get("entityId") or ""))]
    names = await inventory_names(app, ids) if ids else {}
    if names is None:
        return None
    gone: list[str] = []
    for i, row in zip(raw, rows, strict=True):
        eid = str(i.get("entityId") or "")
        if not (is_device_issue(i) and is_uuid(eid)):
            continue
        if eid not in names:
            row["device"] = f"{row.get('device') or eid} (not in inventory)"
            gone.append(str(row["device"]))
        elif "device" not in row:
            row["device"] = names[eid]
    return sorted(set(gone))


STALE_NOTE = (
    "Catalyst Center keeps an issue 'active' until it re-evaluates it, which can take hours: an issue "
    "whose last_seen is old may already have cleared. Check the live state with the issue's suggested "
    "commands (catc_get_issue -> catc_run_show_commands) before reporting it as current."
)


def group_issues(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Repeated issues (same name, device and summary) as one row, newest first: the newest
    occurrence's fields, the earliest firstOccurredTime and every id (newest first)."""
    ordered = sorted(rows, key=lambda r: str(r.get("mostRecentOccurredTime") or ""), reverse=True)
    groups: dict[tuple[Any, ...], dict[str, Any]] = {}
    for r in ordered:
        key = (r.get("name"), r.get("device"), r.get("summary"))
        g = groups.setdefault(key, {**r, "ids": []})
        g["ids"].append(r.get("id"))
        firsts = [str(x) for x in (g.get("firstOccurredTime"), r.get("firstOccurredTime")) if x]
        if firsts:
            g["firstOccurredTime"] = min(firsts)
    out = []
    for g in groups.values():
        if len(g["ids"]) == 1:
            g.pop("ids")
        else:
            g.pop("id", None)
            g["times_raised"] = len(g["ids"])
        out.append(g)
    return out


EVENT_FAMILIES = Literal[
    "Switches and Hubs",
    "Routers",
    "Wireless Controller",
    "Unified AP",
    "Wired Client",
    "Wireless Client",
]


def event_row(e: dict[str, Any]) -> dict[str, Any]:
    """One event, most useful columns first, with a readable UTC time."""
    ts = e.get("timestamp")
    row: dict[str, Any] = {
        "time": datetime.fromtimestamp(ts / 1000, tz=UTC).strftime("%Y-%m-%d %H:%M:%S")
        if isinstance(ts, int | float)
        else ts,
        "name": e.get("name"),
        "device": e.get("networkDeviceName"),
        "client": e.get("clientMac") or e.get("hostName"),
        "type": e.get("messageType"),
        "severity": e.get("severity"),
        "result": e.get("result"),
        "failure": e.get("failureCategory") or e.get("subreasonDescription"),
        "details": e.get("details"),
        "id": e.get("id"),
    }
    return {k: v for k, v in row.items() if v not in (None, "")}


async def issues_page(app: CatcApp, params: dict[str, Any], *, limit: int, offset: int) -> Any:
    return await app.data_pager.fetch_page(
        app.api,
        "/dna/data/api/v1/assuranceIssues",
        params,
        limit=limit,
        offset=offset,
        max_page=PAGE_ISSUES,
    )


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="Overall network health")
    async def catc_get_network_health(ctx: Context) -> ToolResult:
        """Overall network health score and the healthy/unhealthy device counts per category (access,
        distribution, core, router, wireless), plus a per-site health summary. Start here for "how is
        the network doing"; drill down with catc_list_device_health and catc_list_issues."""
        app: CatcApp = get_client(ctx)
        out: dict[str, Any] = {}
        results: tuple[Any, ...] = await asyncio.gather(
            app.api.get(
                "/dna/intent/api/v1/network-health", {"timestamp": int(time.time() * 1000) - 300_000}
            ),
            app.get_response("/dna/intent/api/v1/site-health"),
            return_exceptions=True,
        )
        net, sites = results
        if isinstance(net, UpstreamError):
            out["network_health"] = {
                "unavailable": str(net)[:200],
                "note": "Catalyst Center returns an error here when it has no assurance data yet "
                "(e.g. an empty inventory); per-site data below may still help.",
            }
        elif isinstance(net, BaseException):
            raise net
        elif isinstance(net, dict):
            out["network_health"] = {
                k: net[k]
                for k in (
                    "latestHealthScore",
                    "totalDevices",
                    "monitoredDevices",
                    "monitoredHealthyDevices",
                    "monitoredUnHealthyDevices",
                    "monitoredPoorHealthDevices",
                    "monitoredFairHealthDevices",
                    "noHealthDevices",
                )
                if k in net
            }
            # (sic) Catalyst Center spells it "healthDistirubution".
            dist = net.get("healthDistirubution") or net.get("healthDistribution") or []
            out["by_category"] = [
                {
                    "category": d.get("category"),
                    "healthScore": d.get("healthScore"),
                    "devices": d.get("totalCount"),
                    "good": d.get("goodCount"),
                    "fair": d.get("fairCount"),
                    "bad": d.get("badCount"),
                    "no_health": d.get("noHealthCount"),
                }
                for d in dist
                if isinstance(d, dict)
            ]
        else:
            out["network_health"] = net
        if isinstance(sites, list):
            keep = [
                "siteName",
                "siteType",
                "networkHealthAverage",
                "clientHealthWired",
                "clientHealthWireless",
                "numberOfNetworkDevice",
                "numberOfClients",
                "healthyNetworkDevicePercentage",
            ]
            out["sites"] = [pick(s, keep) for s in sites if isinstance(s, dict)]
        elif isinstance(sites, UpstreamError):
            out["sites"] = {"unavailable": str(sites)[:200]}
        elif isinstance(sites, BaseException):
            raise sites
        return object_result(out)

    @reg.read(title="List device health")
    async def catc_list_device_health(
        ctx: Context,
        role: Annotated[
            Literal["CORE", "ACCESS", "DISTRIBUTION", "ROUTER", "WLC", "AP"] | None,
            Field(description="Only devices with this role"),
        ] = None,
        health: Annotated[
            Literal["POOR", "FAIR", "GOOD"] | None, Field(description="Only devices in this health category")
        ] = None,
        site: Annotated[
            str | None, Field(description="Only devices at this site (id or name hierarchy)")
        ] = None,
        limit: Annotated[int, Field(ge=1, le=500)] = 50,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """Assurance health per network device: overall score, CPU/memory, interface/link errors,
        reachability, and the issue count. Filter with health='POOR' to find unhealthy devices. Assurance
        keeps health records of devices deleted from the inventory; those are left out (and named)."""
        app: CatcApp = get_client(ctx)
        params: dict[str, Any] = {}
        if role:
            params["deviceRole"] = role
        if health:
            params["health"] = health
        if site:
            params["siteId"] = (await resolve_site(app, site))["id"]
        # Fetched whole (the API returns up to 500 per page) so that leaving out deleted devices keeps
        # offsets and totals consistent.
        full = await fetch_all(
            app.data_pager,
            app.api,
            "/dna/intent/api/v1/device-health",
            params,
            cap=HEALTH_SCAN_CAP,
            max_page=PAGE_DEVICE_HEALTH,
        )
        fields = [
            "name",
            "ipAddress",
            "deviceFamily",
            "deviceType",
            "overallHealth",
            "cpuHealth",
            "memoryUtilizationHealth",
            "interfaceLinkErrHealth",
            "reachabilityHealth",
            "issueCount",
            "location",
            "uuid",
        ]
        rows = [d for d in full.items if isinstance(d, dict)]
        names = await inventory_names(app, [d.get("uuid") for d in rows])
        extra: dict[str, Any] = {"legend": "-1 = not computed for this device/platform"}
        if names is None:
            extra["inventory_check"] = "failed: records of deleted devices may be included"
        else:
            gone_ids = {
                str(d["uuid"])
                for d in rows
                if d.get("uuid") and is_uuid(str(d["uuid"])) and str(d["uuid"]) not in names
            }
            if gone_ids:
                gone = [d for d in rows if str(d.get("uuid")) in gone_ids]
                rows = [d for d in rows if str(d.get("uuid")) not in gone_ids]
                extra["left_out"] = (
                    f"{len(gone)} health record(s) of devices no longer in the inventory: "
                    + ", ".join(str(d.get("name") or d.get("ipAddress")) for d in gone)
                )
        page = page_of([pick(d, fields) for d in rows], limit=limit, offset=offset)
        if not full.complete:
            page.total = None
            page.more = True
            extra["scan"] = (
                f"only the first {HEALTH_SCAN_CAP} health records were read; filter by site or role"
            )
        return list_result(page, fmt=response_format, extra=extra)

    @reg.read(title="Client health")
    async def catc_get_client_health(ctx: Context) -> ToolResult:
        """Client health summary: overall, wired and wireless client scores and how many clients are
        in each health band (poor/fair/good/idle/no data). For one client use catc_client_360."""
        app: CatcApp = get_client(ctx)
        data = await app.get_response(
            "/dna/intent/api/v1/client-health", {"timestamp": int(time.time() * 1000) - 300_000}
        )
        out = []
        for site in data if isinstance(data, list) else []:
            for score in site.get("scoreDetail", []) or []:
                cat = score.get("scoreCategory", {})
                row: dict[str, Any] = {
                    "site": site.get("siteId"),
                    "category": cat.get("value"),
                    "score": score.get("scoreValue"),
                    "clients": score.get("clientCount"),
                }
                bands = {
                    str(b.get("scoreCategory", {}).get("value")): b.get("clientCount")
                    for b in score.get("scoreList", []) or []
                }
                if bands:
                    row["by_health"] = bands
                out.append(row)
        return object_result({"client_health": out, "note": "score -1 means no data (no clients)"})

    @reg.read(title="Get client")
    async def catc_get_client(
        ctx: Context,
        mac: Annotated[str, Field(description="Client MAC address (aa:bb:cc:dd:ee:ff or aabb.ccdd.eeff)")],
    ) -> ToolResult:
        """Details for one wired or wireless client: IP, user, host type/OS, health score, connected
        switch/port or AP/SSID/band, VLAN, RSSI/SNR, and onboarding state. For the full picture with
        its issues and connection path use catc_client_360."""
        app: CatcApp = get_client(ctx)
        mac_n = norm_mac(mac)
        data = await app.api.get(
            "/dna/intent/api/v1/client-detail",
            {"macAddress": mac_n, "timestamp": int(time.time() * 1000) - 60_000},
        )
        detail = data.get("detail", data) if isinstance(data, dict) else data
        return object_result(detail)

    @reg.read(title="List clients")
    async def catc_list_clients(
        ctx: Context,
        device: Annotated[
            str | None,
            Field(description="Switch, WLC or AP the clients connect through (hostname, IP, serial or id)"),
        ] = None,
        site: Annotated[
            str | None, Field(description="Site (id or name hierarchy; includes sites below)")
        ] = None,
        ssid: Annotated[str | None, Field(description="Wireless clients on this SSID")] = None,
        client_type: Annotated[
            Literal["Wired", "Wireless"] | None, Field(description="Wired or Wireless")
        ] = None,
        mac: Annotated[
            str | None, Field(description="MAC address; '*' wildcards allowed, e.g. '52:54:00*'")
        ] = None,
        ip: Annotated[
            str | None, Field(description="IPv4 address; '*' wildcards allowed, e.g. '10.10.*'")
        ] = None,
        connected_only: Annotated[
            bool, Field(description="Only clients connected now (default: everything seen in the window)")
        ] = False,
        hours: Hours = 24,
        limit: Annotated[int, Field(ge=1, le=500)] = 50,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """Wired and wireless clients Catalyst Center Assurance saw in the window, newest first: MAC, IP,
        user, type, connection status, health, the switch and port or WLC/SSID/band, VLAN, last
        onboarding failure and when it was last seen. Filter by the device they connect through, site,
        SSID, type, MAC or IP. Then catc_client_360 for one client."""
        app: CatcApp = get_client(ctx)
        params: dict[str, Any] = {**window(hours), "sortBy": "lastUpdatedTime", "order": "desc"}
        if device:
            dev = await resolve_device(app, device)
            name = str(dev.get("hostname") or "")
            if "wireless controller" in str(dev.get("family") or "").lower():
                params["wlcName"] = name
            else:
                params["connectedNetworkDeviceName"] = name
        if site:
            params["siteId"] = (await resolve_site(app, site))["id"]
        if ssid:
            params["ssid"] = ssid
        if client_type:
            params["type"] = client_type
        if mac:
            params["macAddress"] = mac if "*" in mac else norm_mac(mac)
        if ip:
            params["ipv4Address"] = ip
        if connected_only:
            # The API has no status filter; scan the window and keep the connected ones.
            full = await fetch_all(
                app.data_pager, app.api, "/dna/data/api/v1/clients", params, cap=2000, max_page=PAGE_CLIENTS
            )
            rows = [
                c
                for c in full.items
                if isinstance(c, dict) and str(c.get("connectionStatus") or "").lower() == "connected"
            ]
            page = page_of(rows, limit=limit, offset=offset)
            extra = (
                None if full.complete else {"scan": "read the newest 2000 clients only; narrow the filters"}
            )
        else:
            page = await app.data_pager.fetch_page(
                app.api,
                "/dna/data/api/v1/clients",
                params,
                limit=limit,
                offset=offset,
                max_page=PAGE_CLIENTS,
            )
            extra = None
        page.items = [client_row(c) for c in page.items if isinstance(c, dict)]
        return list_result(
            page,
            fmt=response_format,
            columns=[
                "mac",
                "ip",
                "type",
                "user",
                "status",
                "health",
                "device",
                "port",
                "ssid",
                "vlan",
                "last_failure",
                "last_seen",
            ],
            extra=extra,
        )

    @reg.read(title="List assurance issues")
    async def catc_list_issues(
        ctx: Context,
        priority: Annotated[
            list[Literal["P1", "P2", "P3", "P4"]] | None, Field(description="Only these priorities")
        ] = None,
        status: Annotated[
            Literal["active", "resolved", "ignored"] | None,
            Field(description="Issue status (default active)"),
        ] = "active",
        severity: Annotated[
            Literal["high", "medium", "low"] | None, Field(description="Only this severity")
        ] = None,
        category: Annotated[
            str | None, Field(description="Category, e.g. 'availability', 'connectivity', 'onboarding'")
        ] = None,
        site: Annotated[
            str | None, Field(description="Site name hierarchy; '*' wildcard allowed, e.g. 'Global/SJC/*'")
        ] = None,
        device: Annotated[
            str | None, Field(description="Only issues for this device (name, IP or id)")
        ] = None,
        mac: Annotated[str | None, Field(description="Only issues for this client/AP MAC")] = None,
        hours: Hours = 24,
        limit: Annotated[int, Field(ge=1, le=500)] = 50,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """Assurance issues (problems Catalyst Center detected) with priority, the device they are about,
        summary, status, site and how long ago each last occurred, newest first. Issues stay 'active'
        until Catalyst Center re-evaluates them, so an old last_seen may already have cleared; issues of
        devices deleted from the inventory are marked. Use catc_get_issue for root cause and suggested
        actions."""
        app: CatcApp = get_client(ctx)
        params: dict[str, Any] = {**window(hours), "sortBy": "mostRecentOccurredTime", "order": "desc"}
        if priority:
            params["priority"] = priority
        if status:
            params["status"] = status
        if severity:
            params["severity"] = severity
        if category:
            params["category"] = category
        if site:
            params["siteHierarchy"] = site if site.lower().startswith("global") else f"Global/{site}"
        if device:
            params["networkDeviceId"] = (await resolve_device(app, device))["id"]
        if mac:
            params["macAddress"] = norm_mac(mac)
        page = await issues_page(app, params, limit=limit, offset=offset)
        raw = [i for i in page.items if isinstance(i, dict)]
        page.items = [issue_row(i) for i in raw]
        gone = await mark_unmanaged(app, raw, page.items)
        extra: dict[str, Any] = {}
        if gone is None:
            extra["inventory_check"] = "failed: issues of deleted devices are not marked"
        elif gone:
            extra["unmanaged"] = (
                f"Issues for devices no longer in the inventory: {', '.join(gone)} (Catalyst Center keeps "
                "them until they age out)."
            )
        return list_result(
            page,
            fmt=response_format,
            columns=[
                "priority",
                "name",
                "device",
                "summary",
                "status",
                "siteHierarchy",
                "last_seen",
                "id",
            ],
            extra=extra or None,
        )

    @reg.read(title="Get assurance issue")
    async def catc_get_issue(
        ctx: Context,
        issue_id: Annotated[str, Field(description="Issue id from catc_list_issues")],
    ) -> ToolResult:
        """One assurance issue in full: description, affected device/client/site, timeline,
        additional attributes and Catalyst Center's suggested actions with the show commands it proposes
        (run them with catc_run_show_commands). Mark it resolved or ignored with
        catc_update_issue_status."""
        app: CatcApp = get_client(ctx)
        # No `view`: the default view is the one that carries suggestedActions.
        data = await app.get_response(f"/dna/data/api/v1/assuranceIssues/{safe_id(issue_id, 'issue id')}")
        data = data[0] if isinstance(data, list) and data else data
        if not isinstance(data, dict):
            return object_result(data)
        out = issue_row(data)
        for key in ("description", "deviceFamily", "siteName", "notes", "updatedBy", "isGlobal"):
            if data.get(key) not in (None, ""):
                out[key] = data[key]
        # Suggested actions: what to check, and the command-runner commands Catalyst Center proposes.
        out["suggested_actions"] = [
            {
                "action": a.get("message"),
                "commands": [
                    st.get("command")
                    for st in a.get("steps") or []
                    if isinstance(st, dict) and st.get("command")
                ],
            }
            for a in data.get("suggestedActions") or []
            if isinstance(a, dict)
        ]
        dup = {"nwDeviceName": out.get("device"), "managementIpAddr": out.get("device")}
        texts = {str(out.get("description") or ""), str(out.get("summary") or "")}
        attrs = {
            k: v
            for k, v in issue_attrs(data).items()
            if v not in (None, "", "null")
            and not k.startswith("_")
            and k not in ATTR_DROP
            and not ID_KEY.search(k)
            and not (k in dup and str(v) == str(dup[k]))
            and not (k in ("failureReason", "additionalDescription") and str(v) in texts | {"Issue"})
        }
        if attrs:
            out["attributes"] = attrs
        return object_result(out)

    @reg.read(title="List assurance events")
    async def catc_list_events(
        ctx: Context,
        device_family: Annotated[
            EVENT_FAMILIES | None,
            Field(description="Event family (one per call); default: the device's family, or Wired Client"),
        ] = None,
        device: Annotated[
            str | None,
            Field(description="Network device (hostname, IP, serial or id; or a name with '*' wildcards)"),
        ] = None,
        client_mac: Annotated[str | None, Field(description="Client MAC for client events")] = None,
        ap_mac: Annotated[str | None, Field(description="AP MAC for AP or wireless client events")] = None,
        message_type: Annotated[
            Literal["Syslog", "Trap", "Netflow", "Apple Diagnostics", "PathTrace"] | None,
            Field(description="Only events from this source"),
        ] = None,
        severity: Annotated[
            int | None, Field(ge=0, le=6, description="Max syslog-style severity (0 emergency .. 6 info)")
        ] = None,
        hours: Annotated[
            float, Field(gt=0, le=168, description="Look-back window in hours (max 7 days)")
        ] = 24,
        limit: Annotated[int, Field(ge=1, le=500)] = 50,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """Assurance events (syslog, SNMP traps, client onboarding events) for network devices or
        clients, newest first. The API takes one device family per call; it is worked out from
        `device` (or Wired/Wireless Client for client_mac/ap_mac) when not given."""
        app: CatcApp = get_client(ctx)
        family: str | None = device_family
        name = device
        if device and "*" not in device:
            dev = await resolve_device(app, device)
            name = str(dev.get("hostname"))
            family = family or str(dev.get("family") or "") or None
        if family is None:
            if ap_mac:
                family = "Wireless Client" if client_mac else "Unified AP"
            elif client_mac:
                family = "Wired Client"
            else:
                raise InvalidRequest(
                    "Give device_family, or a device / client_mac / ap_mac to infer it from."
                )
        params: dict[str, Any] = {
            "deviceFamily": family,
            **window(hours),
            "sortBy": "timestamp",
            "order": "desc",
        }
        if name:
            params["networkDeviceName"] = name
        if client_mac:
            params["clientMac"] = norm_mac(client_mac)
        if ap_mac:
            params["apMac"] = norm_mac(ap_mac)
        if message_type:
            params["messageType"] = message_type
        if severity is not None:
            params["severity"] = list(range(severity + 1))
        page = await app.data_pager.fetch_page(
            app.api,
            "/dna/data/api/v1/assuranceEvents",
            params,
            limit=limit,
            offset=offset,
            max_page=PAGE_EVENTS,
        )
        page.items = [event_row(e) for e in page.items if isinstance(e, dict)]
        return list_result(page, fmt=response_format)
