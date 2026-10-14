"""Assurance reads: network/device/client health, clients, issues, events."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import asyncio
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
from stutters_mcp_core.http import OffsetLimit

from catc_mcp.client import CatcApp, safe_id
from catc_mcp.common import DATA_PAGER, norm_mac, pick, resolve_device, resolve_site, window

EVENTS_PAGER = OffsetLimit(items="response", total="page.count", one_based=True, max_page=20)
DEVICE_HEALTH_PAGER = OffsetLimit(items="response", total="totalCount", one_based=True, max_page=500)

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
    return await DATA_PAGER.fetch_page(
        app.api, "/dna/data/api/v1/assuranceIssues", params, limit=limit, offset=offset
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
        reachability, and the issue count. Filter with health='POOR' to find unhealthy devices."""
        app: CatcApp = get_client(ctx)
        params: dict[str, Any] = {}
        if role:
            params["deviceRole"] = role
        if health:
            params["health"] = health
        if site:
            params["siteId"] = (await resolve_site(app, site))["id"]
        page = await DEVICE_HEALTH_PAGER.fetch_page(
            app.api, "/dna/intent/api/v1/device-health", params, limit=limit, offset=offset
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
        page.items = [pick(d, fields) for d in page.items if isinstance(d, dict)]
        return list_result(page, fmt=response_format)

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
        """Assurance issues (problems Catalyst Center detected) with priority, severity, status,
        category, affected entity and site, newest first. Use catc_get_issue for root cause and
        suggested actions."""
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
        page.items = [pick(i, ISSUE_FIELDS) for i in page.items if isinstance(i, dict)]
        return list_result(page, fmt=response_format)

    @reg.read(title="Get assurance issue")
    async def catc_get_issue(
        ctx: Context,
        issue_id: Annotated[str, Field(description="Issue id from catc_list_issues")],
    ) -> ToolResult:
        """One assurance issue in full: description, affected device/client/site, timeline,
        additional attributes and Catalyst Center's suggested actions (troubleshooting steps)."""
        app: CatcApp = get_client(ctx)
        data = await app.get_response(
            f"/dna/data/api/v1/assuranceIssues/{safe_id(issue_id, 'issue id')}", {"view": "impactedHosts"}
        )
        return object_result(data)

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
        page = await EVENTS_PAGER.fetch_page(
            app.api, "/dna/data/api/v1/assuranceEvents", params, limit=limit, offset=offset
        )
        page.items = [event_row(e) for e in page.items if isinstance(e, dict)]
        return list_result(page, fmt=response_format)
