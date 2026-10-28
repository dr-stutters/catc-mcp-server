"""Network services health (D68): what Catalyst Center Assurance measured for the AAA (RADIUS), DHCP and DNS
servers the network devices use, from the data API's aaaServices / dhcpServices / dnsServices (transactions,
failures, latency per server and per device, EAP vs MAB for AAA) and their trend. "Is it the network or
ISE/DHCP?" in one call, with one verdict line per server.

#259: the data API counts only the transactions a device sent. A switch that has marked its AAA server DEAD
sends nothing, so a dead-server window shows no failures at all; for AAA the Assurance issues that say so
(fabric_aaa_server_down_trigger, radius_error_trigger), open or resolved in the window, go into the
verdict."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import fnmatch
import re
from datetime import UTC, datetime
from typing import Annotated, Any, Literal

from fastmcp import Context
from pydantic import Field

from catc_mcp._core import ToolRegistrar, UpstreamError, get_client
from catc_mcp._core.http import fetch_all
from catc_mcp.client import CatcApp
from catc_mcp.common import pick, resolve_site
from catc_mcp.tools.aaa import policy_servers
from catc_mcp.tools.assurance import issue_attrs, issue_row, issues_page
from catc_mcp.tools.assurance_analytics import pick_interval, trend_buckets, utc, window_ms

SERVICES = {"aaa": "aaaServices", "dhcp": "dhcpServices", "dns": "dnsServices"}
# The site filter each list API takes (dnsServices has no name-hierarchy filter: it takes the id form).
SITE_PARAM = {"aaa": "siteHierarchy", "dhcp": "deviceSiteHierarchy", "dns": "deviceSiteHierarchyId"}
COUNTERS = {
    "aaa": [
        "transactions",
        "successfulTransactions",
        "failedTransactions",
        "eapTransactions",
        "eapFailedTransactions",
        "mabTransactions",
        "mabFailedTransactions",
    ],
    "dhcp": ["transactions", "successfulTransactions", "failedTransactions"],
    "dns": ["transactions", "successfulTransactions", "failedTransactions"],
}
LATENCIES = {
    "aaa": ["latency", "eapLatency", "mabLatency"],
    "dhcp": ["latency", "discoverOfferLatency", "requestAcknowledgeLatency"],
    "dns": ["latency"],
}
DEVICE_FIELDS = ["deviceName", "deviceId", "deviceFamily", "deviceSiteHierarchy", "serverIp", "ssid"]
TREND_INTERVALS = [("5MIN", 5), ("15MIN", 15), ("1HR", 60), ("1DAY", 1440)]
ROW_CAP = 2000
TOP = 5
# Assurance issues raised when a device stops reaching its AAA server (#259): what each one says.
DEAD_ISSUES = {
    "fabric_aaa_server_down_trigger": "marked {label} DEAD",
    "radius_error_trigger": "reported {label} not responding",
}
DEAD_ISSUE_CAP = 100
IP_IN_TEXT = re.compile(r"'(\d{1,3}(?:\.\d{1,3}){3})[:']")
COUNTING_NOTE = (
    "The data API counts only the AAA transactions a device actually sent: while a switch has marked its "
    "server DEAD it sends nothing, and a switch without clients sends nothing either, so neither shows any "
    "failures. Dead-server windows come from the Assurance issues in dead_server_issues."
)


def n(v: Any) -> int:
    return int(v) if isinstance(v, int | float) and not isinstance(v, bool) else 0


def aggregate(service: str, rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Counters summed, latencies averaged weighted by the transactions they belong to (the API averages
    latency per row)."""
    out: dict[str, Any] = {k: sum(n(r.get(k)) for r in rows) for k in COUNTERS[service]}
    weights = {"latency": "transactions", "eapLatency": "eapTransactions", "mabLatency": "mabTransactions"}
    for lat in LATENCIES[service]:
        w = weights.get(lat, "transactions")
        total = sum(n(r.get(w)) for r in rows if r.get(lat) is not None)
        if total:
            out[f"{lat}_ms"] = round(sum(n(r.get(lat)) * n(r.get(w)) for r in rows) / total)
    tx = out.get("transactions", 0)
    if tx:
        out["success_percent"] = round(100 * out.get("successfulTransactions", 0) / tx, 1)
    return out


def device_row(service: str, r: dict[str, Any]) -> dict[str, Any]:
    row = pick(r, DEVICE_FIELDS)
    row |= {k: n(r.get(k)) for k in COUNTERS[service] if r.get(k) is not None}
    row |= {f"{k}_ms": r[k] for k in LATENCIES[service] if r.get(k) is not None}
    return row


def verdict(
    service: str, server: str, name: str | None, agg: dict[str, Any], devices: list[dict[str, Any]]
) -> str:
    label = f"{name} {server}" if name else server
    tx = agg.get("transactions", 0)
    if not tx:
        return f"{label}: no {service.upper()} transactions measured in the window."
    line = f"{label} answered {agg.get('success_percent', 0)}% of {tx} {service.upper()} requests"
    if agg.get("latency_ms") is not None:
        line += f", average latency {agg['latency_ms']} ms"
    failing = sorted(
        (d for d in devices if d.get("failedTransactions")), key=lambda d: -d["failedTransactions"]
    )
    if service == "aaa" and failing:
        d = failing[0]
        parts = [
            f"{d.get(k)} {m}"
            for k, m in (("mabFailedTransactions", "MAB"), ("eapFailedTransactions", "EAP"))
            if d.get(k)
        ]
        what = " and ".join(parts) or str(d["failedTransactions"])
        line += f"; {what} failures on {d.get('deviceName') or d.get('deviceId')}"
    elif failing:
        d = failing[0]
        line += f"; {d['failedTransactions']} failures on {d.get('deviceName') or d.get('deviceId')}"
    return line + "."


def hhmm(ms: Any) -> str | None:
    if not isinstance(ms, int | float) or isinstance(ms, bool):
        return None
    return datetime.fromtimestamp(ms / 1000, tz=UTC).strftime("%H:%M UTC")


def like(value: str, pattern: str) -> bool:
    """Case-insensitive wildcard match, also on the short host name (sw1 for sw1.example.com)."""
    v, p = value.lower(), pattern.lower()
    return fnmatch.fnmatchcase(v, p) or fnmatch.fnmatchcase(v.split(".")[0], p)


def dead_row(i: dict[str, Any]) -> dict[str, Any]:
    """One dead-AAA issue: the issue row plus the server it names and short first/last/resolved times."""
    row = issue_row(i)
    attrs = issue_attrs(i)
    if "device" not in row:
        dev = re.search(r"device '([^']+)'", str(i.get("summary") or i.get("description") or ""))
        if dev:
            row["device"] = dev.group(1)
    found = IP_IN_TEXT.search(str(i.get("summary") or i.get("description") or ""))
    server = found.group(1) if found else attrs.get("serverIp") or attrs.get("aaaServerIp")
    if server:
        row["server"] = str(server)
    row["first_at"] = hhmm(i.get("firstOccurredTime"))
    row["last_at"] = hhmm(i.get("mostRecentOccurredTime"))
    if str(i.get("status") or "").lower() == "resolved" and (at := hhmm(i.get("updatedTime"))):
        row["resolved_at"] = at
    return {k: v for k, v in row.items() if v is not None}


def dead_phrase(row: dict[str, Any], names: dict[str, str]) -> str:
    """'sw1 marked ISE 192.0.2.10 DEAD at 03:44 UTC (P1, resolved 03:47 UTC)'."""
    ip = row.get("server") or "its AAA server"
    label = f"{names[ip]} {ip}" if ip in names else ip
    what = DEAD_ISSUES.get(str(row.get("name")), "reported {label} unreachable").format(label=label)
    when = f"at {row['first_at']}" if row.get("first_at") else "in the window"
    if row.get("resolved_at"):
        state = f"resolved {row['resolved_at']}"
    elif str(row.get("status") or "").lower() == "active":
        state = f"still active, last seen {row.get('last_at') or '?'}"
    else:
        state = str(row.get("status") or "?")
    return f"{row.get('device') or 'a device'} {what} {when} ({row.get('priority') or '?'}, {state})"


async def dead_server_issues(
    app: CatcApp,
    start: int,
    end: int,
    *,
    site: dict[str, Any] | None,
    server: str | None,
    device: str | None,
) -> list[dict[str, Any]]:
    """The open and resolved dead-AAA issues in the window, filtered to the site, server and device."""
    params: dict[str, Any] = {
        "startTime": start,
        "endTime": end,
        "name": list(DEAD_ISSUES),
        "status": ["active", "resolved"],
        "sortBy": "mostRecentOccurredTime",
        "order": "desc",
    }
    if site is not None:
        params["siteHierarchy"] = f"{site['nameHierarchy']}*"
    page = await issues_page(app, params, limit=DEAD_ISSUE_CAP, offset=0)
    rows = []
    for i in page.items:
        if not isinstance(i, dict) or i.get("name") not in DEAD_ISSUES:
            continue
        if site is not None:
            nh, at = str(site["nameHierarchy"]), str(i.get("siteHierarchy") or "")
            if at and at != nh and not at.startswith(nh + "/"):
                continue
        row = dead_row(i)
        if server and not like(str(row.get("server") or ""), server):
            continue
        if device and not like(str(row.get("device") or ""), device):
            continue
        rows.append(row)
    return rows


def dead_verdicts(
    servers: list[dict[str, Any]], dead: list[dict[str, Any]], names: dict[str, str]
) -> list[str]:
    """Fold the dead-AAA issues into the per-server verdicts; a server with no transactions at all gets a
    verdict of its own, so a dead window never reads as 'nothing measured'. Returns those extra lines."""
    by_ip = {srv["server"]: srv for srv in servers}
    extra: dict[str, list[str]] = {}
    for row in dead:
        ip = str(row.get("server") or "?")
        phrase = dead_phrase(row, names)
        if ip in by_ip:
            by_ip[ip].setdefault("dead_server_issues", []).append(phrase)
        else:
            extra.setdefault(ip, []).append(phrase)
    tail = ": requests in that window never reached the server and are not counted."
    for srv in servers:
        if phrases := srv.get("dead_server_issues"):
            srv["verdict"] += " But " + "; ".join(phrases) + tail
    lines = []
    for ip, phrases in extra.items():
        label = f"{names[ip]} {ip}" if ip in names else ip
        lines.append(f"{label}: no AAA transactions counted, but " + "; ".join(phrases) + tail)
    return lines


async def trend(
    app: CatcApp, service: str, start: int, end: int, hours: float, server: str | None
) -> list[dict[str, Any]]:
    interval, _ = pick_interval(hours, TREND_INTERVALS)
    body: dict[str, Any] = {
        "startTime": start,
        "endTime": end,
        "trendInterval": interval,
        "aggregateAttributes": [
            {"name": k, "function": "sum"} for k in ("transactions", "failedTransactions")
        ],
        "page": {"limit": 500, "offset": 1, "timestampOrder": "asc"},
    }
    if server:
        body["filters"] = [{"key": "serverIp", "operator": "eq", "value": server}]
    data = await app.api.post(f"/dna/data/api/v1/{SERVICES[service]}/trendAnalytics", body)
    out = []
    for b in trend_buckets(data):
        vals = {
            a.get("name"): a.get("value") for a in b.get("aggregateAttributes") or [] if isinstance(a, dict)
        }
        if n(vals.get("transactions")) or n(vals.get("failedTransactions")):
            out.append(
                {
                    "time": utc(b.get("timestamp")),
                    "transactions": n(vals.get("transactions")),
                    "failed": n(vals.get("failedTransactions")),
                }
            )
    return out


async def service_health(
    app: CatcApp,
    service: str,
    *,
    hours: float,
    site: dict[str, Any] | None,
    server: str | None,
    device: str | None,
    with_trend: bool,
    names: dict[str, str],
) -> dict[str, Any]:
    start, end = window_ms(hours)
    params: dict[str, Any] = {"startTime": start, "endTime": end}
    if site is not None:
        params[SITE_PARAM[service]] = (
            site.get("siteHierarchyId") or site["id"] if service == "dns" else f"{site['nameHierarchy']}*"
        )
    if server:
        params["serverIp"] = server
    if device:
        params["deviceName"] = device
    page = await fetch_all(
        app.data_pager, app.api, f"/dna/data/api/v1/{SERVICES[service]}", params, cap=ROW_CAP, max_page=50
    )
    rows = [r for r in page.items if isinstance(r, dict)]
    by_server: dict[str, list[dict[str, Any]]] = {}
    for r in rows:
        by_server.setdefault(str(r.get("serverIp") or "?"), []).append(r)
    servers = []
    for ip, srows in sorted(by_server.items()):
        agg = aggregate(service, srows)
        devices = sorted(
            (device_row(service, r) for r in srows), key=lambda d: -d.get("failedTransactions", 0)
        )
        servers.append(
            {
                "server": ip,
                **({"name": names[ip]} if ip in names else {}),
                **agg,
                "verdict": verdict(service, ip, names.get(ip), agg, devices),
                "devices": devices[:50],
                **({"devices_total": len(devices)} if len(devices) > 50 else {}),
            }
        )
    out: dict[str, Any] = {"servers": servers}
    if service == "aaa":
        out["counting_note"] = COUNTING_NOTE
        try:
            dead = await dead_server_issues(app, start, end, site=site, server=server, device=device)
        except UpstreamError as e:
            dead = []
            out["dead_server_issues_unavailable"] = str(e)[:200]
        if dead:
            out["dead_server_issues"] = dead
            out["dead_verdicts"] = dead_verdicts(servers, dead, names)
    failing = sorted(
        (device_row(service, r) for r in rows if n(r.get("failedTransactions"))),
        key=lambda d: -d.get("failedTransactions", 0),
    )
    if failing:
        out["top_failing_devices"] = failing[:TOP]
    if not rows:
        out["note"] = (
            f"No {service.upper()} rows in the window: Catalyst Center measures these for managed devices "
            "with assurance telemetry (wired switches report AAA once provisioned at a site), and the data "
            "API "
            "lags the transactions by several minutes."
        )
    if not page.complete:
        out["truncated"] = f"First {ROW_CAP} rows only."
    if with_trend and rows:
        try:
            out["trend"] = await trend(app, service, start, end, hours, server)
        except UpstreamError as e:
            out["trend_unavailable"] = str(e)[:200]
    return out


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="Network services health (AAA, DHCP, DNS)")
    async def catc_network_services_health(
        ctx: Context,
        service: Annotated[
            Literal["aaa", "dhcp", "dns", "all"], Field(description="aaa (RADIUS to ISE), dhcp, dns or all")
        ] = "aaa",
        site: Annotated[
            str | None, Field(description="Only devices at this site and below (id or name hierarchy)")
        ] = None,
        hours: Annotated[float, Field(gt=0, le=720, description="Window, ending now")] = 24,
        server: Annotated[str | None, Field(description="Only this server IP (wildcards with *)")] = None,
        device: Annotated[str | None, Field(description="Only this device name (wildcards with *)")] = None,
        trend: Annotated[bool, Field(description="Add the transactions/failures trend per interval")] = True,
    ) -> dict[str, Any]:
        """How the AAA (RADIUS), DHCP and DNS servers answered the network, as Catalyst Center Assurance
        measured it: per server the transactions, successful and failed ones, success %, average latency
        (AAA: EAP vs MAB split; DHCP: discover-offer and request-ack), one verdict line ("ISE 198.18.134.35
        answered 97% of 212 AAA requests, average latency 180 ms; 6 MAB failures on sw1"), the devices
        (NADs) behind it with their own counts, the top failing devices and the trend. AAA also reads the
        Assurance issues saying a device marked its AAA server DEAD or not responding (open or resolved in
        the window) into the verdict: the data API counts only requests a device sent, so a dead-server
        window or a switch without clients shows no failures. Answers "is it the network or ISE/DHCP?" with
        Catalyst Center's own numbers; the data API lags by minutes. For one login's failure reason use ISE
        (ise_why_auth_failed)."""
        app: CatcApp = get_client(ctx)
        s = await resolve_site(app, site) if site else None
        names: dict[str, str] = {}
        try:
            for r in await policy_servers(app):
                kind = "ISE" if r.get("isIseEnabled") or r.get("iseEnabled") else "AAA"
                if r.get("ipAddress"):
                    names[str(r["ipAddress"])] = kind
        except UpstreamError:
            pass
        wanted = list(SERVICES) if service == "all" else [service]
        out: dict[str, Any] = {"window_hours": hours}
        if s:
            out["site"] = s.get("nameHierarchy")
        verdicts: list[str] = []
        for svc in wanted:
            try:
                res = await service_health(
                    app, svc, hours=hours, site=s, server=server, device=device, with_trend=trend, names=names
                )
            except UpstreamError as e:
                out[svc] = {"unavailable": str(e)[:200]}
                continue
            out[svc] = res
            verdicts += [srv["verdict"] for srv in res["servers"]]
            verdicts += res.pop("dead_verdicts", [])
        out["verdict"] = verdicts or ["No network-service transactions measured in the window."]
        return out
