"""Task-oriented tools: device 360, client 360, path trace, read-only command runner."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import json
import re
import time
from datetime import UTC, datetime
from typing import Annotated, Any, Literal

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field

from catc_mcp._core import (
    InvalidRequest,
    NotFound,
    TaskFailed,
    ToolRegistrar,
    UpstreamError,
    UpstreamTimeout,
    compact,
    get_client,
    object_result,
    poll_until,
)
from catc_mcp.client import CatcApp, safe_id
from catc_mcp.common import (
    DEVICE_FIELDS,
    ensure_list,
    gather_sections,
    inventory_names,
    is_ip,
    norm_mac,
    pick,
    resolve_device,
    window,
)
from catc_mcp.tools.assurance import (
    PAGE_CLIENTS,
    STALE_NOTE,
    client_row,
    clients_by_user,
    group_issues,
    issue_row,
    user_pattern,
)
from catc_mcp.tools.inventory import redact_config

# --- command runner allow-list ---------------------------------------------------------------

MAX_COMMANDS = 10
MAX_DEVICES = 20
_SHOW = re.compile(r"^(show|sh|sho)\s+\S", re.IGNORECASE)
# Output filters that only narrow what `show` prints. Anything else after a pipe (redirect, tee,
# append, ...) could write files on the device.
_PIPE_FILTERS = {
    "include",
    "exclude",
    "begin",
    "section",
    "count",
    "i",
    "in",
    "inc",
    "incl",
    "e",
    "ex",
    "exc",
    "excl",
    "b",
    "be",
    "beg",
    "s",
    "sec",
    "c",
    "cou",
}
# Pipe keywords that write or reformat output; never accepted, even glued to a regex.
_PIPE_WRITERS = ("redirect", "tee", "append", "format", "save", "file")
_FORBIDDEN = re.compile(r"[\n\r;`&<>]|\$\(")


def check_show_command(cmd: str) -> str:
    """Return the normalised command or raise InvalidRequest if it isn't a plain `show` command."""
    c = " ".join(cmd.split())
    if not c or not c.isascii() or not c.isprintable() or _FORBIDDEN.search(cmd) or not _SHOW.match(c):
        raise InvalidRequest(
            f"Refused {cmd!r}: only 'show ...' commands are allowed here (no ;, &, <, >, newlines)."
        )
    for i, part in enumerate(c.split("|")[1:]):
        words = part.strip().split()
        refused = False
        if i == 0 or part[:1].isspace() or not part:
            # A new pipe: only output filters.
            refused = not words or words[0].lower() not in _PIPE_FILTERS
        else:
            # Glued to the previous text ('include up|down'): a regex alternative, unless it could be
            # read as a pipe keyword (IOS accepts abbreviations, so refuse any prefix of one).
            refused = not words or any(k.startswith(words[0].lower()) for k in _PIPE_WRITERS)
        if refused:
            raise InvalidRequest(
                f"Refused {cmd!r}: after '|' only include/exclude/begin/section/count filters are allowed "
                "('a|b' regex alternatives are fine)."
            )
    return c


_PROMPT = re.compile(r"^[\w.\-/()]+[#>]\s*$")


def clean_output(command: str, text: str) -> str:
    """Drop the echoed command and the trailing device prompt the command runner includes."""
    lines = text.splitlines()
    if lines and " ".join(lines[0].split()) == " ".join(command.split()):
        lines = lines[1:]
    if lines and _PROMPT.match(lines[-1].strip()):
        lines = lines[:-1]
    return "\n".join(lines).strip("\n")


# --- path trace -------------------------------------------------------------------------------


def _iface(x: Any) -> str | None:
    if not isinstance(x, dict):
        return None
    phys = x.get("physicalInterface") or {}
    virt = ensure_list(x.get("virtualInterface"))
    names = [phys.get("name")] if isinstance(phys, dict) and phys.get("name") else []
    names += [v.get("name") for v in virt if isinstance(v, dict) and v.get("name")]
    return " / ".join(str(n) for n in names) or None


def summarise_trace(r: dict[str, Any]) -> dict[str, Any]:
    req = r.get("request") or {}
    hops = []
    for i, el in enumerate(ensure_list(r.get("networkElementsInfo")), start=1):
        if not isinstance(el, dict):
            continue
        hop: dict[str, Any] = {
            "hop": i,
            "name": el.get("name") or el.get("ip"),
            "ip": el.get("ip"),
            "type": el.get("type"),
            "role": el.get("role"),
            "ingress": _iface(el.get("ingressInterface")),
            "egress": _iface(el.get("egressInterface")),
            "learned_from": el.get("linkInformationSource"),
        }
        if el.get("tunnels"):
            hop["tunnels"] = el["tunnels"]
        stats = el.get("detailedStatus") or {}
        if isinstance(stats, dict) and stats.get("aclTraceCalculation") not in (None, "", "SUCCESS"):
            hop["acl_trace"] = stats
        hops.append({k: v for k, v in hop.items() if v not in (None, "", [])})
    out: dict[str, Any] = {
        "flow_analysis_id": req.get("id"),
        "status": req.get("status"),
        "source": req.get("sourceIP"),
        "destination": req.get("destIP"),
        "hops": hops,
    }
    for key in ("protocol", "sourcePort", "destPort", "failureReason"):
        if req.get(key):
            out[key] = req[key]
    acl = r.get("detailedStatus")
    if isinstance(acl, dict) and acl.get("aclTraceCalculation"):
        out["acl_trace"] = acl
    return out


async def trace_ip(app: CatcApp, ref: str) -> str:
    """An IP as given, or a managed device's management IP."""
    ref = ref.strip()
    if is_ip(ref):
        return ref
    if re.fullmatch(r"[\d.]+|[0-9a-fA-F]*:[0-9a-fA-F:]*", ref):
        raise InvalidRequest(f"{ref!r} is not a valid IP address.")
    ip = (await resolve_device(app, ref)).get("managementIpAddress")
    if not ip:
        raise InvalidRequest(f"Device {ref!r} has no management IP; give an IP address instead.")
    return str(ip)


# --- find host ---------------------------------------------------------------------------------

FIND_MAX = 5  # matching clients returned, newest first
SEARCH_MAX = 10  # switches searched live
_DOTTED = r"[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}"
_MAC_TABLE = re.compile(rf"^\s*\*?\s*(\d+)\s+({_DOTTED})\s+(\S+)\s+(\S+)", re.IGNORECASE)
_TRACKING = re.compile(rf"^\s*(\S+)\s+([0-9.]+|[0-9a-f:]+)\s+({_DOTTED})\s+(\S+)\s+(\d+)\s", re.IGNORECASE)
_ARP = re.compile(rf"^Internet\s+([0-9.]+)\s+\S+\s+({_DOTTED})\s+\S+\s+(\S+)", re.IGNORECASE)


def dotted(mac: str) -> str:
    raw = norm_mac(mac).replace(":", "")
    return f"{raw[0:4]}.{raw[4:8]}.{raw[8:12]}"


def live_hits(device: str, output: dict[str, str]) -> list[dict[str, Any]]:
    """Port/VLAN/MAC/IP rows from show mac address-table, show device-tracking database and show
    ip arp output."""
    hits: list[dict[str, Any]] = []
    for cmd, text in output.items():
        for line in str(text).splitlines():
            if "mac address-table" in cmd and (m := _MAC_TABLE.match(line)):
                hits.append(
                    {"vlan": m[1], "mac": norm_mac(m[2]), "type": m[3].lower(), "port": m[4], "source": cmd}
                )
            elif "device-tracking" in cmd and (m := _TRACKING.match(line)):
                hits.append({"ip": m[2], "mac": norm_mac(m[3]), "port": m[4], "vlan": m[5], "source": cmd})
            elif cmd.startswith("show ip arp") and (m := _ARP.match(line)):
                hits.append({"ip": m[1], "mac": norm_mac(m[2]), "interface": m[3], "source": cmd})
    return [{"device": device, **h} for h in hits]


def host_row(c: dict[str, Any]) -> dict[str, Any]:
    """client_row plus what 'where is it plugged in' needs: the switch's management IP and id, the
    SGT and the AAA server that answered, and one 'where' line."""
    nd: dict[str, Any] = c.get("connectedNetworkDevice") or {}
    cn: dict[str, Any] = c.get("connection") or {}
    ob: dict[str, Any] = c.get("onboarding") or {}
    row = client_row(c)
    sgt = str(cn.get("securityGroupTag") or "").removesuffix(".0")
    extra = {
        "device_ip": nd.get("connectedNetworkDeviceManagementIp"),
        "device_id": nd.get("connectedNetworkDeviceId"),
        "ap_mac": cn.get("apMac") if cn.get("apMac") not in (None, "-1") else None,
        "sgt": sgt if sgt not in ("", "-1", "0") else None,
        "aaa_server": ob.get("aaaServerIp"),
    }
    row.update({k: v for k, v in extra.items() if v not in (None, "")})
    if row.get("ssid"):
        where = f"AP {row.get('device') or row.get('ap_mac') or '?'}"
        where += f" on WLC {row['wlc']}" if row.get("wlc") else ""
        where += f", SSID {row['ssid']}"
    else:
        where = str(row.get("device") or "unknown switch")
        where += f" ({row['device_ip']})" if row.get("device_ip") else ""
        where += f" {row['port']}" if row.get("port") else ""
    if row.get("vlan"):
        where += f", VLAN {row['vlan']}"
    if row.get("site"):
        where += f", {row['site']}"
    row["where"] = where
    return row


async def clients_by(app: CatcApp, key: str, value: str, hours: float) -> list[dict[str, Any]]:
    """Newest clients for a MAC or IP (GET clients) or a client hostname (clients/query 'name')."""
    if key == "name":
        resp = await app.api.post(
            "/dna/data/api/v1/clients/query",
            {
                **window(hours),
                "filters": [{"key": "name", "operator": "like", "value": user_pattern(value, partial=False)}],
                "page": {
                    "limit": FIND_MAX,
                    "offset": 1,
                    "sortBy": [{"name": "lastUpdatedTime", "order": "desc"}],
                },
            },
        )
        items = resp.get("response") if isinstance(resp, dict) else resp
    else:
        resp = await app.api.get(
            "/dna/data/api/v1/clients",
            {
                **window(hours),
                key: value,
                "sortBy": "lastUpdatedTime",
                "order": "desc",
                "limit": min(FIND_MAX, PAGE_CLIENTS),
                "offset": 1,
            },
        )
        items = resp.get("response") if isinstance(resp, dict) else resp
    return [c for c in ensure_list(items) if isinstance(c, dict)][:FIND_MAX]


# Catalyst Center 3.2.2 answers 400 "Maximum of 5 commands allowed per request" to a longer command list.
RUNNER_MAX_COMMANDS = 5


async def run_show(
    app: CatcApp, ctx: Context, devs: list[dict[str, Any]], cmds: list[str]
) -> list[dict[str, Any]]:
    """Run checked `show` commands on resolved devices through the command runner: one entry per
    device with its output (secrets masked), failures and commands Catalyst Center blocked. More than
    RUNNER_MAX_COMMANDS commands go in several runner requests, one after another, merged per device."""
    merged: dict[str, dict[str, Any]] = {}
    for i in range(0, len(cmds), RUNNER_MAX_COMMANDS):
        for entry in await _run_show_once(app, ctx, devs, cmds[i : i + RUNNER_MAX_COMMANDS]):
            into = merged.setdefault(str(entry["device"]), {"device": entry["device"], "output": {}})
            into["output"].update(entry.get("output") or {})
            for key in ("failed", "blocked_by_catalyst_center"):
                if entry.get(key):
                    into.setdefault(key, {}).update(entry[key])
    return list(merged.values())


async def _run_show_once(
    app: CatcApp, ctx: Context, devs: list[dict[str, Any]], cmds: list[str]
) -> list[dict[str, Any]]:
    names = {str(d["id"]): str(d.get("hostname") or d.get("managementIpAddress")) for d in devs}
    timeout = app.settings.command_runner_timeout
    started = await app.api.post(
        "/dna/intent/api/v1/network-device-poller/cli/read-request",
        {
            "name": "catc-mcp-show",
            "commands": cmds,
            "deviceUuids": list(names),
            "timeout": int(min(timeout, 300)),
        },
    )
    try:
        job = await app.wait_job(started, ctx=ctx, timeout=timeout + 30, what="command runner")
    except TaskFailed as e:
        raise TaskFailed(f"Command runner failed: {e}") from e
    progress = job.get("progress")
    if isinstance(progress, str):
        try:
            progress = json.loads(progress)
        except ValueError:
            progress = {}
    file_id = progress.get("fileId") if isinstance(progress, dict) else None
    if not file_id:
        raise UpstreamError(f"Command runner finished without an output file: {job}")
    results = await app.api.get(f"/dna/intent/api/v1/file/{safe_id(str(file_id), 'file id')}")
    out: list[dict[str, Any]] = []
    for r in ensure_list(results):
        if not isinstance(r, dict):
            continue
        resp = r.get("commandResponses") or {}
        entry: dict[str, Any] = {"device": names.get(str(r.get("deviceUuid")), r.get("deviceUuid"))}
        ok = resp.get("SUCCESS") or {}
        entry["output"] = {c: redact_config(clean_output(c, str(t))) or "(no output)" for c, t in ok.items()}
        if resp.get("FAILURE"):
            entry["failed"] = {c: redact_config(str(t)) for c, t in resp["FAILURE"].items()}
        if resp.get("BLACKLISTED"):
            entry["blocked_by_catalyst_center"] = {
                c: redact_config(str(t)) for c, t in resp["BLACKLISTED"].items()
            }
        out.append(entry)
    return out


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="Device 360")
    async def catc_device_360(
        ctx: Context,
        device: Annotated[str, Field(description="Device hostname, management IP, serial number or id")],
    ) -> ToolResult:
        """Everything about one network device in one call: inventory record, site, assurance health
        (overall, CPU, memory), tags, whether it is provisioned, active issues (last 24h, repeats grouped,
        with how long ago each last occurred), interface
        counts and the ports that are down while admin-up, compliance status and end-of-life (EoX)
        alerts. Start device troubleshooting
        here; follow up with catc_get_issue, catc_get_device_config or catc_run_show_commands."""
        app: CatcApp = get_client(ctx)
        dev = await resolve_device(app, device)
        did = str(dev["id"])
        data, errors = await gather_sections(
            {
                "health": app.get_response(f"/dna/data/api/v1/networkDevices/{did}"),
                "issues": app.api.get(
                    "/dna/data/api/v1/assuranceIssues",
                    {**window(24), "networkDeviceId": did, "status": "active", "limit": 20, "offset": 1},
                ),
                "interfaces": app.get_response(f"/dna/intent/api/v1/interface/network-device/{did}"),
                "compliance": app.get_response("/dna/intent/api/v1/compliance", {"deviceUuid": did}),
                "eox": app.get_response(f"/dna/intent/api/v1/eox-status/device/{did}"),
                "provisioned": app.get_response(
                    "/dna/intent/api/v1/sda/provisionDevices", {"networkDeviceId": did}
                ),
            }
        )
        out: dict[str, Any] = {"device": pick(dev, [*DEVICE_FIELDS, "series", "macAddress", "lastUpdated"])}
        if "reachabilityFailureReason" in dev:
            out["device"]["reachabilityFailureReason"] = dev["reachabilityFailureReason"]
        health = data.get("health")
        if isinstance(health, dict):
            out["site"] = health.get("siteHierarchy")
            if health.get("tagNames"):
                out["tags"] = health["tagNames"]
            m = health.get("metricsDetails")
            metrics: dict[str, Any] = m if isinstance(m, dict) else {}
            # -1 / null mean "not computed" for this platform.
            out["health"] = {
                k: v
                for k, v in {**health, **metrics}.items()
                if v not in (None, -1, "")
                and not isinstance(v, dict | list)
                and any(
                    w in k.lower() for w in ("health", "score", "utilization", "temperature", "communication")
                )
            }
            if not out["health"]:
                out["health"] = "not computed yet (Assurance needs ~15 minutes after a device is added)"
        issues = data.get("issues")
        if isinstance(issues, dict):
            rows = [issue_row(i) for i in ensure_list(issues.get("response")) if isinstance(i, dict)]
            keep = [
                "name",
                "priority",
                "summary",
                "last_seen",
                "mostRecentOccurredTime",
                "occurrenceCount",
                "id",
                "ids",
            ]
            grouped = [{k: g[k] for k in [*keep, "times_raised"] if k in g} for g in group_issues(rows)]
            out["active_issues"] = grouped
            if grouped:
                out["issues_note"] = STALE_NOTE
        ifaces = [i for i in ensure_list(data.get("interfaces")) if isinstance(i, dict)]
        if "interfaces" in data:
            down = [
                pick(i, ["portName", "description", "status", "adminStatus"])
                for i in ifaces
                if str(i.get("status", "")).lower() == "down"
                and str(i.get("adminStatus", "")).upper() == "UP"
            ]
            out["interfaces"] = {
                "total": len(ifaces),
                "up": sum(1 for i in ifaces if str(i.get("status", "")).lower() == "up"),
                "admin_down": sum(1 for i in ifaces if str(i.get("adminStatus", "")).upper() == "DOWN"),
                "down_but_enabled": down[:50],
            }
        comp = ensure_list(data.get("compliance"))
        if comp:
            out["compliance"] = pick(comp[0], ["complianceStatus", "lastUpdateTime", "message"])
            if isinstance(out["compliance"].get("lastUpdateTime"), int | float):
                out["compliance"]["checked"] = datetime.fromtimestamp(
                    out["compliance"].pop("lastUpdateTime") / 1000, tz=UTC
                ).strftime("%Y-%m-%d %H:%M UTC")
        if "eox" in data:
            out["eox"] = data["eox"]
        elif "eox" in errors and "404" in errors["eox"]:
            del errors["eox"]
            out["eox"] = "no EoX data for this device (not scanned yet, or no announcements)"
        if "provisioned" in data:
            prov = [
                p
                for p in ensure_list(data["provisioned"])
                if isinstance(p, dict) and p.get("networkDeviceId") == did
            ]
            out["provisioned"] = bool(prov)
        if errors:
            out["unavailable"] = errors
        return object_result(out)

    @reg.read(title="Client 360")
    async def catc_client_360(
        ctx: Context,
        mac: Annotated[str, Field(description="Client MAC address (aa:bb:cc:dd:ee:ff or aabb.ccdd.eeff)")],
        hours: Annotated[float, Field(gt=0, le=168, description="Look-back window for issues/events")] = 24,
    ) -> ToolResult:
        """Everything about one client in one call: identity (IP, user, host type/OS), health score,
        where it connects (switch and port, or AP, SSID, band and RSSI/SNR), VLAN, onboarding state,
        its active issues and recent onboarding events. Use it for "why is this user's connection bad"."""
        app: CatcApp = get_client(ctx)
        m = norm_mac(mac)
        data, errors = await gather_sections(
            {
                "detail": app.api.get(
                    "/dna/intent/api/v1/client-detail",
                    {"macAddress": m, "timestamp": int(time.time() * 1000) - 60_000},
                ),
                "issues": app.api.get(
                    "/dna/data/api/v1/assuranceIssues",
                    {**window(hours), "macAddress": m, "limit": 20, "offset": 1},
                ),
            }
        )
        out: dict[str, Any] = {"mac": m}
        detail = data.get("detail")
        host_type = ""
        if isinstance(detail, dict):
            d = detail.get("detail") or {}
            host_type = str(d.get("hostType", ""))
            wireless = host_type.upper() == "WIRELESS"
            fields = [
                "hostName",
                "hostIpV4",
                "userId",
                "hostType",
                "hostOs",
                "deviceVendor",
                "connectionStatus",
                "vlanId",
                "clientConnection",
                "port",
                "location",
                "issueCount",
                "lastUpdated",
            ]
            if wireless:
                fields += ["ssid", "frequency", "channel", "rssi", "snr", "dataRate"]
            out["client"] = pick(d, fields)
            scores = {
                str(h.get("healthType")).lower(): h.get("score")
                for h in ensure_list(d.get("healthScore"))
                if isinstance(h, dict) and h.get("healthType")
            }
            if scores:
                out["client"]["health"] = scores
            dev = [
                pick(c, ["name", "type", "mgmtIp", "id"])
                for c in ensure_list(d.get("connectedDevice"))
                if isinstance(c, dict)
            ]
            if dev:
                out["client"]["connected_device"] = dev[0] if len(dev) == 1 else dev
            o = d.get("onboarding")
            onb: dict[str, Any] = o if isinstance(o, dict) else {}
            causes = {
                k: onb[k]
                for k in ("latestRootCauseList", "dhcpRootcauseList", "aaaRootcauseList")
                if onb.get(k)
            }
            if causes:
                out["client"]["onboarding"] = causes
            if wireless and detail.get("connectionInfo"):
                out["connection"] = detail["connectionInfo"]
            topo = detail.get("topology") or {}
            if isinstance(topo, dict) and topo.get("nodes"):
                out["path"] = [
                    pick(n, ["name", "deviceType", "ip", "role", "healthScore"])
                    for n in ensure_list(topo.get("nodes"))
                    if isinstance(n, dict)
                ]
        issues = data.get("issues")
        if isinstance(issues, dict):
            out["issues"] = [issue_row(i) for i in ensure_list(issues.get("response")) if isinstance(i, dict)]
        family = "Wireless Client" if host_type.upper() == "WIRELESS" else "Wired Client"
        try:
            ev = await app.api.get(
                "/dna/data/api/v1/assuranceEvents",
                {"deviceFamily": family, "clientMac": m, **window(min(hours, 168)), "limit": 20, "offset": 1},
            )
            out["recent_events"] = [
                pick(e, ["timestamp", "name", "subreasonDescription", "result", "failureCategory", "details"])
                for e in ensure_list(ev.get("response") if isinstance(ev, dict) else ev)
                if isinstance(e, dict)
            ]
        except UpstreamError as e:
            errors["events"] = str(e)[:200]
        if errors:
            out["unavailable"] = errors
        if "client" not in out and not out.get("issues"):
            out["note"] = (
                "Catalyst Center has no data for this MAC in the window; check the MAC or widen `hours`."
            )
        return object_result(out)

    @reg.read(title="Path trace", idempotent=False)
    async def catc_path_trace(
        ctx: Context,
        source_ip: Annotated[
            str | None,
            Field(description="Source host or interface IP, or a managed device name (its management IP)"),
        ] = None,
        dest_ip: Annotated[
            str | None,
            Field(description="Destination IP, or a managed device name (its management IP)"),
        ] = None,
        protocol: Annotated[
            Literal["TCP", "UDP"] | None, Field(description="Protocol (both checked when omitted)")
        ] = None,
        source_port: Annotated[int | None, Field(ge=1, le=65535, description="Source port")] = None,
        dest_port: Annotated[int | None, Field(ge=1, le=65535, description="Destination port")] = None,
        include_stats: Annotated[
            bool, Field(description="Collect interface/device/QoS statistics and ACL trace (slower)")
        ] = False,
        flow_analysis_id: Annotated[
            str | None, Field(description="Fetch an earlier path trace by id instead of starting a new one")
        ] = None,
        wait: Annotated[bool, Field(description="Wait for the trace to finish (default true)")] = True,
    ) -> ToolResult:
        """Trace the network path between two IPs as Catalyst Center sees it: each hop (device,
        ingress/egress interfaces, how the link was learned), ACL verdicts when statistics are
        requested, and the failure reason if the trace can't be built (e.g. the source isn't known to
        Catalyst Center). A device name stands for its management IP, which may take the management
        path rather than the data path: give loopback/host IPs for that. Starts a flow analysis, waits
        for it and summarises it. It records the trace
        in Catalyst Center's path-trace history but changes no configuration."""
        app: CatcApp = get_client(ctx)
        if flow_analysis_id:
            fid = safe_id(flow_analysis_id, "flow analysis id")
        else:
            if not source_ip or not dest_ip:
                raise InvalidRequest(
                    "Give source_ip and dest_ip (IPs or device names), or a flow_analysis_id."
                )
            # A device name stands for its management IP (a loopback or host IP traces a data path).
            source_ip = await trace_ip(app, source_ip)
            dest_ip = await trace_ip(app, dest_ip)
            body: dict[str, Any] = {"sourceIP": source_ip, "destIP": dest_ip, "periodicRefresh": False}
            if protocol:
                body["protocol"] = protocol
            if source_port:
                body["sourcePort"] = str(source_port)
            if dest_port:
                body["destPort"] = str(dest_port)
            if include_stats:
                body["inclusions"] = ["INTERFACE-STATS", "DEVICE-STATS", "QOS-STATS", "ACL-TRACE"]
            started = await app.api.post("/dna/intent/api/v1/flow-analysis", body)
            fid = (
                str((started.get("response") or {}).get("flowAnalysisId", ""))
                if isinstance(started, dict)
                else ""
            )
            if not fid:
                raise UpstreamError(f"Catalyst Center did not return a flow analysis id: {started}")
        path = f"/dna/intent/api/v1/flow-analysis/{fid}"

        async def fetch() -> dict[str, Any]:
            r = await app.get_response(path)
            return r if isinstance(r, dict) else {}

        def status(r: dict[str, Any]) -> str:
            return str((r.get("request") or {}).get("status", "")).upper()

        if not wait:
            r = await fetch()
            return object_result(
                {**summarise_trace(r), "how_to_check": f"catc_path_trace(flow_analysis_id='{fid}')"}
            )
        try:
            r = await poll_until(
                fetch,
                done=lambda r: status(r) in ("COMPLETED", "FAILED"),
                describe=status,
                timeout=min(app.settings.mcp_task_timeout, 300),
                interval=2.0,
                ctx=ctx,
                what="path trace",
            )
        except UpstreamTimeout as e:
            raise UpstreamTimeout(f"{e} Check later with catc_path_trace(flow_analysis_id='{fid}').") from e
        return object_result(summarise_trace(r))

    @reg.read(title="Run show commands", idempotent=False)
    async def catc_run_show_commands(
        ctx: Context,
        devices: Annotated[list[str], Field(description="Devices (hostname, IP, serial or id); up to 20")],
        commands: Annotated[
            list[str],
            Field(description="Up to 10 'show' commands, e.g. ['show ip int brief', 'show run | sec bgp']"),
        ],
    ) -> ToolResult:
        """Run read-only `show` commands live on managed devices through Catalyst Center's command
        runner and return each device's output. Only `show ...` is accepted (pipes limited to
        include/exclude/begin/section/count; no redirects); secrets in the output are masked. Use it
        for live state that inventory doesn't hold (routing tables, logs, counters)."""
        app: CatcApp = get_client(ctx)
        if not devices or not commands:
            raise InvalidRequest("Give at least one device and one command.")
        if len(devices) > MAX_DEVICES or len(commands) > MAX_COMMANDS:
            raise InvalidRequest(f"At most {MAX_DEVICES} devices and {MAX_COMMANDS} commands per call.")
        cmds = [check_show_command(c) for c in commands]
        devs = [await resolve_device(app, d) for d in devices]
        out = await run_show(app, ctx, devs, cmds)
        return object_result({"results": compact(out, mask_secrets=False)}, shape=False)

    @reg.read(title="Find a host", idempotent=False)
    async def catc_find_host(
        ctx: Context,
        mac: Annotated[str | None, Field(description="Host MAC address (any notation)")] = None,
        ip: Annotated[str | None, Field(description="Host IPv4 address")] = None,
        hostname: Annotated[
            str | None, Field(description="Host name as Assurance knows it (or a network device's hostname)")
        ] = None,
        user: Annotated[
            str | None,
            Field(
                description="Username the host logged in with (802.1X/web identity); case-insensitive, "
                "'*' wildcards allowed"
            ),
        ] = None,
        search_devices: Annotated[
            list[str] | None,
            Field(
                description="Up to 10 switches to look the host up on live (MAC table, device-tracking, "
                "ARP via the command runner): needed when Assurance has no record, and confirms where "
                "it is now"
            ),
        ] = None,
        hours: Annotated[float, Field(gt=0, le=720, description="Look-back window in hours")] = 24,
    ) -> ToolResult:
        """Where is this host plugged in: from a MAC, IP, hostname or username, each matching client
        Assurance saw in the window, newest first, with its switch (name, management IP) and port or
        AP/WLC/SSID, VLAN, SGT, site, status, health, last seen and a one-line `where`, plus a live
        lookup on given switches. Give exactly one of the four. A username can match several hosts (a
        ticket that arrives with a username: take the MAC to ise_why_auth_failed). With
        `search_devices` the host is also looked up live on those switches (show mac address-table /
        device-tracking / ip arp through the command runner): the answer when Assurance has none, or a
        check that it is still there. Then catc_client_360 for its health and issues."""
        app: CatcApp = get_client(ctx)
        given = {k: v for k, v in {"mac": mac, "ip": ip, "hostname": hostname, "user": user}.items() if v}
        if len(given) != 1:
            raise InvalidRequest("Give exactly one of mac, ip, hostname or user.")
        if search_devices and len(search_devices) > SEARCH_MAX:
            raise InvalidRequest(f"At most {SEARCH_MAX} search_devices per call.")
        out: dict[str, Any] = {"query": given}
        if mac:
            found = await clients_by(app, "macAddress", norm_mac(mac), hours)
        elif ip:
            if not is_ip(ip) or ":" in ip:
                raise InvalidRequest(f"{ip!r} is not an IPv4 address.")
            found = await clients_by(app, "ipv4Address", ip.strip(), hours)
        elif hostname:
            found = await clients_by(app, "name", hostname, hours)
        else:
            assert user is not None
            found, how, complete = await clients_by_user(app, user, hours, partial=False, cap=FIND_MAX)
            out["user_match"] = how if complete else f"{how}; more than {FIND_MAX} matched, newest shown"
        hosts = [host_row(c) for c in found]
        if hosts:
            present = await inventory_names(app, [h.get("device_id") for h in hosts])
            for h in hosts:
                if present is not None and h.get("device_id") and h["device_id"] not in present:
                    h["device_in_inventory"] = False
                h.pop("device_id", None)
            out["where"] = hosts[0]["where"]
            if len({h["mac"] for h in hosts if h.get("mac")}) > 1:
                out["note"] = f"{len(hosts)} hosts match, newest first: pick one by MAC."
        out["found"] = len(hosts)
        out["hosts"] = hosts
        if hostname and not hosts:
            try:
                dev = await resolve_device(app, hostname)
            except (InvalidRequest, NotFound):
                dev = None
            if dev:
                out["network_device"] = pick(dev, DEVICE_FIELDS)
                out["note"] = (
                    f"{hostname!r} is a network device in the inventory, not a client: catc_device_360."
                )
        if search_devices:
            key_mac = norm_mac(mac) if mac else (hosts[0].get("mac") if hosts and not ip else None)
            if key_mac:
                d = dotted(str(key_mac))
                cmds = [f"show mac address-table address {d}", f"show device-tracking database mac {d}"]
            elif ip:
                cmds = [f"show device-tracking database address {ip.strip()}", f"show ip arp {ip.strip()}"]
            else:
                cmds = []
            if cmds:
                devs = [await resolve_device(app, x) for x in search_devices]
                results = await run_show(app, ctx, devs, [check_show_command(c) for c in cmds])
                live: list[dict[str, Any]] = []
                for r in results:
                    live += live_hits(str(r.get("device")), r.get("output") or {})
                    if r.get("failed") or r.get("blocked_by_catalyst_center"):
                        out.setdefault("live_unavailable", {})[str(r.get("device"))] = r.get(
                            "failed"
                        ) or r.get("blocked_by_catalyst_center")
                arp_macs = sorted({str(h["mac"]) for h in live if h.get("interface")})
                if ip and arp_macs and not any(h.get("port") for h in live):
                    # Only ARP knew the IP (an SVI, no port): find the port from the MAC table.
                    again = await run_show(
                        app,
                        ctx,
                        devs,
                        [
                            check_show_command(f"show mac address-table address {dotted(m)}")
                            for m in arp_macs[:3]
                        ],
                    )
                    for r in again:
                        live += live_hits(str(r.get("device")), r.get("output") or {})
                out["live"] = live
                if live and not hosts:
                    first = next((h for h in live if h.get("port")), live[0])
                    out["where"] = (
                        f"{first['device']} {first.get('port') or first.get('interface')}"
                        + (f", VLAN {first['vlan']}" if first.get("vlan") else "")
                        + " (live; not in Assurance)"
                    )
                if live:
                    out["live_note"] = (
                        "A MAC learned on an uplink or trunk shows the next switch, not the access port; "
                        "the device-tracking row names the access port."
                    )
            else:
                out["live"] = "nothing to search for: no MAC or IP is known for this host"
        if not hosts and not out.get("live") and "network_device" not in out:
            out["next_steps"] = [
                f"Widen `hours` (now {hours:g}) if the host was last seen earlier",
                "Give search_devices (the site's access switches) to search their MAC, device-tracking "
                "and ARP tables live",
                "If the host authenticated, ISE has its session: ise_find_session / ise_why_auth_failed",
            ]
        return object_result(out)
