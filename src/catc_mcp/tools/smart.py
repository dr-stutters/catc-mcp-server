"""Task-oriented tools: device 360, client 360, path trace, read-only command runner."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import asyncio
import json
import re
import time
from collections.abc import Awaitable
from typing import Annotated, Any, Literal

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field
from stutters_mcp_core import (
    InvalidRequest,
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
from catc_mcp.common import DEVICE_FIELDS, ensure_list, is_ip, norm_mac, pick, resolve_device, window
from catc_mcp.tools.assurance import issue_row
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


async def _gather_sections(sections: dict[str, Awaitable[Any]]) -> tuple[dict[str, Any], dict[str, str]]:
    results = await asyncio.gather(*sections.values(), return_exceptions=True)
    ok: dict[str, Any] = {}
    errors: dict[str, str] = {}
    for key, val in zip(sections, results, strict=True):
        if isinstance(val, UpstreamError):
            errors[key] = str(val)[:200]
        elif isinstance(val, BaseException):
            raise val
        else:
            ok[key] = val
    return ok, errors


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="Device 360")
    async def catc_device_360(
        ctx: Context,
        device: Annotated[str, Field(description="Device hostname, management IP, serial number or id")],
    ) -> ToolResult:
        """Everything about one network device in one call: inventory record, site, assurance health
        (overall, CPU, memory), tags, whether it is provisioned, active issues (last 24h), interface
        counts and the ports that are down while admin-up, compliance status and end-of-life (EoX)
        alerts. Start device troubleshooting
        here; follow up with catc_get_issue, catc_get_device_config or catc_run_show_commands."""
        app: CatcApp = get_client(ctx)
        dev = await resolve_device(app, device)
        did = str(dev["id"])
        data, errors = await _gather_sections(
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
            out["active_issues"] = [
                issue_row(i) for i in ensure_list(issues.get("response")) if isinstance(i, dict)
            ]
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
        if "eox" in data:
            out["eox"] = data["eox"]
        elif "eox" in errors and "404" in errors["eox"]:
            del errors["eox"]
            out["eox"] = "no EoX data for this device (not scanned yet, or no announcements)"
        if "provisioned" in data:
            prov = [p for p in ensure_list(data["provisioned"]) if isinstance(p, dict)]
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
        data, errors = await _gather_sections(
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
            out["client"] = pick(
                d,
                [
                    "hostName",
                    "hostIpV4",
                    "userId",
                    "hostType",
                    "hostOs",
                    "deviceVendor",
                    "connectionStatus",
                    "healthScore",
                    "ssid",
                    "frequency",
                    "channel",
                    "rssi",
                    "snr",
                    "dataRate",
                    "vlanId",
                    "clientConnection",
                    "port",
                    "connectedDevice",
                    "location",
                    "onboarding",
                    "issueCount",
                    "lastUpdated",
                ],
            )
            if detail.get("connectionInfo"):
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
        source_ip: Annotated[str | None, Field(description="Source host or interface IP")] = None,
        dest_ip: Annotated[str | None, Field(description="Destination host or interface IP")] = None,
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
        Catalyst Center). Starts a flow analysis, waits for it and summarises it. It records the trace
        in Catalyst Center's path-trace history but changes no configuration."""
        app: CatcApp = get_client(ctx)
        if flow_analysis_id:
            fid = safe_id(flow_analysis_id, "flow analysis id")
        else:
            if not source_ip or not dest_ip or not is_ip(source_ip) or not is_ip(dest_ip):
                raise InvalidRequest("Give source_ip and dest_ip as IP addresses (or a flow_analysis_id).")
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
            entry["output"] = {
                c: redact_config(clean_output(c, str(t))) or "(no output)" for c, t in ok.items()
            }
            if resp.get("FAILURE"):
                entry["failed"] = {c: redact_config(str(t)) for c, t in resp["FAILURE"].items()}
            if resp.get("BLACKLISTED"):
                entry["blocked_by_catalyst_center"] = {
                    c: redact_config(str(t)) for c, t in resp["BLACKLISTED"].items()
                }
            out.append(entry)
        return object_result({"results": compact(out, mask_secrets=False)}, shape=False)
