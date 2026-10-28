"""Network settings writes (Design > Network Settings): DNS, NTP, DHCP, banner, time zone and
telemetry (syslog / SNMP trap collectors, wired client data collection) for a site, and pushing a
site's telemetry settings to its devices without a full re-provision (D122)."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import asyncio
import ipaddress
from typing import Annotated, Any
from zoneinfo import available_timezones

from fastmcp import Context
from pydantic import Field

from catc_mcp._core import (
    Confirm,
    InvalidRequest,
    NotFound,
    Plan,
    TaskFailed,
    ToolRegistrar,
    UpstreamError,
    UpstreamTimeout,
    field_changes,
    get_client,
    preview_or_apply,
)
from catc_mcp.client import CatcApp, safe_id
from catc_mcp.common import resolve_site
from catc_mcp.safety import device_limit_blockers, limit_policy, resolve_targets
from catc_mcp.tools.sites import SETTINGS

Servers = Annotated[
    list[str] | None,
    Field(max_length=10, description="Server IP addresses; [] clears the list for this site"),
]


def _ips(name: str, values: list[str] | None) -> list[str] | None:
    if values is None:
        return None
    out = []
    for v in values:
        try:
            out.append(str(ipaddress.ip_address(v.strip())))
        except ValueError as e:
            raise InvalidRequest(f"{name}: {v!r} is not an IP address.") from e
    return out


def _strip_inherited(v: Any) -> Any:
    if isinstance(v, dict):
        return {
            k: _strip_inherited(x) for k, x in v.items() if k not in ("inheritedSiteId", "inheritedSiteName")
        }
    return v


# D122: POST telemetrySettings/apply {deviceIds} makes devices conform to their own site's telemetry settings
# (3.2.2 spec: one task tracks the whole request; "for more granular status tracking, split your devices
# into multiple requests", so the tool sends one request per device).
TELEMETRY_APPLY_PATH = "/dna/intent/api/v1/telemetrySettings/apply"
TELEMETRY_VERIFY_COMMANDS = [
    "show logging | include Logging to",
    "show running-config | include snmp-server host",
    "show flow exporter",
]
_APPLY_CONCURRENCY = 5


def _brief(d: dict[str, Any]) -> str:
    return f"{d.get('hostname') or '(not collected yet)'} ({d.get('managementIpAddress')})"


def effective_telemetry(raw: Any, site_name: str | None) -> dict[str, Any]:
    """GET sites/{id}/telemetrySettings?_inherited=true -> each part with `source`: 'local' or
    'inherited from <site>'."""
    out: dict[str, Any] = {}
    for key, v in (raw if isinstance(raw, dict) else {}).items():
        if not isinstance(v, dict):
            out[key] = v
            continue
        part = _strip_inherited(v)
        name = v.get("inheritedSiteName")
        part["source"] = f"inherited from {name}" if name and name != site_name else "local"
        out[key] = part
    return out


async def _assigned_site(app: CatcApp, device_id: str) -> dict[str, Any] | None:
    try:
        a = await app.get_response(f"/dna/intent/api/v1/networkDevices/{safe_id(device_id)}/assignedToSite")
    except NotFound:
        return None
    return a if isinstance(a, dict) and a.get("siteId") else None


def register(reg: ToolRegistrar) -> None:
    @reg.write(title="Update site network settings", destructive=False)
    async def catc_update_site_settings(
        ctx: Context,
        site: Annotated[
            str, Field(description="Site (id or name hierarchy, 'Global' for all); child sites inherit it")
        ],
        dns_servers: Servers = None,
        domain_name: Annotated[
            str | None, Field(description="DNS domain name, e.g. 'corp.example.com'")
        ] = None,
        ntp_servers: Servers = None,
        dhcp_servers: Servers = None,
        banner: Annotated[
            str | None, Field(max_length=2000, description="Message-of-the-day banner text; '' removes it")
        ] = None,
        timezone: Annotated[
            str | None,
            Field(description="IANA time zone, e.g. 'Australia/Sydney', 'America/New_York', 'GMT'"),
        ] = None,
        syslog_servers: Servers = None,
        snmp_trap_servers: Servers = None,
        use_builtin_syslog: Annotated[
            bool | None, Field(description="Send syslog to Catalyst Center itself (Assurance needs this)")
        ] = None,
        use_builtin_trap_server: Annotated[
            bool | None, Field(description="Send SNMP traps to Catalyst Center itself")
        ] = None,
        wired_data_collection: Annotated[
            bool | None, Field(description="Enable wired endpoint data collection (Assurance client data)")
        ] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Change a site's network settings (Design > Network Settings): DNS servers and domain, NTP,
        DHCP servers, banner, time zone, and telemetry (external syslog/SNMP trap servers, Catalyst
        Center as collector, wired client data collection). Only the settings you pass change; child
        sites inherit them unless they override. Preview-first: shows each setting's current
        (effective, possibly inherited) and new value. Nothing reaches the devices until they are
        updated: telemetry (syslog, SNMP traps, NetFlow) with catc_apply_telemetry_settings, the other
        settings by re-provisioning (catc_provision_devices). Read settings with catc_get_site_settings."""
        app: CatcApp = get_client(ctx)
        s = await resolve_site(app, site)
        sid = str(s["id"])
        desired: dict[str, dict[str, Any]] = {}
        dns = _ips("dns_servers", dns_servers)
        if dns is not None or domain_name is not None:
            desired["dns"] = {"dns": {}}
            if domain_name is not None:
                desired["dns"]["dns"]["domainName"] = domain_name
            if dns is not None:
                desired["dns"]["dns"]["dnsServers"] = dns
        if (ntp := _ips("ntp_servers", ntp_servers)) is not None:
            desired["ntp"] = {"ntp": {"servers": ntp}}
        if (dhcp := _ips("dhcp_servers", dhcp_servers)) is not None:
            desired["dhcp"] = {"dhcp": {"servers": dhcp}}
        if banner is not None:
            desired["banner"] = {
                "banner": {"type": "Custom", "message": banner} if banner else {"type": "Builtin"}
            }
        if timezone is not None and timezone not in available_timezones() and timezone != "GMT":
            raise InvalidRequest(
                f"Unknown time zone {timezone!r}; use an IANA name such as 'Australia/Sydney'."
            )
        if timezone is not None:
            desired["timezone"] = {"timeZone": {"identifier": timezone}}
        tele: dict[str, Any] = {}
        syslog = _ips("syslog_servers", syslog_servers)
        if syslog is not None or use_builtin_syslog is not None:
            tele["syslogs"] = {}
            if syslog is not None:
                tele["syslogs"]["externalSyslogServers"] = syslog
            if use_builtin_syslog is not None:
                tele["syslogs"]["useBuiltinSyslogServer"] = use_builtin_syslog
        traps = _ips("snmp_trap_servers", snmp_trap_servers)
        if traps is not None or use_builtin_trap_server is not None:
            tele["snmpTraps"] = {}
            if traps is not None:
                tele["snmpTraps"]["externalTrapServers"] = traps
            if use_builtin_trap_server is not None:
                tele["snmpTraps"]["useBuiltinTrapServer"] = use_builtin_trap_server
        if wired_data_collection is not None:
            tele["wiredDataCollection"] = {"enableWiredDataCollection": wired_data_collection}
        if tele:
            desired["telemetry"] = tele
        if not desired:
            raise InvalidRequest("Give at least one setting to change.")

        current: dict[str, Any] = {}
        blockers: list[str] = []
        changes: dict[str, Any] = {}
        bodies: dict[str, dict[str, Any]] = {}
        for cat, want in desired.items():
            path = f"/dna/intent/api/v1/sites/{sid}/{SETTINGS[cat]}"
            try:
                cur = await app.get_response(path, {"_inherited": "true"})
                local = await app.get_response(path, {"_inherited": "false"})
            except UpstreamError as e:
                blockers.append(f"Can't read the current {cat} settings: {str(e)[:200]}")
                continue
            cur = _strip_inherited(cur if isinstance(cur, dict) else {})
            local = _strip_inherited(local if isinstance(local, dict) else {})
            current[cat] = {"effective": cur, "local": local}
            # Partial diff on purpose: the body below merges each given part into the site's own values
            # and keeps the category's other local sub-settings, so nothing is removed.
            diff = field_changes(cur, want)
            if diff:
                changes[cat] = diff
                # The PUT replaces the category's object at this site, so start from the values set
                # here (not inherited ones, which would turn into local overrides), including the
                # sub-settings this call doesn't touch (e.g. telemetry's snmpTraps when only syslogs change).
                body: dict[str, Any] = {k: v for k, v in local.items() if v not in (None, {}, [])}
                for key, part in want.items():
                    base = local.get(key) if isinstance(local.get(key), dict) else {}
                    body[key] = {**base, **part} if isinstance(part, dict) else part
                bodies[cat] = body
        if not blockers and not changes:
            blockers.append("Nothing to change: the site already has these settings.")
        plan = Plan(
            f"Update network settings of {s.get('nameHierarchy')}: {', '.join(changes) or 'nothing'}",
            details={
                "changes": changes,
                "note": "Devices get the new settings when updated: apply telemetry with "
                "catc_apply_telemetry_settings, or re-provision (catc_provision_devices) for other settings.",
            },
            fingerprint=current,
            blockers=blockers,
        )

        async def apply() -> Any:
            done: dict[str, Any] = {}
            for cat, body in bodies.items():
                path = f"/dna/intent/api/v1/sites/{sid}/{SETTINGS[cat]}"
                try:
                    job = await app.run_job("PUT", path, body, ctx=ctx, what=f"{cat} settings")
                except UpstreamError as e:
                    done[cat] = f"failed: {str(e)[:300]}"
                    return {"updated": done, "stopped_at": cat}
                done[cat] = job.get("status") or "ok"
            out: dict[str, Any] = {"updated": done}
            if "telemetry" in done:
                out["next"] = (
                    "Push the telemetry to the site's devices with catc_apply_telemetry_settings(site=...), "
                    "or re-provision (catc_provision_devices) for other settings."
                )
            else:
                out["next"] = "Re-provision the site's devices (catc_provision_devices) to push the settings."
            return out

        return await preview_or_apply(
            ctx,
            tool="catc_update_site_settings",
            args={
                "site": site,
                "dns_servers": dns_servers,
                "domain_name": domain_name,
                "ntp_servers": ntp_servers,
                "dhcp_servers": dhcp_servers,
                "banner": banner,
                "timezone": timezone,
                "syslog_servers": syslog_servers,
                "snmp_trap_servers": snmp_trap_servers,
                "use_builtin_syslog": use_builtin_syslog,
                "use_builtin_trap_server": use_builtin_trap_server,
                "wired_data_collection": wired_data_collection,
            },
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.write(title="Apply telemetry settings", destructive=False, idempotent=True)
    async def catc_apply_telemetry_settings(
        ctx: Context,
        devices: Annotated[
            list[str] | None,
            Field(max_length=100, description="Devices (hostname, IP, serial or id)"),
        ] = None,
        site: Annotated[
            str | None, Field(description="Every device assigned to this site or a site below it")
        ] = None,
        tag: Annotated[str | None, Field(description="Every device with this tag")] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Push the site telemetry settings (external syslog and SNMP trap servers, NetFlow / application
        visibility collector, wired and wireless data collection) to devices without a full re-provision:
        Catalyst Center's 'Update Telemetry Settings' device action. Each device follows the settings of
        the site it is assigned to (catc_update_site_settings changes them). Give exactly one of devices,
        site or tag. Preview-first: the device count, each device's site and that site's effective telemetry
        (local or inherited from a parent); counts towards CATC_MAX_DEVICES_PER_CHANGE. One Catalyst Center
        task per device; returns the status per device and the show commands to verify with
        catc_run_show_commands."""
        app: CatcApp = get_client(ctx)
        devs, targeting = await resolve_targets(app, devices, site, tag)
        if not devs:
            raise InvalidRequest(f"No devices to apply telemetry settings to ({targeting}).")
        blockers = device_limit_blockers(app, len(devs))
        sites: dict[str, dict[str, Any]] = {}
        per_device: list[dict[str, Any]] = []
        unassigned: list[str] = []
        if not blockers:  # over the limit: don't read every device's site just to refuse
            for d in devs:
                a = await _assigned_site(app, str(d["id"]))
                if a is None:
                    unassigned.append(_brief(d))
                    continue
                sid = str(a["siteId"])
                name = str(a.get("siteNameHierarchy") or sid)
                per_device.append({"device": _brief(d), "site": name})
                if sid not in sites:
                    try:
                        raw = await app.get_response(
                            f"/dna/intent/api/v1/sites/{safe_id(sid)}/{SETTINGS['telemetry']}",
                            {"_inherited": "true"},
                        )
                        tele: Any = effective_telemetry(raw, name.rsplit("/", 1)[-1])
                    except UpstreamError as e:
                        tele = {"error": f"can't read the site's telemetry settings: {str(e)[:200]}"}
                    sites[sid] = {"site": name, "devices": 0, "telemetry": tele}
                sites[sid]["devices"] += 1
        if unassigned:
            blockers.append(
                "Not assigned to a site, so there are no telemetry settings to apply: "
                f"{', '.join(unassigned)}. Assign them first (catc_assign_devices_to_site)."
            )
        unreachable = [
            _brief(d) for d in devs if str(d.get("reachabilityStatus") or "").lower() != "reachable"
        ]
        details: dict[str, Any] = {
            "targets": targeting,
            "device_count": len(devs),
            "devices": per_device or [{"device": _brief(d)} for d in devs],
            "site_telemetry": list(sites.values()),
            "method": "POST",
            "path": TELEMETRY_APPLY_PATH,
            "body": "one request per device: {'deviceIds': [<device id>]}",
            **limit_policy(app),
        }
        if unreachable:
            details["warning"] = (
                "Not Reachable in the inventory, so the update will probably fail there: "
                f"{', '.join(unreachable)}."
            )
        plan = Plan(
            f"Apply site telemetry settings to {len(devs)} device(s)",
            details=details,
            side_effects=[
                "Changes the running configuration of every listed device: logging hosts, SNMP trap "
                "receivers and NetFlow exporters follow the site's telemetry settings (others are removed).",
                "Not saved to the startup config: run catc_write_memory(devices) afterwards to keep it.",
            ],
            fingerprint={
                "devices": sorted(str(d["id"]) for d in devs),
                "sites": {k: v["telemetry"] for k, v in sites.items()},
            },
            blockers=blockers,
            blast_radius=len(devs),
        )

        async def apply() -> Any:
            sem = asyncio.Semaphore(_APPLY_CONCURRENCY)

            async def one(d: dict[str, Any]) -> dict[str, Any]:
                row: dict[str, Any] = {"device": _brief(d)}
                async with sem:
                    try:
                        job = await app.run_job(
                            "POST",
                            TELEMETRY_APPLY_PATH,
                            {"deviceIds": [str(d["id"])]},
                            ctx=ctx,
                            what=f"telemetry update {d.get('hostname') or d['id']}",
                        )
                    except (TaskFailed, UpstreamTimeout, UpstreamError) as e:
                        row.update(applied=False, error=str(e)[:400])
                        return row
                row.update(applied=True, status=job.get("status"))
                if job.get("task_id"):
                    row["task_id"] = job["task_id"]
                if job.get("progress"):
                    row["progress"] = job["progress"]
                return row

            rows = await asyncio.gather(*(one(d) for d in devs))
            ok = sum(1 for r in rows if r["applied"])
            out: dict[str, Any] = {"applied": ok, "failed": len(rows) - ok, "devices": rows}
            done = [d for d, r in zip(devs, rows, strict=True) if r["applied"]]
            if done:
                out["verify"] = {
                    "tool": "catc_run_show_commands",
                    "devices": [str(d.get("hostname") or d.get("managementIpAddress")) for d in done],
                    "commands": TELEMETRY_VERIFY_COMMANDS,
                }
                out["note"] = "Not saved to the startup config: catc_write_memory(devices) keeps it."
            if ok < len(rows):
                out["next"] = (
                    "Check the failed devices are Reachable and Managed (catc_get_device) and the task "
                    "(catc_get_task), then run catc_apply_telemetry_settings again for them."
                )
            return out

        return await preview_or_apply(
            ctx,
            tool="catc_apply_telemetry_settings",
            args={"devices": devices, "site": site, "tag": tag},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )
