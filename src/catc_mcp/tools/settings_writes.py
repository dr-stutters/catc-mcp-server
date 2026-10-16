"""Network settings writes (Design > Network Settings): DNS, NTP, DHCP, banner, time zone and
telemetry (syslog / SNMP trap collectors, wired client data collection) for a site."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import ipaddress
from typing import Annotated, Any
from zoneinfo import available_timezones

from fastmcp import Context
from pydantic import Field

from catc_mcp._core import (
    Confirm,
    InvalidRequest,
    Plan,
    ToolRegistrar,
    UpstreamError,
    field_changes,
    get_client,
    preview_or_apply,
)
from catc_mcp.client import CatcApp
from catc_mcp.common import resolve_site
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
        provisioned (catc_provision_devices). Read settings with catc_get_site_settings."""
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
            details={"changes": changes, "note": "Devices get the new settings when (re)provisioned."},
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
            return {"updated": done}

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
