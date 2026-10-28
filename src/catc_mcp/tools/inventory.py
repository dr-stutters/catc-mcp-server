"""Inventory reads: devices, interfaces, running config, modules."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import asyncio
import contextlib
import re
from typing import Annotated, Any, Literal

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field

from catc_mcp._core import (
    ResponseFormat,
    ToolRegistrar,
    UpstreamError,
    get_client,
    list_result,
    object_result,
    text_result,
)
from catc_mcp._core.http import fetch_all, page_of
from catc_mcp.client import CatcApp
from catc_mcp.common import DEVICE_FIELDS, ensure_list, pick, resolve_device, resolve_site
from catc_mcp.safety import ASSIGNED, devices_by_id, site_assignments
from catc_mcp.tools.udfs import device_udfs

DeviceRef = Annotated[str, Field(description="Device hostname, management IP, serial number or id")]

INTERFACE_FIELDS = [
    "portName",
    "status",
    "adminStatus",
    "description",
    "ipv4Address",
    "vlanId",
    "portMode",
    "speed",
    "duplex",
    "macAddress",
    "interfaceType",
    "id",
]

# Patterns for IOS-style lines that carry secrets. Each has a `keep` group; everything after it on
# the line is masked.
_SECRET_PATTERNS = [
    # SNMP: host community strings and v3 user auth/priv keys.
    re.compile(
        r"^(?P<keep>\s*snmp-server\s+host\s+\S+(?:\s+(?:informs|traps))?"
        r"(?:\s+version\s+(?:1|2c|3(?:\s+(?:auth|noauth|priv))?))?)\s+\S.*$",
        re.IGNORECASE,
    ),
    re.compile(r"^(?P<keep>\s*snmp-server\s+user\s+.*?\bauth\s+\S+)\s+\S.*$", re.IGNORECASE),
    # `key` alone is a common word (key chain, crypto key): only mask "key [0-9] <value>" or a value at
    # the end of a server/tacacs/radius key line.
    re.compile(r"^(?P<keep>\s*(?:\S+\s+)*?key\s+[0-9])\s+\S.*$", re.IGNORECASE),
    re.compile(r"^(?P<keep>\s+key)\s+(?!\d+\s*$)\S.*$", re.IGNORECASE),  # " key RKEY" under radius server
    re.compile(r"^(?P<keep>\s*(?:tacacs|radius|server|ntp|aaa)\S*\s+(?:\S+\s+)*?key)\s+\S.*$", re.IGNORECASE),
    re.compile(
        r"^(?P<keep>\s*(?:\S+\s+)*?(?:password|secret|key-string|key-hash|community|pre-shared-key|"
        r"authentication-key|server-key|md5|psk|passphrase|encrypted|wpa-psk|ascii)(?:\s+[0-9])?)\s+\S.*$",
        re.IGNORECASE,
    ),
]


# `show cts pacs`: the PAC-Opaque blob is the TrustSec PAC itself (a bearer credential for the device's
# environment-data and policy downloads). It is one long hex line, sometimes wrapped onto hex-only lines.
_PAC_OPAQUE = re.compile(r"^(?P<keep>\s*PAC-Opaque\s*:)\s*\S.*$", re.IGNORECASE)
_HEX_ONLY = re.compile(r"^\s*[0-9A-Fa-f]{16,}\s*$")


def redact_config(text: str) -> str:
    """Mask passwords, secrets, keys and SNMP communities in IOS-style configuration text, and the
    PAC-Opaque blob in `show cts pacs` output."""
    out = []
    in_pac = False
    for line in text.splitlines():
        if in_pac and _HEX_ONLY.match(line):
            continue  # a wrapped continuation of the masked PAC-Opaque value
        in_pac = False
        m = _PAC_OPAQUE.match(line)
        if m:
            out.append(f"{m.group('keep')} ********")
            in_pac = True
            continue
        for pat in _SECRET_PATTERNS:
            m = pat.match(line)
            if m:
                line = f"{m.group('keep')} ********"
                break
        out.append(line)
    return "\n".join(out)


LICENCE_FAMILIES = {
    "Routers": "ROUTERS",
    "Switches and Hubs": "SWITCHES_AND_HUBS",
    "Wireless Controller": "WIRELESS_CONTROLLER",
    "Unified AP": "UNIFIED_AP",
}


def licence_filter(dev: dict[str, Any]) -> dict[str, str]:
    """Narrow the licence list to the device's family (the API has no device filter; records are
    matched on the management address afterwards)."""
    fam = LICENCE_FAMILIES.get(str(dev.get("family")))
    return {"family": fam} if fam else {}


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="List network devices")
    async def catc_list_devices(
        ctx: Context,
        hostname: Annotated[
            str | None, Field(description="Hostname filter; '.*' wildcards allowed (e.g. 'edge.*')")
        ] = None,
        ip: Annotated[str | None, Field(description="Management IP; '.*' wildcards allowed")] = None,
        family: Annotated[
            str | None, Field(description="Device family, e.g. 'Switches and Hubs', 'Routers', 'Unified AP'")
        ] = None,
        role: Annotated[
            Literal["ACCESS", "DISTRIBUTION", "CORE", "BORDER ROUTER", "UNKNOWN"] | None,
            Field(description="Device role"),
        ] = None,
        reachability: Annotated[
            Literal["Reachable", "Unreachable", "Ping Reachable"] | None,
            Field(description="Reachability status"),
        ] = None,
        platform: Annotated[str | None, Field(description="Platform id, e.g. 'C9300-24U'")] = None,
        serial: Annotated[str | None, Field(description="Serial number")] = None,
        software_version: Annotated[str | None, Field(description="Software version, e.g. '17.9.4'")] = None,
        site: Annotated[
            str | None,
            Field(
                description="Only devices at this site (id or name hierarchy) and, by default, every site "
                "below it (a building's floors, an area's buildings)"
            ),
        ] = None,
        include_children: Annotated[
            bool,
            Field(description="With site: also devices at its child sites; false = the exact site only"),
        ] = True,
        limit: Annotated[int, Field(ge=1, le=500)] = 50,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """List network devices in the Catalyst Center inventory with hostname, management IP,
        platform, software version, role, reachability and serial. Filters combine (AND). With `site`, a
        building includes the devices on its floors (each row names its assigned site); pass
        include_children=false for that site's own devices only. Use the hostname/IP/id with
        catc_get_device or catc_device_360 for details."""
        app: CatcApp = get_client(ctx)
        params: dict[str, Any] = {
            k: v
            for k, v in {
                "hostname": hostname,
                "managementIpAddress": ip,
                "family": family,
                "role": role,
                "reachabilityStatus": reachability,
                "platformId": platform,
                "serialNumber": serial,
                "softwareVersion": software_version,
            }.items()
            if v
        }
        extra: dict[str, Any] = {}
        if site:
            s = await resolve_site(app, site)
            extra["site"] = s.get("nameHierarchy")
            if s.get("type") != "global":
                if include_children:
                    extra["includes_child_sites"] = True
                    assignments = await site_assignments(app, s)
                else:
                    assigned = await fetch_all(app.pager, app.api, ASSIGNED, {"siteId": s["id"]})
                    assignments = [
                        {"siteNameHierarchy": s.get("nameHierarchy"), **a}
                        for a in assigned.items
                        if isinstance(a, dict) and a.get("deviceId")
                    ]
                where = {str(a["deviceId"]): a.get("siteNameHierarchy") for a in assignments}
                if not where:
                    return list_result(
                        page_of([], limit=limit, offset=offset), fmt=response_format, extra=extra
                    )
                # id= ignores other filters, so filter client-side when both are given.
                devices = [d for d in await devices_by_id(app, sorted(where)) if _matches(d, params)]
                rows = [{**pick(d, DEVICE_FIELDS), "site": where.get(str(d.get("id")))} for d in devices]
                rows.sort(key=lambda r: (str(r.get("site") or ""), str(r.get("hostname") or "")))
                return list_result(
                    page_of(rows, limit=limit, offset=offset), fmt=response_format, extra=extra
                )
        page = await app.pager.fetch_page(
            app.api, "/dna/intent/api/v1/network-device", params, limit=limit, offset=offset
        )
        page.items = [pick(d, DEVICE_FIELDS) for d in page.items if isinstance(d, dict)]
        return list_result(page, fmt=response_format, extra=extra or None)

    @reg.read(title="Get network device")
    async def catc_get_device(ctx: Context, device: DeviceRef) -> ToolResult:
        """Full inventory record for one network device: platform, serial, software, role, uptime,
        reachability and collection status (with failure reason), management IP, MAC, location, and
        the user-defined fields it carries (userDefinedFields: {name: value}; see catc_list_udfs).
        Use catc_device_360 for health, issues, interfaces and compliance in one call."""
        app: CatcApp = get_client(ctx)
        dev = await resolve_device(app, device)
        with contextlib.suppress(UpstreamError):  # releases without the USER_DEFINED_FIELDS view
            dev["userDefinedFields"] = await device_udfs(app, str(dev["id"]))
        return object_result(dev)

    @reg.read(title="List device interfaces")
    async def catc_list_device_interfaces(
        ctx: Context,
        device: DeviceRef,
        status: Annotated[
            Literal["up", "down"] | None, Field(description="Only interfaces in this oper status")
        ] = None,
        name: Annotated[
            str | None, Field(description="Interface name contains, e.g. 'Gi1/0/' or 'Vlan'")
        ] = None,
        limit: Annotated[int, Field(ge=1, le=500)] = 100,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """Interfaces of one device with oper/admin status, description, IPv4 address, VLAN, port mode,
        speed/duplex and MAC. Filter by status or name to find down ports or SVIs."""
        app: CatcApp = get_client(ctx)
        dev = await resolve_device(app, device)
        data = ensure_list(await app.get_response(f"/dna/intent/api/v1/interface/network-device/{dev['id']}"))
        rows = [pick(i, INTERFACE_FIELDS) for i in data if isinstance(i, dict)]
        if status:
            rows = [r for r in rows if str(r.get("status", "")).lower() == status]
        if name:
            rows = [r for r in rows if name.lower() in str(r.get("portName", "")).lower()]
        rows.sort(key=lambda r: str(r.get("portName", "")))
        return list_result(
            page_of(rows, limit=limit, offset=offset),
            fmt=response_format,
            extra={"device": dev.get("hostname")},
        )

    @reg.read(title="Get device running config")
    async def catc_get_device_config(
        ctx: Context,
        device: DeviceRef,
        match: Annotated[
            str | None,
            Field(
                description="Only return top-level config sections whose first line starts with this text, "
                "e.g. 'interface Vlan'"
            ),
        ] = None,
    ) -> ToolResult:
        """The device's running configuration as last collected by Catalyst Center (not live: run
        catc_run_show_commands for that). Passwords, secrets, keys and SNMP communities are masked.
        Use `match` to return only matching top-level sections (e.g. 'router bgp', 'interface Gi1/0/1')."""
        app: CatcApp = get_client(ctx)
        dev = await resolve_device(app, device)
        cfg = await app.get_response(f"/dna/intent/api/v1/network-device/{dev['id']}/config")
        text = redact_config(cfg if isinstance(cfg, str) else str(cfg or ""))
        if match:
            sections: list[str] = []
            current: list[str] = []
            for line in text.splitlines():
                if line and not line[0].isspace():
                    if current:
                        sections.append("\n".join(current))
                    current = [line]
                elif current:
                    current.append(line)
            if current:
                sections.append("\n".join(current))
            want = " ".join(match.lower().split())
            heads = [(" ".join(s.splitlines()[0].lower().split()), s) for s in sections]
            # An exact header wins ('interface Gi1/0/2' shouldn't also return Gi1/0/20-24).
            hits = [s for h, s in heads if h == want] or [s for h, s in heads if h.startswith(want)]
            text = "\n!\n".join(hits) if hits else f"(no config section starts with {match!r})"
        return text_result(
            f"! {dev.get('hostname')} ({dev.get('managementIpAddress')}) running config\n{text}"
        )

    @reg.read(title="List device modules")
    async def catc_list_device_modules(
        ctx: Context,
        device: DeviceRef,
        limit: Annotated[int, Field(ge=1, le=500)] = 100,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """Hardware modules of one device (line cards, supervisors, power supplies, fans, transceivers)
        with part number, serial number and operational state."""
        app: CatcApp = get_client(ctx)
        dev = await resolve_device(app, device)
        page = await app.pager.fetch_page(
            app.api,
            "/dna/intent/api/v1/network-device/module",
            {"deviceId": dev["id"]},
            limit=limit,
            offset=offset,
        )
        fields = [
            "name",
            "partNumber",
            "serialNumber",
            "operationalStateCode",
            "containmentEntity",
            "description",
        ]
        page.items = [pick(m, fields) for m in page.items if isinstance(m, dict)]
        return list_result(page, fmt=response_format, extra={"device": dev.get("hostname")})

    @reg.read(title="Device hardware and licences")
    async def catc_get_device_hardware(ctx: Context, device: DeviceRef) -> ToolResult:
        """Hardware and licensing of one device in one call: stack members (role, state, priority,
        serial, platform, software) and StackWise Virtual links, PoE budget (allocated / consumed /
        remaining watts) and the PoE ports drawing power, module count, and smart-licensing state with
        the licences in use. Use catc_list_device_modules for the full module list."""
        app: CatcApp = get_client(ctx)
        dev = await resolve_device(app, device)
        did = str(dev["id"])
        results: tuple[Any, ...] = await asyncio.gather(
            app.get_response(f"/dna/intent/api/v1/network-device/{did}/stack"),
            app.get_response(f"/dna/intent/api/v1/network-device/{did}/poe"),
            app.get_response(f"/dna/intent/api/v1/network-device/{did}/interface/poe-detail"),
            app.get_response("/dna/intent/api/v1/network-device/module/count", {"deviceId": did}),
            fetch_all(
                app.pager, app.api, "/dna/intent/api/v1/networkDeviceLicenses", licence_filter(dev), cap=5000
            ),
            return_exceptions=True,
        )
        stack, poe, poe_ports, modules, licences = results
        out: dict[str, Any] = {"device": f"{dev.get('hostname')} ({dev.get('managementIpAddress')})"}
        unavailable: dict[str, str] = {}

        def failed(key: str, v: Any) -> bool:
            if isinstance(v, BaseException):
                if not isinstance(v, UpstreamError):
                    raise v
                unavailable[key] = str(v)[:200]
                return True
            return False

        if not failed("stack", stack) and isinstance(stack, dict):
            members = [
                pick(
                    m,
                    [
                        "stackMemberNumber",
                        "role",
                        "state",
                        "switchPriority",
                        "serialNumber",
                        "platformId",
                        "softwareImage",
                        "macAddress",
                    ],
                )
                for m in ensure_list(stack.get("stackSwitchInfo"))
                if isinstance(m, dict)
            ]
            out["stack"] = members or "not a stack"
            if stack.get("svlSwitchInfo"):
                out["stackwise_virtual"] = stack["svlSwitchInfo"]
        if not failed("poe", poe) and isinstance(poe, dict):
            budget = {k: v for k, v in poe.items() if v is not None}
            out["poe"] = budget or "no PoE"
        if not failed("poe_ports", poe_ports):
            ports = [
                pick(
                    p,
                    [
                        "interfaceName",
                        "operStatus",
                        "adminStatus",
                        "allocatedPower",
                        "maxPortPower",
                        "portPowerDrawn",
                        "pdClassSignal",
                        "pdDeviceType",
                    ],
                )
                for p in ensure_list(poe_ports)
                if isinstance(p, dict)
            ]
            if ports:
                out["poe_ports"] = [p for p in ports if str(p.get("operStatus", "")).lower() == "on"][
                    :100
                ] or (f"{len(ports)} PoE ports, none drawing power")
        if not failed("modules", modules):
            out["module_count"] = modules.get("count") if isinstance(modules, dict) else modules
        if not failed("licences", licences):
            # Licence records carry their own ids; match on the management address.
            mine = [
                lic
                for lic in licences.items
                if isinstance(lic, dict) and lic.get("managementAddress") == dev.get("managementIpAddress")
            ]
            if mine:
                lic = mine[0]
                out["licensing"] = pick(
                    lic,
                    [
                        "licenseMode",
                        "registrationStatus",
                        "authorizationStatus",
                        "authCodeStatus",
                        "throughputValue",
                    ],
                )
                out["licensing"]["licenses"] = [
                    pick(x, ["name", "type", "status", "count"]) for x in ensure_list(lic.get("licenses"))
                ]
            else:
                out["licensing"] = "no licence record yet (collected with inventory)"
        if unavailable:
            out["unavailable"] = unavailable
        return object_result(out)


def _matches(dev: dict[str, Any], params: dict[str, Any]) -> bool:
    """Client-side version of the network-device filters (values may use '.*' wildcards)."""
    for key, pattern in params.items():
        value = str(dev.get(key, ""))
        # Only '.*' is a wildcard; everything else matches literally.
        rx = ".*".join(re.escape(part) for part in str(pattern).split(".*"))
        if not re.fullmatch(rx, value, re.IGNORECASE):
            return False
    return True
