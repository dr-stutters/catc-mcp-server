"""Appliance and design reads: system health, network profiles, PnP, SDA fabric, wireless SSIDs."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import asyncio
from collections import Counter
from typing import Annotated, Any

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field
from stutters_mcp_core import (
    ResponseFormat,
    ToolRegistrar,
    UpstreamError,
    get_client,
    list_result,
    object_result,
)
from stutters_mcp_core.http import Page, fetch_all

from catc_mcp.client import CatcApp, safe_id
from catc_mcp.common import ensure_list, gather_sections, pick, resolve_site


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="Appliance health")
    async def catc_get_system_health(
        ctx: Context,
        include_healthy: Annotated[
            bool, Field(description="Also list the healthy services (default: only problems)")
        ] = False,
    ) -> ToolResult:
        """Health of the Catalyst Center appliance itself: service health events (counts by state and
        the ones that are not healthy), last backups and the backup target, system licence
        (registration/evaluation), ISE/AAA server integration status, and release version. Use it when
        tools time out or data looks stale, before upgrades, or to check backups."""
        app: CatcApp = get_client(ctx)
        data, errors = await gather_sections(
            {
                "health": app.api.get("/dna/intent/api/v1/diagnostics/system/health", {"summary": "false"}),
                "backups": app.get_response("/dna/system/api/v1/backups", {"limit": 5}),
                "backup_config": app.get_response("/dna/system/api/v1/backupConfiguration"),
                "license": app.get_response("/dna/system/api/v1/license/status"),
                "aaa_servers": app.get_response("/dna/intent/api/v1/authentication-policy-servers"),
                "release": app.get_response("/dna/intent/api/v1/dnac-release"),
            }
        )
        out: dict[str, Any] = {}
        rel = data.get("release")
        if isinstance(rel, dict):
            out["release"] = pick(
                rel, ["displayVersion", "installedVersion", "systemVersion", "supportedDirectUpdates"]
            )
        health = data.get("health")
        events = [e for e in ensure_list((health or {}).get("healthEvents")) if isinstance(e, dict)]
        if "health" in data:
            states = Counter(str(e.get("state") or e.get("status") or "?").upper() for e in events)
            bad = [e for e in events if str(e.get("state", "")).upper() not in ("HEALTHY", "OK", "")]
            fields = ["state", "severity", "domain", "subDomain", "description", "hostname"]
            out["services"] = {
                "by_state": dict(states),
                "not_healthy": [pick(e, fields) for e in bad[:50]],
            }
            if include_healthy:
                out["services"]["healthy"] = [
                    pick(e, ["subDomain", "description"]) for e in events if e not in bad
                ][:200]
        if "backups" in data:
            out["backups"] = [
                pick(b, ["name", "status", "startDate", "endDate", "scope", "size", "id"])
                for b in ensure_list(data["backups"])
                if isinstance(b, dict)
            ] or "no backups taken"
        cfg = data.get("backup_config")
        if isinstance(cfg, dict):
            out["backup_target"] = (
                pick(cfg, ["type", "mountPath", "dataRetention"]) if cfg.get("type") else "not configured"
            )
        lic = data.get("license")
        if isinstance(lic, dict):
            out["license"] = {
                "registration": (lic.get("registrationStatus") or {}).get("status"),
                "authorization": (lic.get("authorizationStatus") or {}).get("status"),
            }
        if "aaa_servers" in data:
            out["aaa_servers"] = [
                pick(a, ["ipAddress", "isIseEnabled", "state", "protocol", "role", "pxgridEnabled"])
                for a in ensure_list(data["aaa_servers"])
                if isinstance(a, dict)
            ] or "none configured (System > Settings > Authentication and Policy Servers)"
        if errors:
            out["unavailable"] = errors
        return object_result(out)

    @reg.read(title="List network profiles")
    async def catc_list_network_profiles(
        ctx: Context,
        profile_type: Annotated[
            str | None, Field(description="'Switching', 'Wireless' or 'Assurance' (default all)")
        ] = None,
        limit: Annotated[int, Field(ge=1, le=500)] = 50,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """Network profiles (Design > Network Profiles) with their type, the sites they are assigned to
        and the Day-N CLI templates attached to them. Templates attached to a profile are applied when
        devices at those sites are provisioned."""
        app: CatcApp = get_client(ctx)
        params = {"type": profile_type} if profile_type else {}
        page = await fetch_all(
            app.pager, app.api, "/dna/intent/api/v1/networkProfilesForSites", params, cap=2000
        )
        profiles = [p for p in page.items if isinstance(p, dict)]
        window = profiles[offset : offset + limit]

        async def detail(p: dict[str, Any]) -> dict[str, Any]:
            pid = safe_id(str(p.get("id")), "profile id")
            res: tuple[Any, ...] = await asyncio.gather(
                app.get_response(f"/dna/intent/api/v1/networkProfilesForSites/{pid}/siteAssignments"),
                app.get_response(f"/dna/intent/api/v1/networkProfilesForSites/{pid}/templates"),
                return_exceptions=True,
            )
            sites, tpls = res
            row = pick(p, ["name", "type", "id"])
            if not isinstance(sites, BaseException):
                row["sites"] = len(ensure_list(sites))
            if not isinstance(tpls, BaseException):
                row["templates"] = ", ".join(
                    str(t.get("name")) for t in ensure_list(tpls) if isinstance(t, dict)
                )
            return row

        rows = list(await asyncio.gather(*(detail(p) for p in window)))
        return list_result(Page(rows, offset, len(profiles)), fmt=response_format)

    @reg.read(title="List PnP devices")
    async def catc_list_pnp_devices(
        ctx: Context,
        state: Annotated[
            str | None,
            Field(description="Device state: 'Unclaimed', 'Planned', 'Onboarding', 'Provisioned', 'Error'"),
        ] = None,
        serial: Annotated[str | None, Field(description="Serial number")] = None,
        limit: Annotated[int, Field(ge=1, le=500)] = 50,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """Plug and Play (PnP) devices waiting for or going through zero-touch onboarding: serial,
        platform, state, the site and workflow they're claimed to, first/last contact, and any error.
        Unclaimed devices have contacted Catalyst Center and wait to be claimed (Provision > Plug and
        Play)."""
        app: CatcApp = get_client(ctx)
        params: dict[str, Any] = {"limit": limit, "offset": offset}
        if state:
            params["state"] = state
        if serial:
            params["serialNumber"] = serial
        data = await app.api.get("/dna/intent/api/v1/onboarding/pnp-device", params)
        rows = []
        for d in ensure_list(data):
            if not isinstance(d, dict):
                continue
            info = d.get("deviceInfo") or {}
            rows.append(
                {
                    "serial": info.get("serialNumber"),
                    "pid": info.get("pid"),
                    "hostname": info.get("hostname"),
                    "state": info.get("state"),
                    "onboarding": info.get("onbState"),
                    "site": (info.get("location") or {}).get("siteId") or info.get("siteName"),
                    "workflow": info.get("workflowName"),
                    "error": info.get("errorDetails") and str(info.get("errorDetails"))[:200],
                    "lastContact": info.get("lastContact"),
                    "id": d.get("id"),
                }
            )
        rows = [{k: v for k, v in r.items() if v not in (None, "")} for r in rows]
        return list_result(Page(rows, offset, None, more=len(rows) >= limit), fmt=response_format)

    @reg.read(title="SDA fabric")
    async def catc_get_sda_fabric(
        ctx: Context,
        site: Annotated[
            str | None, Field(description="Only the fabric site at this site (id or name hierarchy)")
        ] = None,
    ) -> ToolResult:
        """SD-Access fabric overview in one call: fabric sites (authentication profile, pub/sub), the
        fabric devices at each with their roles (control plane, border, edge) and border settings,
        layer 3 virtual networks, anycast gateways (VN, IP pool, VLAN) and edge port assignments, with the
        ids catc_delete_sda_object takes. Empty when SD-Access isn't deployed."""
        app: CatcApp = get_client(ctx)
        params: dict[str, Any] = {}
        if site:
            params["siteId"] = (await resolve_site(app, site))["id"]
        fabrics = [
            f
            for f in (
                await fetch_all(app.pager, app.api, "/dna/intent/api/v1/sda/fabricSites", params, cap=500)
            ).items
            if isinstance(f, dict)
        ]
        if not fabrics:
            return object_result({"fabric_sites": [], "note": "No SD-Access fabric sites."}, shape=False)
        sites = {
            str(s.get("id")): s.get("nameHierarchy")
            for s in (await fetch_all(app.pager, app.api, "/dna/intent/api/v1/sites", cap=20_000)).items
            if isinstance(s, dict)
        }
        out: list[dict[str, Any]] = []
        for f in fabrics:
            fid = str(f.get("id"))
            sec, errors = await gather_sections(
                {
                    "devices": fetch_all(
                        app.pager,
                        app.api,
                        "/dna/intent/api/v1/sda/fabricDevices",
                        {"fabricId": fid},
                        cap=2000,
                    ),
                    "gateways": fetch_all(
                        app.pager,
                        app.api,
                        "/dna/intent/api/v1/sda/anycastGateways",
                        {"fabricId": fid},
                        cap=2000,
                    ),
                    "ports": fetch_all(
                        app.pager,
                        app.api,
                        "/dna/intent/api/v1/sda/portAssignments",
                        {"fabricId": fid},
                        cap=2000,
                    ),
                }
            )
            entry: dict[str, Any] = {
                "site": sites.get(str(f.get("siteId")), f.get("siteId")),
                "authentication_profile": f.get("authenticationProfileName"),
                "pub_sub": f.get("isPubSubEnabled"),
                "id": fid,
            }
            if "devices" in sec:
                entry["devices"] = [
                    {
                        "networkDeviceId": d.get("networkDeviceId"),
                        "roles": d.get("deviceRoles"),
                        "id": d.get("id"),
                    }
                    for d in sec["devices"].items
                    if isinstance(d, dict)
                ]
            if "gateways" in sec:
                entry["anycast_gateways"] = [
                    pick(g, ["virtualNetworkName", "ipPoolName", "vlanId", "vlanName", "trafficType", "id"])
                    for g in sec["gateways"].items
                    if isinstance(g, dict)
                ]
            if "ports" in sec:
                entry["port_assignments"] = [
                    pick(
                        p,
                        [
                            "networkDeviceId",
                            "interfaceName",
                            "connectedDeviceType",
                            "dataVlanName",
                            "voiceVlanName",
                            "id",
                        ],
                    )
                    for p in sec["ports"].items
                    if isinstance(p, dict)
                ]
            if errors:
                entry["unavailable"] = errors
            out.append(entry)
        try:
            vns = await fetch_all(
                app.pager, app.api, "/dna/intent/api/v1/sda/layer3VirtualNetworks", cap=2000
            )
            l3 = [pick(v, ["virtualNetworkName", "fabricIds"]) for v in vns.items if isinstance(v, dict)]
        except UpstreamError as e:
            l3 = [{"unavailable": str(e)[:200]}]
        # Device ids -> hostnames for readability.
        ids = sorted(
            {d["networkDeviceId"] for f in out for d in f.get("devices", []) if d.get("networkDeviceId")}
        )
        if ids:
            devs = ensure_list(
                await app.get_response("/dna/intent/api/v1/network-device", {"id": ",".join(ids[:100])})
            )
            names = {str(d.get("id")): d.get("hostname") for d in devs if isinstance(d, dict)}
            for f in out:
                for d in f.get("devices", []):
                    d["hostname"] = names.get(str(d.get("networkDeviceId")))
        return object_result({"fabric_sites": out, "layer3_virtual_networks": l3})

    @reg.read(title="List SSIDs")
    async def catc_list_ssids(
        ctx: Context,
        site: Annotated[
            str, Field(description="Site (id or name hierarchy); 'Global' for all SSIDs")
        ] = "Global",
        limit: Annotated[int, Field(ge=1, le=500)] = 50,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """Wireless SSIDs defined at a site (Design > Network Settings > Wireless): name, security
        (auth type), radio bands, whether it's enabled and broadcast, AAA servers and id."""
        app: CatcApp = get_client(ctx)
        s = await resolve_site(app, site)
        page = await app.pager.fetch_page(
            app.api,
            f"/dna/intent/api/v1/sites/{s['id']}/wirelessSettings/ssids",
            {},
            limit=limit,
            offset=offset,
        )
        page.items = [
            pick(
                x,
                [
                    "ssid",
                    "profileName",
                    "authType",
                    "ssidRadioType",
                    "isEnabled",
                    "isBroadcastSSID",
                    "wlanType",
                    "authServers",
                    "id",
                ],
            )
            for x in page.items
            if isinstance(x, dict)
        ]
        return list_result(page, fmt=response_format, extra={"site": s.get("nameHierarchy")})
