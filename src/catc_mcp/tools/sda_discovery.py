"""SD-Access LAN automation and fabric wireless, read-only (roadmap D102: discovery before any writes).

LAN automation builds the fabric underlay itself: from a seed device it discovers factory-fresh switches over
PnP, assigns them IS-IS links and loopbacks from IP pools, and onboards them. Fabric wireless puts a WLC and
its APs in the fabric (VLAN-to-SSID mappings, the switch-side wireless settings, wireless multicast). Both are
read here only: writes wait until a lab can host them (PnP switches behind a seed, a fabric WLC and APs).
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
from typing import Annotated, Any

from fastmcp import Context
from pydantic import Field

from catc_mcp._core import AuthError, ToolRegistrar, get_client
from catc_mcp.client import CatcApp
from catc_mcp.common import ensure_list, gather_sections, seg
from catc_mcp.tools.sda import resolve_fabric, sda_list

LAN = "/dna/intent/api/v1/lan-automation"
PAGE = 10  # lan-automation/status and /log refuse limit > 10
LAN_FIELDS = [
    "id",
    "name",
    "status",
    "action",
    "creationTime",
    "discoveredDeviceSiteNameHierarchy",
    "primaryDeviceManagmentIPAddress",
    "peerDeviceManagmentIPAddress",
    "discoveryLevel",
    "multicastEnabled",
    "hostNamePrefix",
]
DENIED = (
    "Catalyst Center refused the LAN automation API (403): the account's role needs Network Operations.LAN "
    "Automation Read, which exists only once the SD Access package is deployed; re-run the seed step "
    "(docs/least-privilege.md)."
)


async def paged(app: CatcApp, path: str, cap: int = 100) -> list[Any]:
    """The LAN automation reads page 10 at a time (3.2.2 answers 400 to limit > 10), 1-based."""
    out: list[Any] = []
    while len(out) < cap:
        page = ensure_list(await app.get_response(path, {"offset": len(out) + 1, "limit": PAGE}))
        out += page
        if len(page) < PAGE:
            break
    return out[:cap]


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="LAN automation")
    async def catc_get_lan_automation(
        ctx: Context,
        include_log: Annotated[
            bool, Field(description="Also return the latest LAN automation log entries")
        ] = False,
    ) -> dict[str, Any]:
        """LAN automation (underlay automation) on Catalyst Center: active sessions and their limit, each
        session's status (seed devices, discovered devices and their site, IP pools, discovery level,
        multicast, hostname prefix) and optionally the latest log entries. Read-only."""
        app: CatcApp = get_client(ctx)
        try:
            sessions = await app.get_response(f"{LAN}/sessions")
        except AuthError as e:
            raise AuthError(DENIED, status_code=e.status_code) from e
        sec, errors = await gather_sections(
            {
                "status": paged(app, f"{LAN}/status"),
                **({"log": paged(app, f"{LAN}/log", cap=50)} if include_log else {}),
            }
        )
        rows = [r for r in ensure_list(sec.get("status")) if isinstance(r, dict)]
        out: dict[str, Any] = {
            "active_sessions": ensure_list((sessions or {}).get("activeSessionIds"))
            if isinstance(sessions, dict)
            else sessions,
            "max_sessions": (sessions or {}).get("maxSupportedCount") if isinstance(sessions, dict) else None,
            "sessions": [
                {
                    **{k: r[k] for k in LAN_FIELDS if r.get(k) not in (None, "")},
                    "discovered_devices": len(ensure_list(r.get("discoveredDeviceList"))),
                    "ip_pools": [
                        p.get("ipPoolName") for p in ensure_list(r.get("ipPools")) if isinstance(p, dict)
                    ],
                }
                for r in rows
            ],
        }
        if include_log and "log" in sec:
            out["log"] = ensure_list(sec["log"])[:50]
        if not rows:
            out["note"] = "No LAN automation sessions (the underlay is configured by hand or by templates)."
        if errors:
            out["errors"] = errors
        return out

    @reg.read(title="SD-Access fabric wireless")
    async def catc_get_fabric_wireless(
        ctx: Context,
        fabric_site: Annotated[
            str | None, Field(description="Only this fabric site (site path or fabric id)")
        ] = None,
    ) -> dict[str, Any]:
        """SD-Access fabric wireless: the VLAN-to-SSID mappings of each fabric site (fabric-enabled WLANs and
        the SGT they carry), and for one fabric site the switch-side wireless settings (which fabric devices
        carry wireless roles, rolling AP upgrade) and wireless multicast. Read-only."""
        app: CatcApp = get_client(ctx)
        fid: str | None = None
        site_name = None
        if fabric_site:
            fabric, site = await resolve_fabric(app, fabric_site)
            fid, site_name = str(fabric["id"]), site.get("nameHierarchy")
        rows = await sda_list(app, "fabrics/vlanToSsids")
        out: dict[str, Any] = {
            "vlan_to_ssids": [r for r in rows if fid is None or str(r.get("fabricId")) == fid],
        }
        if fid:
            sec, errors = await gather_sections(
                {
                    "switch_wireless": app.get_response(
                        f"/dna/intent/api/v1/sda/fabrics/{seg(fid)}/switchWirelessSetting"
                    ),
                    "wireless_multicast": app.get_response(
                        f"/dna/intent/api/v1/sda/fabrics/{seg(fid)}/wirelessMulticast"
                    ),
                }
            )
            out = {"fabric_site": site_name, **out, **sec}
            if errors:
                out["errors"] = errors
        if not out["vlan_to_ssids"]:
            out["note"] = "No fabric-enabled wireless (no VLAN-to-SSID mappings)."
        return out
