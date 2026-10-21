"""SD-Access Security Service Insertion readiness (roadmap D107), read-only.

Security Service Insertion (SSI) sends a virtual network's traffic through a firewall at the fabric border
(the Secure Firewall that fmc-mcp-server manages). Before configuring it, Catalyst Center rates each fabric
site, each of its virtual networks and each fabric device as ready or not, with a message saying why. The
reads need the Security.SSI permission (Read) on the account's role.
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
from typing import Annotated, Any

from fastmcp import Context
from pydantic import Field

from catc_mcp._core import AuthError, NotFound, ToolRegistrar, get_client
from catc_mcp.client import CatcApp
from catc_mcp.common import ensure_list, seg
from catc_mcp.tools.sda import resolve_fabric

BASE = "/dna/intent/api/v1/securityServiceInsertion/fabricSitesReadiness"
DENIED = (
    "Catalyst Center refused the Security Service Insertion API (403): the account's role needs Security.SSI "
    "Read (docs/least-privilege.md)."
)


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="Security Service Insertion readiness")
    async def catc_get_ssi_readiness(
        ctx: Context,
        fabric_site: Annotated[
            str | None,
            Field(description="One fabric site: its virtual networks' readiness (site path or fabric id)"),
        ] = None,
        virtual_network: Annotated[
            str | None, Field(description="With fabric_site: one VN's fabric devices and their readiness")
        ] = None,
    ) -> dict[str, Any]:
        """Security Service Insertion (SSI) readiness of the SD-Access fabric. Per fabric site: its readiness,
        message, pub/sub and border/edge/map-server counts; with fabric_site, each virtual network's
        readiness, anycast gateways, extranet role and ready/total devices; with a virtual network too, each
        fabric device (role, reachability, licence) and why it is or isn't ready. Read-only: the first step
        before steering a VN through a firewall at the border."""
        app: CatcApp = get_client(ctx)
        try:
            if not fabric_site:
                sites = ensure_list(await app.get_response(BASE))
                return {
                    "fabric_sites": sites,
                    **({"note": "No fabric sites rated (no SD-Access fabric yet)."} if not sites else {}),
                }
            fabric, site = await resolve_fabric(app, fabric_site)
            sid = str(fabric["id"])  # both paths take the SDA fabric site id, not the site id
            vns = ensure_list(await app.get_response(f"{BASE}/{seg(sid)}"))
            out: dict[str, Any] = {"fabric_site": site.get("nameHierarchy"), "virtual_networks": vns}
            if virtual_network:
                vn = next(
                    (
                        v
                        for v in vns
                        if isinstance(v, dict) and v.get("virtualNetworkName") == virtual_network
                    ),
                    None,
                )
                if vn is None:
                    raise NotFound(f"{virtual_network} is not rated at {site.get('nameHierarchy')}.")
                vid = str(vn.get("id"))  # the row's id (layer3VirtualNetworkId is a different, integer id)
                out["devices"] = ensure_list(
                    await app.get_response(f"{BASE}/{seg(sid)}/virtualNetworks/{seg(vid)}")
                )
            return out
        except AuthError as e:
            raise AuthError(DENIED, status_code=e.status_code) from e
