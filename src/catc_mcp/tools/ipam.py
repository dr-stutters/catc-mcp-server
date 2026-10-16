"""IP address pools (Design > Network Settings > IP Address Pools): global pools and the subpools
reserved from them for sites (used by LAN automation, SDA, and wireless/wired provisioning)."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import ipaddress
from typing import Annotated, Any, Literal

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field

from catc_mcp._core import (
    Confirm,
    InvalidRequest,
    NotFound,
    Plan,
    ResponseFormat,
    ToolRegistrar,
    get_client,
    list_result,
    preview_or_apply,
)
from catc_mcp._core.http import fetch_all, page_of
from catc_mcp.client import CatcApp
from catc_mcp.common import is_uuid, resolve_site

GLOBAL = "/dna/intent/api/v1/ipam/globalIpAddressPools"
RESERVED = "/dna/intent/api/v1/ipam/siteIpAddressPools"


async def _all(app: CatcApp, path: str) -> list[dict[str, Any]]:
    page = await fetch_all(app.pager, app.api, path, cap=10_000)
    return [p for p in page.items if isinstance(p, dict)]


def _row(p: dict[str, Any], scope: str) -> dict[str, Any]:
    space = p.get("addressSpace") or p.get("ipV4AddressSpace") or p.get("ipV6AddressSpace") or {}
    total = space.get("totalAddresses")
    used = space.get("assignedAddresses")
    row: dict[str, Any] = {
        "name": p.get("name"),
        "scope": scope,
        "site": p.get("siteName"),
        "type": p.get("poolType"),
        "subnet": f"{space.get('subnet')}/{space.get('prefixLength')}" if space.get("subnet") else None,
        "gateway": space.get("gatewayIpAddress"),
        "dhcp": ", ".join(space.get("dhcpServers") or []),
        "dns": ", ".join(space.get("dnsServers") or []),
        "used": f"{used}/{total}" if total else None,
        "id": p.get("id"),
    }
    if p.get("ipV6AddressSpace") and p.get("ipV4AddressSpace"):
        v6 = p["ipV6AddressSpace"]
        row["ipv6_subnet"] = f"{v6.get('subnet')}/{v6.get('prefixLength')}"
    return {k: v for k, v in row.items() if v not in (None, "")}


async def resolve_pool(app: CatcApp, ref: str, *, reserved: bool) -> dict[str, Any]:
    pools = await _all(app, RESERVED if reserved else GLOBAL)
    ref = ref.strip()
    found = [p for p in pools if p.get("id") == ref] if is_uuid(ref) else []
    found = found or [p for p in pools if str(p.get("name", "")).lower() == ref.lower()]
    what = "reserved (site) pool" if reserved else "global pool"
    if len(found) == 1:
        return found[0]
    if len(found) > 1:
        sites = ", ".join(str(p.get("siteName")) for p in found)
        raise InvalidRequest(f"{len(found)} {what}s are named {ref!r} ({sites}); use the id.")
    raise NotFound(f"No {what} {ref!r}. Use catc_list_ip_pools.")


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="List IP pools")
    async def catc_list_ip_pools(
        ctx: Context,
        scope: Annotated[
            Literal["all", "global", "reserved"],
            Field(description="Global pools, site reservations (subpools), or both"),
        ] = "all",
        site: Annotated[
            str | None, Field(description="Only reservations of this site (id or name hierarchy)")
        ] = None,
        name: Annotated[str | None, Field(description="Pool name contains (case-insensitive)")] = None,
        limit: Annotated[int, Field(ge=1, le=500)] = 100,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """IP address pools: global pools and the subpools reserved from them for sites, with subnet,
        gateway, DHCP/DNS servers, type (Generic/LAN/Management/Service/WAN) and usage (assigned/total
        addresses). Use it before reserving a pool (catc_create_ip_pool) to find free space."""
        app: CatcApp = get_client(ctx)
        rows: list[dict[str, Any]] = []
        if scope in ("all", "global") and not site:
            rows += [_row(p, "global") for p in await _all(app, GLOBAL)]
        if scope in ("all", "reserved"):
            reserved = await _all(app, RESERVED)
            if site:
                sid = (await resolve_site(app, site))["id"]
                reserved = [p for p in reserved if p.get("siteId") == sid]
            rows += [_row(p, "reserved") for p in reserved]
        if name:
            rows = [r for r in rows if name.lower() in str(r.get("name", "")).lower()]
        return list_result(page_of(rows, limit=limit, offset=offset), fmt=response_format)

    @reg.write(title="Create IP pool")
    async def catc_create_ip_pool(
        ctx: Context,
        name: Annotated[str, Field(min_length=1, max_length=100, description="Pool name")],
        subnet: Annotated[str, Field(description="IPv4 subnet in CIDR form, e.g. '10.20.0.0/16'")],
        site: Annotated[
            str | None,
            Field(
                description="Reserve the subnet for this site (needs global_pool); "
                "omit to create a global pool"
            ),
        ] = None,
        global_pool: Annotated[
            str | None, Field(description="With site: the global pool (name or id) the subnet comes from")
        ] = None,
        pool_type: Annotated[
            Literal["Generic", "LAN", "Management", "Service", "WAN", "Tunnel"],
            Field(
                description="Global pools: Generic or Tunnel; site reservations: Generic, LAN, Management, "
                "Service or WAN"
            ),
        ] = "Generic",
        gateway: Annotated[str | None, Field(description="Gateway IP (default: first host)")] = None,
        dhcp_servers: Annotated[list[str] | None, Field(description="DHCP server IPs")] = None,
        dns_servers: Annotated[list[str] | None, Field(description="DNS server IPs")] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Create a global IP pool, or reserve a subpool of one for a site (pass site + global_pool).
        Preview-first: checks the subnet is valid, inside the global pool and not overlapping existing
        pools or reservations. Returns the new pool id."""
        app: CatcApp = get_client(ctx)
        try:
            net = ipaddress.ip_network(subnet.strip(), strict=True)
        except ValueError as e:
            raise InvalidRequest(f"subnet {subnet!r}: {e}") from e
        if net.version != 4:
            raise InvalidRequest("Only IPv4 pools are supported here; use catc_api_call for IPv6.")
        try:
            gw = (
                str(ipaddress.ip_address(gateway.strip()))
                if gateway
                else str(next(net.hosts(), net.network_address))
            )
            dhcp = [str(ipaddress.ip_address(x.strip())) for x in dhcp_servers or []]
            dns = [str(ipaddress.ip_address(x.strip())) for x in dns_servers or []]
        except ValueError as e:
            raise InvalidRequest(f"Not an IP address: {e}") from e
        if ipaddress.ip_address(gw) not in net:
            raise InvalidRequest(f"Gateway {gw} is outside {net}.")
        space: dict[str, Any] = {
            "subnet": str(net.network_address),
            "prefixLength": net.prefixlen,
            "gatewayIpAddress": gw,
            "dhcpServers": dhcp,
            "dnsServers": dns,
        }
        blockers: list[str] = []
        globals_ = await _all(app, GLOBAL)
        reserved = await _all(app, RESERVED)
        details: dict[str, Any] = {"name": name, "subnet": str(net), "gateway": gw, "type": pool_type}
        if site:
            if not global_pool:
                raise InvalidRequest(
                    "A site reservation needs global_pool (catc_list_ip_pools scope=global)."
                )
            if pool_type == "Tunnel":
                blockers.append("Site reservations can't be of type Tunnel.")
            s = await resolve_site(app, site)
            gp = await resolve_pool(app, global_pool, reserved=False)
            gspace = gp.get("addressSpace") or {}
            if not gspace.get("subnet"):
                raise InvalidRequest(f"Global pool {gp.get('name')} has no IPv4 address space.")
            gnet = ipaddress.ip_network(f"{gspace.get('subnet')}/{gspace.get('prefixLength')}", strict=False)
            if not net.subnet_of(gnet):  # type: ignore[arg-type]
                blockers.append(f"{net} is not inside global pool {gp.get('name')} ({gnet}).")
            clash = [
                p
                for p in reserved
                if (p.get("ipV4AddressSpace") or {}).get("subnet")
                and net.overlaps(
                    ipaddress.ip_network(
                        f"{p['ipV4AddressSpace']['subnet']}/{p['ipV4AddressSpace']['prefixLength']}",
                        strict=False,
                    )
                )
            ]
            if clash:
                blockers.append(
                    "Overlaps existing reservation(s): "
                    + ", ".join(f"{p.get('name')} at {p.get('siteName')}" for p in clash)
                )
            if any(
                p.get("siteId") == s["id"] and str(p.get("name")).lower() == name.lower() for p in reserved
            ):
                blockers.append(f"{s.get('nameHierarchy')} already has a reservation named {name!r}.")
            space["globalPoolId"] = gp["id"]
            body: dict[str, Any] = {
                "name": name,
                "poolType": pool_type,
                "siteId": s["id"],
                "ipV4AddressSpace": space,
            }
            path = RESERVED
            details.update({"site": s.get("nameHierarchy"), "global_pool": gp.get("name")})
            summary = f"Reserve {net} as {name} for {s.get('nameHierarchy')}"
        else:
            if pool_type not in ("Generic", "Tunnel"):
                blockers.append(
                    "Global pools are Generic or Tunnel; LAN/Management/Service/WAN are reservations."
                )
            for p in globals_:
                sp = p.get("addressSpace") or {}
                if sp.get("subnet") and net.overlaps(
                    ipaddress.ip_network(f"{sp['subnet']}/{sp['prefixLength']}", strict=False)
                ):
                    blockers.append(
                        f"Overlaps global pool {p.get('name')} ({sp['subnet']}/{sp['prefixLength']})."
                    )
            if any(str(p.get("name")).lower() == name.lower() for p in globals_):
                blockers.append(f"A global pool named {name!r} already exists.")
            body = {"name": name, "poolType": pool_type, "addressSpace": space}
            path = GLOBAL
            summary = f"Create global pool {name} ({net})"
        plan = Plan(summary, details={**details, "method": "POST", "path": path}, blockers=blockers)

        async def apply() -> Any:
            job = await app.run_job("POST", path, body, ctx=ctx, what="create pool")
            # The task reports the new pool's id in `progress`.
            return {"pool_id": job.get("data") or job.get("progress"), "name": name, "subnet": str(net)}

        return await preview_or_apply(
            ctx,
            tool="catc_create_ip_pool",
            args={
                "name": name,
                "subnet": subnet,
                "site": site,
                "global_pool": global_pool,
                "pool_type": pool_type,
                "gateway": gateway,
                "dhcp_servers": dhcp_servers,
                "dns_servers": dns_servers,
            },
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.write(title="Delete IP pool", destructive=True)
    async def catc_delete_ip_pool(
        ctx: Context,
        pool: Annotated[str, Field(description="Pool name or id (catc_list_ip_pools)")],
        reserved: Annotated[
            bool, Field(description="true: release a site reservation; false: delete a global pool")
        ] = True,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Release a site's reserved subpool, or delete a global pool (refused while it still has
        reservations). Preview-first. Catalyst Center refuses pools in use by SDA, LAN automation or
        provisioned devices."""
        app: CatcApp = get_client(ctx)
        p = await resolve_pool(app, pool, reserved=reserved)
        blockers: list[str] = []
        if not reserved:
            subs = [
                r
                for r in await _all(app, RESERVED)
                if (r.get("ipV4AddressSpace") or {}).get("globalPoolId") == p["id"]
            ]
            if subs:
                blockers.append(
                    "The global pool still has reservations: "
                    + ", ".join(f"{r.get('name')} ({r.get('siteName')})" for r in subs)
                    + ". Release them first."
                )
        path = f"{RESERVED if reserved else GLOBAL}/{p['id']}"
        plan = Plan(
            f"{'Release reservation' if reserved else 'Delete global pool'} {p.get('name')}",
            details={**_row(p, "reserved" if reserved else "global"), "method": "DELETE", "path": path},
            fingerprint=p,
            blockers=blockers,
        )

        async def apply() -> Any:
            return await app.run_job("DELETE", path, ctx=ctx, what="delete pool")

        return await preview_or_apply(
            ctx,
            tool="catc_delete_ip_pool",
            args={"pool": pool, "reserved": reserved},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )
