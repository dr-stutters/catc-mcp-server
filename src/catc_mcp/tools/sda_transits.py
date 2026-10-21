"""SD-Access transits and layer 3 handoffs (roadmap D93): how a fabric reaches the rest of the network.

A transit network is the domain a border hands traffic to: an IP transit (VRF-lite eBGP to a fusion router or
WAN, one VLAN/SVI per virtual network) or an SD-Access transit (LISP pub/sub or BGP between fabric sites, with
its own transit control plane nodes). Defining a transit changes no device; a border's layer 3 handoff onto it
pushes the per-VN SVIs and BGP to the border. Without an IP handoff a custom VN has no route out of the fabric
(no DHCP from a server outside it, no shared services). Teardown: catc_delete_l3_handoff, then
catc_delete_transit_network (or catc_delete_fabric_site / catc_delete_fabric_device with cascade=true).
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import ipaddress
from typing import Annotated, Any, Literal

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import BaseModel, Field

from catc_mcp._core import (
    Confirm,
    InvalidRequest,
    NotFound,
    Plan,
    ResponseFormat,
    ToolRegistrar,
    UpstreamError,
    get_client,
    list_result,
    preview_or_apply,
)
from catc_mcp._core.http import Page
from catc_mcp.client import CatcApp, safe_id
from catc_mcp.common import ensure_list, resolve_device, resolve_site
from catc_mcp.safety import device_limit_blockers
from catc_mcp.tools.ops_writes import brief
from catc_mcp.tools.sda import SDA, fabric_devices, sda_job, sda_list

TYPES = {
    "ip": "IP_BASED_TRANSIT",
    "sda_pubsub": "SDA_LISP_PUB_SUB_TRANSIT",
    "sda_bgp": "SDA_LISP_BGP_TRANSIT",
}
IP_HANDOFFS = "fabricDevices/layer3Handoffs/ipTransits"
SDA_HANDOFFS = "fabricDevices/layer3Handoffs/sdaTransits"


class VnHandoff(BaseModel):
    """One virtual network handed off over an IP transit: its SVI VLAN and the point-to-point addresses."""

    virtual_network: str = Field(description="Layer 3 VN at the border's fabric site")
    vlan_id: int = Field(ge=2, le=4094, description="VLAN of the SVI that peers with the external router")
    local_ip: str | None = Field(None, description="Border side, CIDR (e.g. 10.255.30.1/30)")
    remote_ip: str | None = Field(None, description="Peer side, CIDR (e.g. 10.255.30.2/30)")
    local_ipv6: str | None = Field(None, description="Border side IPv6, CIDR")
    remote_ipv6: str | None = Field(None, description="Peer side IPv6, CIDR")


def transit_row(t: dict[str, Any]) -> dict[str, Any]:
    ip = t.get("ipTransitSettings") or {}
    sda = t.get("sdaTransitSettings") or {}
    row = {"name": t.get("name"), "type": t.get("type"), "id": t.get("id")}
    if ip:
        row["asn"] = ip.get("autonomousSystemNumber")
        row["routing_protocol"] = ip.get("routingProtocolName")
    if sda:
        row["control_plane_devices"] = ensure_list(sda.get("controlPlaneNetworkDeviceIds"))
        row["multicast_over_transit"] = sda.get("isMulticastOverTransitEnabled")
    if t.get("siteId"):
        row["site_id"] = t["siteId"]
    return row


async def resolve_transit(app: CatcApp, ref: str) -> dict[str, Any]:
    ref = ref.strip()
    for t in await sda_list(app, "transitNetworks"):
        if ref in (t.get("id"), t.get("name")):
            return t
    raise NotFound(f"No transit network {ref!r} (catc_list_transit_networks).")


async def border_of(app: CatcApp, device: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """(device, its fabric device record) for a device with the BORDER_NODE role."""
    dev = await resolve_device(app, device)
    fdev = next(
        (
            d
            for d in await fabric_devices(app, str(dev["id"]))
            if "BORDER_NODE" in (d.get("deviceRoles") or [])
        ),
        None,
    )
    if fdev is None:
        raise InvalidRequest(
            f"{brief([dev])[0]} is not a border node of any fabric site (catc_add_fabric_device)."
        )
    return dev, fdev


def _cidr(value: str | None, field: str, blockers: list[str]) -> None:
    if value is None:
        return
    try:
        ipaddress.ip_interface(value)
        if "/" not in value:
            raise ValueError("no prefix length")
    except ValueError as e:
        blockers.append(f"{field} {value!r} is not an address in CIDR notation ({e}).")


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="List transit networks")
    async def catc_list_transit_networks(
        ctx: Context,
        name: Annotated[str | None, Field(description="Exact transit name")] = None,
        transit_type: Annotated[
            Literal["ip", "sda_pubsub", "sda_bgp"] | None, Field(description="Only this transit type")
        ] = None,
        limit: Annotated[int, Field(ge=1, le=500)] = 100,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """SD-Access transit networks, with ids. IP transits show their autonomous system and routing
        protocol; SD-Access transits (LISP pub/sub or BGP) their transit control plane devices and multicast
        setting. Borders hand off onto them with catc_add_l3_handoff."""
        app: CatcApp = get_client(ctx)
        params: dict[str, Any] = {}
        if name:
            params["name"] = name
        if transit_type:
            params["type"] = TYPES[transit_type]
        rows = [transit_row(t) for t in await sda_list(app, "transitNetworks", params)]
        return list_result(Page(rows[offset : offset + limit], offset, len(rows)), fmt=response_format)

    @reg.write(title="Create transit network")
    async def catc_create_transit_network(
        ctx: Context,
        name: Annotated[
            str, Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$", description="Transit name")
        ],
        transit_type: Annotated[
            Literal["ip", "sda_pubsub", "sda_bgp"],
            Field(
                description="ip: VRF-lite BGP handoff; sda_pubsub / sda_bgp: SD-Access transit between sites"
            ),
        ],
        asn: Annotated[
            str | None, Field(pattern=r"^\d{1,10}$", description="ip: the transit's (external) AS number")
        ] = None,
        control_plane_devices: Annotated[
            list[str] | None,
            Field(
                max_length=2,
                description="sda_*: transit control plane devices (hostname, IP, serial; up to 2)",
            ),
        ] = None,
        site: Annotated[
            str | None, Field(description="Anchor site: only fabric sites under it may use it")
        ] = None,
        multicast_over_transit: Annotated[
            bool | None, Field(description="sda_pubsub: native multicast over the SD-Access transit")
        ] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Define an SD-Access transit network. An IP transit takes an autonomous system number (the borders
        then peer eBGP per VN with the external router); an SD-Access transit (LISP pub/sub or BGP) takes up
        to two transit control plane devices. Defining it changes no device; borders use it through
        catc_add_l3_handoff. Preview-first."""
        app: CatcApp = get_client(ctx)
        blockers: list[str] = []
        existing = [
            t for t in await sda_list(app, "transitNetworks", {"name": name}) if t.get("name") == name
        ]
        if existing:
            blockers.append(f"Transit network {name} exists ({existing[0].get('type')}).")
        body: dict[str, Any] = {"name": name, "type": TYPES[transit_type]}
        cps: list[dict[str, Any]] = []
        if transit_type == "ip":
            if not asn:
                blockers.append("An IP transit needs asn.")
            if control_plane_devices or multicast_over_transit is not None:
                blockers.append(
                    "control_plane_devices and multicast_over_transit are for SD-Access transits."
                )
            body["ipTransitSettings"] = {"routingProtocolName": "BGP", "autonomousSystemNumber": asn}
        else:
            if asn:
                blockers.append("asn is for IP transits.")
            if not control_plane_devices:
                blockers.append("An SD-Access transit needs one or two control_plane_devices.")
            cps = [await resolve_device(app, d) for d in control_plane_devices or []]
            settings: dict[str, Any] = {"controlPlaneNetworkDeviceIds": [str(d["id"]) for d in cps]}
            if multicast_over_transit is not None:
                settings["isMulticastOverTransitEnabled"] = multicast_over_transit
            body["sdaTransitSettings"] = settings
        anchor = None
        if site:
            anchor = await resolve_site(app, site)
            body["siteId"] = anchor["id"]
        plan = Plan(
            f"Create {TYPES[transit_type]} transit network {name}"
            + (f" (AS {asn})" if asn else "")
            + (f" with control plane {', '.join(brief(cps))}" if cps else ""),
            details={"method": "POST", "path": f"{SDA}/transitNetworks", "body": [body]},
            side_effects=["No device changes until a border hands off onto it (catc_add_l3_handoff)."],
            fingerprint={"existing": existing, "anchor": anchor and anchor["id"]},
            blockers=blockers,
        )

        async def apply() -> Any:
            job = await sda_job(app, "POST", f"{SDA}/transitNetworks", [body], ctx, "create transit network")
            made = [
                t for t in await sda_list(app, "transitNetworks", {"name": name}) if t.get("name") == name
            ]
            return {**job, "transit": transit_row(made[0]) if made else None}

        return await preview_or_apply(
            ctx,
            tool="catc_create_transit_network",
            args={
                "name": name,
                "transit_type": transit_type,
                "asn": asn,
                "control_plane_devices": control_plane_devices,
                "site": site,
                "multicast_over_transit": multicast_over_transit,
            },
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.dangerous(title="Add layer 3 handoff", task=True)
    async def catc_add_l3_handoff(
        ctx: Context,
        border: Annotated[str, Field(description="Border node (hostname, IP, serial or id)")],
        transit: Annotated[str, Field(description="Transit network name or id")],
        interface: Annotated[
            str | None, Field(description="IP transit: the border's interface to the external router")
        ] = None,
        virtual_networks: Annotated[
            list[VnHandoff] | None,
            Field(
                max_length=20, description="IP transit: the VNs to hand off, each with its VLAN and addresses"
            ),
        ] = None,
        external_pool: Annotated[
            str | None,
            Field(
                description="IP transit: the IP pool Catalyst Center allocates the /30s from (instead of "
                "addresses)"
            ),
        ] = None,
        tcp_mss_adjustment: Annotated[
            int | None,
            Field(ge=500, le=1440, description="IP transit: TCP MSS adjustment on the handoff SVIs"),
        ] = None,
        connected_to_internet: Annotated[
            bool | None,
            Field(description="SD-Access transit: this site gives internet access to other sites"),
        ] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Hand a border off onto a transit network. IP transit: per virtual network, an SVI on the given VLAN
        over `interface` with point-to-point addresses (or allocated from `external_pool`) and eBGP to the
        external router; the router needs the matching VRF, subinterface and BGP neighbour. SD-Access transit:
        the border registers with the transit control plane. Catalyst Center pushes the VRF/SVI/BGP (or LISP)
        configuration to the border. Preview-first: the per-VN VLANs and addresses."""
        app: CatcApp = get_client(ctx)
        dev, fdev = await border_of(app, border)
        t = await resolve_transit(app, transit)
        fid = str(fdev["fabricId"])
        blockers = device_limit_blockers(app, 1)
        items: list[dict[str, Any]] = []
        if t.get("type") == TYPES["ip"]:
            path = IP_HANDOFFS
            if not interface or not virtual_networks:
                blockers.append("An IP transit handoff needs interface and virtual_networks.")
            if connected_to_internet is not None:
                blockers.append("connected_to_internet is for SD-Access transits.")
            at_site = {
                str(v.get("virtualNetworkName"))
                for v in await sda_list(app, "layer3VirtualNetworks")
                if fid in map(str, ensure_list(v.get("fabricIds")))
            }
            have = await sda_list(app, IP_HANDOFFS, {"fabricId": fid, "networkDeviceId": dev["id"]})
            used_vlans = {h.get("vlanId") for h in have}
            seen: set[int] = set()
            for vn in virtual_networks or []:
                if vn.virtual_network not in at_site:
                    blockers.append(f"{vn.virtual_network} is not a layer 3 VN of the border's fabric site.")
                if vn.vlan_id in used_vlans or vn.vlan_id in seen:
                    blockers.append(f"VLAN {vn.vlan_id} is already used by a handoff on this border.")
                seen.add(vn.vlan_id)
                if any(
                    h.get("virtualNetworkName") == vn.virtual_network and h.get("transitNetworkId") == t["id"]
                    for h in have
                ):
                    blockers.append(f"{vn.virtual_network} is already handed off onto {t.get('name')} here.")
                if (
                    not external_pool
                    and not (vn.local_ip and vn.remote_ip)
                    and not (vn.local_ipv6 and vn.remote_ipv6)
                ):
                    blockers.append(f"{vn.virtual_network}: give local_ip and remote_ip, or external_pool.")
                for field in ("local_ip", "remote_ip", "local_ipv6", "remote_ipv6"):
                    _cidr(getattr(vn, field), f"{vn.virtual_network} {field}", blockers)
                item = {
                    "networkDeviceId": dev["id"],
                    "fabricId": fid,
                    "transitNetworkId": t["id"],
                    "interfaceName": interface,
                    "virtualNetworkName": vn.virtual_network,
                    "vlanId": vn.vlan_id,
                    "externalConnectivityIpPoolName": external_pool,
                    "localIpAddress": vn.local_ip,
                    "remoteIpAddress": vn.remote_ip,
                    "localIpv6Address": vn.local_ipv6,
                    "remoteIpv6Address": vn.remote_ipv6,
                    "tcpMssAdjustment": tcp_mss_adjustment,
                }
                items.append({k: v for k, v in item.items() if v is not None})
        else:
            path = SDA_HANDOFFS
            if interface or virtual_networks or external_pool:
                blockers.append("interface, virtual_networks and external_pool are for IP transit handoffs.")
            have = await sda_list(app, SDA_HANDOFFS, {"fabricId": fid, "networkDeviceId": dev["id"]})
            if any(h.get("transitNetworkId") == t["id"] for h in have):
                blockers.append(f"{brief([dev])[0]} already hands off onto {t.get('name')}.")
            item = {"networkDeviceId": dev["id"], "fabricId": fid, "transitNetworkId": t["id"]}
            if connected_to_internet is not None:
                item["connectedToInternet"] = connected_to_internet
            items.append(item)
        plan = Plan(
            f"Hand {brief([dev])[0]} off onto {t.get('type')} {t.get('name')}"
            + (
                f" for {', '.join(i['virtualNetworkName'] for i in items if 'virtualNetworkName' in i)}"
                if path == IP_HANDOFFS
                else ""
            ),
            details={"method": "POST", "path": f"{SDA}/{path}", "body": items},
            side_effects=[
                "Catalyst Center pushes the handoff (VRF, SVI per VN and eBGP, or LISP to the transit) "
                "to the border; the external router needs the matching configuration."
            ],
            fingerprint={"fdev": fdev, "transit": t, "have": have},
            blockers=blockers,
            blast_radius=1,
        )

        async def apply() -> Any:
            job = await sda_job(app, "POST", f"{SDA}/{path}", items, ctx, "add layer 3 handoff")
            now = await sda_list(app, path, {"fabricId": fid, "networkDeviceId": dev["id"]})
            return {**job, "handoffs": [h for h in now if h.get("transitNetworkId") == t["id"]]}

        return await preview_or_apply(
            ctx,
            tool="catc_add_l3_handoff",
            args={
                "border": border,
                "transit": transit,
                "interface": interface,
                "virtual_networks": [v.model_dump() for v in virtual_networks] if virtual_networks else None,
                "external_pool": external_pool,
                "tcp_mss_adjustment": tcp_mss_adjustment,
                "connected_to_internet": connected_to_internet,
            },
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.dangerous(title="Delete layer 3 handoff", task=True)
    async def catc_delete_l3_handoff(
        ctx: Context,
        border: Annotated[str, Field(description="Border node (hostname, IP, serial or id)")],
        transit: Annotated[str, Field(description="Transit network name or id")],
        virtual_networks: Annotated[
            list[str] | None,
            Field(description="IP transit: only these VNs (default: all of them on this transit)"),
        ] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Remove a border's layer 3 handoff onto a transit. The per-VN SVIs and eBGP (IP transit) or the
        transit registration (SD-Access transit) go from the border, and the VNs lose that way out.
        Preview-first: lists the handoffs removed."""
        app: CatcApp = get_client(ctx)
        dev, fdev = await border_of(app, border)
        t = await resolve_transit(app, transit)
        fid = str(fdev["fabricId"])
        path = IP_HANDOFFS if t.get("type") == TYPES["ip"] else SDA_HANDOFFS
        have = [
            h
            for h in await sda_list(app, path, {"fabricId": fid, "networkDeviceId": dev["id"]})
            if h.get("transitNetworkId") == t["id"]
        ]
        if virtual_networks:
            if path != IP_HANDOFFS:
                raise InvalidRequest("virtual_networks applies to IP transit handoffs.")
            missing = sorted(set(virtual_networks) - {str(h.get("virtualNetworkName")) for h in have})
            if missing:
                raise NotFound(
                    f"No handoff onto {t.get('name')} for {', '.join(missing)} on {brief([dev])[0]}."
                )
            have = [h for h in have if h.get("virtualNetworkName") in virtual_networks]
        blockers = device_limit_blockers(app, 1)
        if not have:
            blockers.append(f"{brief([dev])[0]} has no handoff onto {t.get('name')}.")
        plan = Plan(
            f"Remove {len(have)} layer 3 handoff(s) of {brief([dev])[0]} onto {t.get('name')}",
            details={"handoffs": have},
            side_effects=["The VNs lose this way out of the fabric; their BGP sessions to the peer drop."],
            fingerprint={"have": have},
            blockers=blockers,
            blast_radius=1,
        )

        async def apply() -> Any:
            done: list[str] = []
            for h in have:
                label = str(h.get("virtualNetworkName") or t.get("name"))
                try:
                    await sda_job(
                        app,
                        "DELETE",
                        f"{SDA}/{path}/{safe_id(str(h['id']), 'handoff id')}",
                        None,
                        ctx,
                        "delete handoff",
                    )
                except UpstreamError as e:
                    raise UpstreamError(f"Stopped at {label} (removed: {done or 'none'}): {e}") from e
                done.append(label)
            return {"removed": done}

        return await preview_or_apply(
            ctx,
            tool="catc_delete_l3_handoff",
            args={"border": border, "transit": transit, "virtual_networks": virtual_networks},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.dangerous(title="Delete transit network")
    async def catc_delete_transit_network(
        ctx: Context,
        transit: Annotated[str, Field(description="Transit network name or id")],
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Delete a transit network. Refused while any border still hands off onto it (remove those first
        with catc_delete_l3_handoff). Preview-first."""
        app: CatcApp = get_client(ctx)
        t = await resolve_transit(app, transit)
        path = IP_HANDOFFS if t.get("type") == TYPES["ip"] else SDA_HANDOFFS
        users: list[dict[str, Any]] = []
        for f in await sda_list(app, "fabricSites"):
            users += [
                h
                for h in await sda_list(app, path, {"fabricId": f["id"]})
                if h.get("transitNetworkId") == t["id"]
            ]
        blockers = []
        if users:
            borders = sorted({str(h.get("networkDeviceId")) for h in users})
            blockers.append(
                f"{len(users)} handoff(s) on {len(borders)} border(s) still use {t.get('name')}; "
                "remove them with catc_delete_l3_handoff."
            )
        plan = Plan(
            f"Delete transit network {t.get('name')} ({t.get('type')})",
            details={"transit": transit_row(t)},
            side_effects=["No device changes (no border uses it)."],
            fingerprint={"transit": t, "users": users},
            blockers=blockers,
        )

        async def apply() -> Any:
            return await sda_job(
                app,
                "DELETE",
                f"{SDA}/transitNetworks/{safe_id(str(t['id']), 'transit id')}",
                None,
                ctx,
                "delete transit",
            )

        return await preview_or_apply(
            ctx,
            tool="catc_delete_transit_network",
            args={"transit": transit},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )
