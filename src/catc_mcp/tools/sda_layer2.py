"""SD-Access layer 2 (roadmap D94): layer 2 virtual networks and layer 2 border handoffs.

A layer 2 VN is a fabric VLAN with no anycast gateway (printers, OT, a subnet still routed outside the fabric,
a brownfield migration): the edges carry it, its hosts reach each other across the fabric, and their gateway
stays outside. A layer 2 handoff extends a fabric VLAN out of a border port into an external VLAN of a
traditional network. Both push configuration to the fabric devices.
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
from typing import Annotated, Any, Literal

from fastmcp import Context
from pydantic import Field

from catc_mcp._core import (
    Confirm,
    InvalidRequest,
    NotFound,
    Plan,
    ToolRegistrar,
    get_client,
    preview_or_apply,
)
from catc_mcp.client import CatcApp, safe_id
from catc_mcp.common import ensure_list, resolve_device
from catc_mcp.safety import device_limit_blockers
from catc_mcp.tools.ops_writes import brief
from catc_mcp.tools.sda import SDA, FabricRef, edge_labels, fabric_devices, resolve_fabric, sda_job, sda_list

L2VN_FIELDS = [
    "id",
    "fabricId",
    "vlanName",
    "vlanId",
    "trafficType",
    "associatedLayer3VirtualNetworkName",
    "isFabricEnabledWireless",
    "isMultipleIpToMacAddresses",
    "isResourceGuardEnabled",
    "isWirelessFloodingEnabled",
    "layer2FloodingAddressAssignment",
    "layer2FloodingAddress",
]
RESERVED_VLANS = {1, 1002, 1003, 1004, 1005, 2046, 4094}
HANDOFFS = "fabricDevices/layer2Handoffs"


def register(reg: ToolRegistrar) -> None:
    @reg.dangerous(title="Set layer 2 virtual network", task=True)
    async def catc_set_l2_virtual_network(
        ctx: Context,
        fabric_site: FabricRef,
        vlan_name: Annotated[
            str, Field(min_length=1, max_length=32, pattern=r"^[A-Za-z0-9_-]+$", description="VLAN name")
        ],
        vlan_id: Annotated[
            int | None,
            Field(ge=2, le=4093, description="Create: VLAN id (default: Catalyst Center picks one)"),
        ] = None,
        traffic_type: Annotated[Literal["DATA", "VOICE"] | None, Field(description="Traffic type")] = None,
        layer3_vn: Annotated[
            str | None, Field(description="Associate with a layer 3 VN (anchoring); create only")
        ] = None,
        flooding_address: Annotated[
            str | None, Field(description="Layer 2 flooding group (239.0.0.0/8); default: shared")
        ] = None,
        multiple_ip_to_mac: Annotated[bool | None, Field(description="Multiple IP-to-MAC addresses")] = None,
        resource_guard: Annotated[bool | None, Field(description="Resource guard")] = None,
        delete: Annotated[bool, Field(description="Delete the layer 2 VN instead")] = False,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Create, change or delete a layer 2 virtual network at an SD-Access fabric site. A layer 2 VN is a
        fabric VLAN without an anycast gateway: its hosts reach each other across the fabric and their gateway
        stays outside (a layer 2 handoff, catc_set_l2_handoff, connects it). Change: traffic type, flooding
        address, multiple IP-to-MAC, resource guard (VLAN name and id are fixed). Catalyst Center pushes the
        VLAN to every edge. Preview-first; delete is refused while edge ports or a layer 2 handoff use the
        VLAN."""
        app: CatcApp = get_client(ctx)
        fabric, site = await resolve_fabric(app, fabric_site)
        fid = str(fabric["id"])
        current = next(
            (
                v
                for v in await sda_list(app, "layer2VirtualNetworks", {"fabricId": fid})
                if v.get("vlanName") == vlan_name
            ),
            None,
        )
        devices = await sda_list(app, "fabricDevices", {"fabricId": fid})
        edges = [d for d in devices if "EDGE_NODE" in (d.get("deviceRoles") or [])]
        blockers = device_limit_blockers(app, len(edges), "edge devices")
        changes: dict[str, Any] = {}
        body: dict[str, Any] | None = None
        method, path = "POST", f"{SDA}/layer2VirtualNetworks"
        if delete:
            if current is None:
                raise NotFound(f"No layer 2 VN {vlan_name} at {site.get('nameHierarchy')}.")
            ports = [
                p
                for p in await sda_list(app, "portAssignments", {"fabricId": fid})
                if vlan_name in (p.get("dataVlanName"), p.get("voiceVlanName"))
            ]
            handoffs = [
                h
                for d in devices
                for h in await sda_list(
                    app, HANDOFFS, {"fabricId": fid, "networkDeviceId": d.get("networkDeviceId")}
                )
                if h.get("internalVlanId") == current.get("vlanId")
            ]
            if ports or handoffs:
                blockers.append(
                    f"{vlan_name} is still used by {len(ports)} edge port(s) and {len(handoffs)} layer 2 "
                    "handoff(s)."
                )
            method, path = (
                "DELETE",
                f"{SDA}/layer2VirtualNetworks/{safe_id(str(current['id']), 'layer 2 VN id')}",
            )
            action = f"Delete layer 2 VN {vlan_name} ({current.get('vlanId')}) at {site.get('nameHierarchy')}"
        else:
            wanted: dict[str, Any] = {
                k: v
                for k, v in {
                    "trafficType": traffic_type,
                    "isMultipleIpToMacAddresses": multiple_ip_to_mac,
                    "isResourceGuardEnabled": resource_guard,
                }.items()
                if v is not None
            }
            if flooding_address is not None:
                wanted["layer2FloodingAddressAssignment"] = "USER"
                wanted["layer2FloodingAddress"] = flooding_address
            if current is None:
                if vlan_id in RESERVED_VLANS:
                    blockers.append(f"VLAN {vlan_id} is reserved.")
                if layer3_vn:
                    vns = {
                        str(v.get("virtualNetworkName"))
                        for v in await sda_list(app, "layer3VirtualNetworks")
                        if fid in map(str, ensure_list(v.get("fabricIds")))
                    }
                    if layer3_vn not in vns:
                        blockers.append(f"{layer3_vn} is not a layer 3 VN of this fabric site.")
                body = {
                    "fabricId": fid,
                    "vlanName": vlan_name,
                    "vlanId": vlan_id,
                    "trafficType": "DATA",
                    "associatedLayer3VirtualNetworkName": layer3_vn,
                    **wanted,
                }
                body = {k: v for k, v in body.items() if v is not None}
                action = f"Create layer 2 VN {vlan_name} at {site.get('nameHierarchy')}"
            else:
                if vlan_id is not None and vlan_id != current.get("vlanId"):
                    blockers.append("The VLAN id of an existing layer 2 VN can't change.")
                if layer3_vn is not None and layer3_vn != current.get("associatedLayer3VirtualNetworkName"):
                    blockers.append("The layer 3 VN association can't change; delete and re-create.")
                before = {k: current.get(k) for k in L2VN_FIELDS if current.get(k) is not None}
                changes = {
                    k: {"from": before.get(k), "to": v} for k, v in wanted.items() if before.get(k) != v
                }
                if not changes:
                    blockers.append("Nothing to change.")
                body = {**before, **wanted}
                method = "PUT"
                action = f"Update layer 2 VN {vlan_name} at {site.get('nameHierarchy')}"
        plan = Plan(
            action,
            details={
                "current": current,
                "changes": changes or None,
                "method": method,
                "path": path,
                "body": [body] if body else None,
                "edges": await edge_labels(app, edges),
            },
            side_effects=[f"Catalyst Center pushes the VLAN change to {len(edges)} edge device(s)."],
            fingerprint={"current": current},
            blockers=blockers,
            blast_radius=len(edges) or None,
        )

        async def apply() -> Any:
            job = await sda_job(app, method, path, [body] if body else None, ctx, f"{method} layer 2 VN")
            now = [
                v
                for v in await sda_list(app, "layer2VirtualNetworks", {"fabricId": fid})
                if v.get("vlanName") == vlan_name
            ]
            return {**job, "layer2_vn": now[0] if now else None}

        return await preview_or_apply(
            ctx,
            tool="catc_set_l2_virtual_network",
            args={
                "fabric_site": fabric_site,
                "vlan_name": vlan_name,
                "vlan_id": vlan_id,
                "traffic_type": traffic_type,
                "layer3_vn": layer3_vn,
                "flooding_address": flooding_address,
                "multiple_ip_to_mac": multiple_ip_to_mac,
                "resource_guard": resource_guard,
                "delete": delete,
            },
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.dangerous(title="Set layer 2 handoff", task=True)
    async def catc_set_l2_handoff(
        ctx: Context,
        border: Annotated[str, Field(description="Border node (hostname, IP, serial or id)")],
        interface: Annotated[str, Field(description="Border port towards the traditional network")],
        vlan: Annotated[
            str, Field(description="Fabric VLAN to extend: a layer 2 VN or gateway VLAN name, or its VLAN id")
        ],
        external_vlan: Annotated[
            int | None, Field(ge=2, le=4094, description="VLAN on the external side (default: the same id)")
        ] = None,
        delete: Annotated[bool, Field(description="Remove this handoff instead")] = False,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Set or remove a layer 2 handoff: a fabric VLAN extended out of a border port into a VLAN of a
        traditional network. The fabric VLAN is a layer 2 VN or an anycast gateway's VLAN (by name or id); the
        external VLAN defaults to the same id. Catalyst Center configures the border port as a trunk carrying
        it. Preview-first: refuses a VLAN already handed off on that port."""
        app: CatcApp = get_client(ctx)
        dev = await resolve_device(app, border)
        fdev = next(
            (
                d
                for d in await fabric_devices(app, str(dev["id"]))
                if "BORDER_NODE" in (d.get("deviceRoles") or [])
            ),
            None,
        )
        if fdev is None:
            raise InvalidRequest(f"{brief([dev])[0]} is not a border node of any fabric site.")
        fid = str(fdev["fabricId"])
        vlans: dict[str, int] = {}
        for v in await sda_list(app, "layer2VirtualNetworks", {"fabricId": fid}):
            vlans[str(v.get("vlanName"))] = int(v["vlanId"])
        for g in await sda_list(app, "anycastGateways", {"fabricId": fid}):
            if g.get("vlanId") is not None:
                vlans[str(g.get("vlanName"))] = int(g["vlanId"])
        internal = int(vlan) if vlan.isdigit() else vlans.get(vlan)
        if internal is None or internal not in vlans.values():
            raise NotFound(
                f"No fabric VLAN {vlan!r} at the border's fabric site "
                f"(have: {', '.join(sorted(vlans)) or 'none'})."
            )
        external = external_vlan or internal
        have = await sda_list(app, HANDOFFS, {"fabricId": fid, "networkDeviceId": dev["id"]})
        mine = [
            h for h in have if h.get("interfaceName") == interface and h.get("internalVlanId") == internal
        ]
        blockers = device_limit_blockers(app, 1)
        if delete:
            if not mine:
                raise NotFound(f"No layer 2 handoff of VLAN {internal} on {interface}.")
            method = "DELETE"
            path = f"{SDA}/{HANDOFFS}/{safe_id(str(mine[0]['id']), 'handoff id')}"
            body = None
            action = f"Remove the layer 2 handoff of VLAN {internal} on {brief([dev])[0]} {interface}"
        else:
            if mine:
                blockers.append(f"VLAN {internal} is already handed off on {interface}.")
            if any(
                h.get("interfaceName") == interface and h.get("externalVlanId") == external
                for h in have
                if h not in mine
            ):
                blockers.append(f"External VLAN {external} is already used on {interface}.")
            method, path = "POST", f"{SDA}/{HANDOFFS}"
            body = {
                "networkDeviceId": dev["id"],
                "fabricId": fid,
                "interfaceName": interface,
                "internalVlanId": internal,
                "externalVlanId": external,
            }
            action = f"Hand VLAN {internal} off on {brief([dev])[0]} {interface} as external VLAN {external}"
        plan = Plan(
            action,
            details={"method": method, "path": path, "body": [body] if body else None, "existing": have},
            side_effects=[
                f"Catalyst Center reconfigures {interface} on the border (trunk carrying the VLAN)."
            ],
            fingerprint={"have": have},
            blockers=blockers,
            blast_radius=1,
        )

        async def apply() -> Any:
            return await sda_job(
                app, method, path, [body] if body else None, ctx, f"{method} layer 2 handoff"
            )

        return await preview_or_apply(
            ctx,
            tool="catc_set_l2_handoff",
            args={
                "border": border,
                "interface": interface,
                "vlan": vlan,
                "external_vlan": external_vlan,
                "delete": delete,
            },
            confirm=confirm,
            plan=plan,
            apply=apply,
        )
