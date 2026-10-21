"""SD-Access day-N edits (roadmap D99): change an anycast gateway or an edge port assignment in place.

Without these, moving a port to another VLAN or turning layer 2 flooding on for a subnet takes a delete and a
re-add, which drops every client on that port or subnet. Both tools PUT the current record with only the
changed fields replaced (the API wants the whole object; the fields it refuses to change are not offered) and
preview current -> new per field. A static security group (SGT) per gateway or port is set here too
(`securityGroupName`, a scalable group Catalyst Center knows).
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
from catc_mcp.client import CatcApp
from catc_mcp.common import resolve_device
from catc_mcp.safety import device_limit_blockers
from catc_mcp.tools.ops_writes import brief
from catc_mcp.tools.sda import SDA, AuthProfile, FabricRef, fabric_devices, resolve_fabric, sda_job, sda_list

# Fields the PUT body carries for a gateway (the required ones plus the optional settings it keeps).
GW_FIELDS = [
    "id",
    "fabricId",
    "virtualNetworkName",
    "ipPoolName",
    "vlanName",
    "vlanId",
    "trafficType",
    "poolType",
    "securityGroupName",
    "isCriticalPool",
    "isLayer2FloodingEnabled",
    "isWirelessPool",
    "isIpDirectedBroadcast",
    "isIntraSubnetRoutingEnabled",
    "isMultipleIpToMacAddresses",
    "isSupplicantBasedExtendedNodeOnboarding",
    "isGroupBasedPolicyEnforcementEnabled",
    "isWirelessFloodingEnabled",
    "isResourceGuardEnabled",
    "layer2FloodingAddressAssignment",
    "layer2FloodingAddress",
    "tcpMssAdjustment",
    "additionalIpPools",
]
PORT_FIELDS = [
    "id",
    "fabricId",
    "networkDeviceId",
    "interfaceName",
    "connectedDeviceType",
    "dataVlanName",
    "voiceVlanName",
    "authenticateTemplateName",
    "securityGroupName",
    "interfaceDescription",
    "nativeVlanId",
    "allowedVlanRanges",
]


def diff(before: dict[str, Any], after: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {k: {"from": before.get(k), "to": after.get(k)} for k in after if before.get(k) != after.get(k)}


def register(reg: ToolRegistrar) -> None:
    @reg.dangerous(title="Update anycast gateway", task=True)
    async def catc_update_anycast_gateway(
        ctx: Context,
        fabric_site: FabricRef,
        ip_pool: Annotated[str, Field(description="The gateway's IP pool name (or its VLAN name)")],
        layer2_flooding: Annotated[bool | None, Field(description="Layer 2 flooding (ARP/broadcast)")] = None,
        flooding_address: Annotated[
            str | None,
            Field(
                description="Layer 2 flooding multicast group (239.0.0.0/8); implies a USER-defined address"
            ),
        ] = None,
        ip_directed_broadcast: Annotated[bool | None, Field(description="IP-directed broadcast")] = None,
        multiple_ip_to_mac: Annotated[
            bool | None, Field(description="Multiple IP-to-MAC addresses (bridged VMs behind one MAC)")
        ] = None,
        traffic_type: Annotated[Literal["DATA", "VOICE"] | None, Field(description="Traffic type")] = None,
        security_group: Annotated[
            str | None, Field(description="Static security group for the subnet ('' removes it)")
        ] = None,
        group_policy_enforcement: Annotated[
            bool | None, Field(description="Group-based policy enforcement on this gateway's VLAN")
        ] = None,
        tcp_mss_adjustment: Annotated[
            int | None, Field(ge=500, le=1440, description="TCP MSS adjustment on the SVI")
        ] = None,
        resource_guard: Annotated[bool | None, Field(description="Resource guard")] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Change an anycast gateway in place instead of deleting and re-adding it (which drops every client
        in the subnet). Settable: layer 2 flooding and its address, IP-directed broadcast, multiple IP-to-MAC,
        traffic type, a static security group, group-based policy enforcement, TCP MSS, resource guard. Unset
        arguments keep their value; the VLAN, pool, VN, critical pool and intra-subnet routing can't be
        changed (re-create the gateway for those). Catalyst Center pushes the SVI change to every edge.
        Preview-first: current -> new per field and the edges."""
        app: CatcApp = get_client(ctx)
        fabric, fsite = await resolve_fabric(app, fabric_site)
        gws = await sda_list(app, "anycastGateways", {"fabricId": fabric["id"]})
        gw = next((g for g in gws if ip_pool in (g.get("ipPoolName"), g.get("vlanName"))), None)
        if gw is None:
            raise NotFound(
                f"No anycast gateway for {ip_pool!r} at {fsite.get('nameHierarchy')} "
                f"(have: {', '.join(str(g.get('ipPoolName')) for g in gws) or 'none'})."
            )
        changes: dict[str, Any] = {
            k: v
            for k, v in {
                "isLayer2FloodingEnabled": layer2_flooding,
                "isIpDirectedBroadcast": ip_directed_broadcast,
                "isMultipleIpToMacAddresses": multiple_ip_to_mac,
                "trafficType": traffic_type,
                "isGroupBasedPolicyEnforcementEnabled": group_policy_enforcement,
                "tcpMssAdjustment": tcp_mss_adjustment,
                "isResourceGuardEnabled": resource_guard,
            }.items()
            if v is not None
        }
        if flooding_address is not None:
            changes["layer2FloodingAddressAssignment"] = "USER"
            changes["layer2FloodingAddress"] = flooding_address
        if security_group is not None:
            changes["securityGroupName"] = security_group or None
        before = {k: gw.get(k) for k in GW_FIELDS if gw.get(k) is not None}
        after = {**before, **changes}
        if after.get("securityGroupName") is None:
            after.pop("securityGroupName", None)
        blockers: list[str] = []
        if flooding_address is not None and not after.get("isLayer2FloodingEnabled"):
            blockers.append("flooding_address needs layer 2 flooding on (layer2_flooding=true).")
        if gw.get("isCriticalPool") and traffic_type is not None:
            blockers.append("The traffic type of a critical pool can't be changed.")
        if gw.get("virtualNetworkName") == "INFRA_VN" and changes:
            blockers.append("INFRA_VN gateways take none of these settings.")
        # Diff against the merged changes, not `after`: a cleared security group is dropped from the body,
        # and diffing the body alone would hide the removal (and refuse it as 'Nothing to change').
        changed = diff(before, {**before, **changes})
        if not changed and not blockers:
            blockers.append("Nothing to change: the gateway already has those settings.")
        edges = [
            d
            for d in await sda_list(app, "fabricDevices", {"fabricId": fabric["id"]})
            if "EDGE_NODE" in (d.get("deviceRoles") or [])
        ]
        blockers += device_limit_blockers(app, len(edges), "edge devices")
        plan = Plan(
            f"Update the anycast gateway {gw.get('ipPoolName')} ({gw.get('vlanName')}) in "
            f"{gw.get('virtualNetworkName')} at {fsite.get('nameHierarchy')}",
            details={"changes": changed, "edges": [d.get("networkDeviceId") for d in edges], "body": [after]},
            side_effects=[f"Catalyst Center pushes the SVI change to {len(edges)} edge device(s)."],
            fingerprint={"gateway": gw},
            blockers=blockers,
            blast_radius=len(edges) or None,
        )

        async def apply() -> Any:
            job = await sda_job(app, "PUT", f"{SDA}/anycastGateways", [after], ctx, "update anycast gateway")
            now = [
                g
                for g in await sda_list(app, "anycastGateways", {"fabricId": fabric["id"]})
                if g.get("id") == gw["id"]
            ]
            return {**job, "gateway": now[0] if now else None}

        return await preview_or_apply(
            ctx,
            tool="catc_update_anycast_gateway",
            args={
                "fabric_site": fabric_site,
                "ip_pool": ip_pool,
                "layer2_flooding": layer2_flooding,
                "flooding_address": flooding_address,
                "ip_directed_broadcast": ip_directed_broadcast,
                "multiple_ip_to_mac": multiple_ip_to_mac,
                "traffic_type": traffic_type,
                "security_group": security_group,
                "group_policy_enforcement": group_policy_enforcement,
                "tcp_mss_adjustment": tcp_mss_adjustment,
                "resource_guard": resource_guard,
            },
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.dangerous(title="Update fabric port assignment")
    async def catc_update_port_assignment(
        ctx: Context,
        device: Annotated[str, Field(description="Fabric edge (hostname, IP, serial or id)")],
        interface: Annotated[str, Field(description="Interface name, e.g. GigabitEthernet1/0/3")],
        data_vlan: Annotated[
            str | None,
            Field(description="New data VLAN: VLAN name or IP pool of an anycast gateway ('' clears)"),
        ] = None,
        voice_vlan: Annotated[str | None, Field(description="New voice VLAN or pool ('' clears)")] = None,
        authentication: Annotated[
            AuthProfile | None, Field(description="Port authentication template (USER_DEVICE ports)")
        ] = None,
        security_group: Annotated[
            str | None, Field(description="Static security group for the port ('' removes it)")
        ] = None,
        description: Annotated[str | None, Field(max_length=230, description="Interface description")] = None,
        native_vlan: Annotated[
            int | None, Field(ge=1, le=4094, description="Native VLAN (TRUNKING_DEVICE ports)")
        ] = None,
        allowed_vlans: Annotated[
            str | None, Field(description="Allowed VLAN ranges, e.g. '100,200-210' (TRUNKING_DEVICE ports)")
        ] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Change an edge port's fabric assignment in place. Settable: its data or voice VLAN, authentication
        template, static security group, description, or a trunk's native and allowed VLANs. Unset arguments
        keep their value; the connected device type can't change (delete and re-assign for that). Catalyst
        Center reconfigures the port, so the client on it re-authenticates or renews its address.
        Preview-first: current -> new per field."""
        app: CatcApp = get_client(ctx)
        dev = await resolve_device(app, device)
        fdev = next(
            (
                d
                for d in await fabric_devices(app, str(dev["id"]))
                if "EDGE_NODE" in (d.get("deviceRoles") or [])
            ),
            None,
        )
        if fdev is None:
            raise InvalidRequest(f"{brief([dev])[0]} is not a fabric edge node.")
        fid = str(fdev["fabricId"])
        current = await sda_list(
            app,
            "portAssignments",
            {"fabricId": fid, "networkDeviceId": dev["id"], "interfaceName": interface},
        )
        port = next((p for p in current if p.get("interfaceName") == interface), None)
        if port is None:
            raise NotFound(
                f"{interface} on {brief([dev])[0]} has no port assignment (catc_assign_fabric_port)."
            )
        gws = await sda_list(app, "anycastGateways", {"fabricId": fid})
        blockers: list[str] = []

        def vlan_of(ref: str) -> str | None:
            if ref == "":
                return None
            for g in gws:
                if ref in (g.get("vlanName"), g.get("ipPoolName")):
                    return str(g.get("vlanName"))
            blockers.append(f"No anycast gateway with VLAN or pool {ref!r} at this fabric site.")
            return ref

        changes: dict[str, Any] = {}
        if data_vlan is not None:
            changes["dataVlanName"] = vlan_of(data_vlan)
        if voice_vlan is not None:
            changes["voiceVlanName"] = vlan_of(voice_vlan)
        if authentication is not None:
            changes["authenticateTemplateName"] = authentication
        if security_group is not None:
            changes["securityGroupName"] = security_group or None
        if description is not None:
            changes["interfaceDescription"] = description
        if native_vlan is not None:
            changes["nativeVlanId"] = native_vlan
        if allowed_vlans is not None:
            changes["allowedVlanRanges"] = allowed_vlans
        kind = port.get("connectedDeviceType")
        if (native_vlan is not None or allowed_vlans is not None) and kind != "TRUNKING_DEVICE":
            blockers.append(f"native_vlan and allowed_vlans apply to TRUNKING_DEVICE ports, not {kind}.")
        if authentication is not None and kind != "USER_DEVICE":
            blockers.append(f"An authentication template applies to USER_DEVICE ports, not {kind}.")
        before = {k: port.get(k) for k in PORT_FIELDS if port.get(k) is not None}
        after = {k: v for k, v in {**before, **changes}.items() if v is not None}
        if kind == "USER_DEVICE" and not (after.get("dataVlanName") or after.get("voiceVlanName")):
            blockers.append("A USER_DEVICE port needs a data or voice VLAN.")
        changed = diff(before, {**before, **changes})
        if not changed and not blockers:
            blockers.append("Nothing to change: the port already has those settings.")
        blockers += device_limit_blockers(app, 1)
        plan = Plan(
            f"Update {brief([dev])[0]} {interface} ({kind})",
            details={"changes": changed, "body": [after]},
            side_effects=[
                f"Catalyst Center reconfigures {interface}; its client re-authenticates or renews."
            ],
            fingerprint={"port": port, "gws": sorted(str(g.get("vlanName")) for g in gws)},
            blockers=blockers,
            blast_radius=1,
        )

        async def apply() -> Any:
            return await sda_job(app, "PUT", f"{SDA}/portAssignments", [after], ctx, "update port assignment")

        return await preview_or_apply(
            ctx,
            tool="catc_update_port_assignment",
            args={
                "device": device,
                "interface": interface,
                "data_vlan": data_vlan,
                "voice_vlan": voice_vlan,
                "authentication": authentication,
                "security_group": security_group,
                "description": description,
                "native_vlan": native_vlan,
                "allowed_vlans": allowed_vlans,
            },
            confirm=confirm,
            plan=plan,
            apply=apply,
        )
