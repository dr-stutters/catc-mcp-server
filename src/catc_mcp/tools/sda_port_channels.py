"""SD-Access port channels (roadmap D98): bundle a fabric device's ports towards a server, a trunked switch or
an extended node.

One tool creates a port channel (Catalyst Center names it Port-channelN), changes its member ports,
description or trunk VLANs, or deletes it. Protocol and connected device type can't change after creation
(delete and re-create). The member ports must be free of port assignments and other port channels.
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
from catc_mcp.common import resolve_device
from catc_mcp.safety import device_limit_blockers
from catc_mcp.tools.ops_writes import brief
from catc_mcp.tools.sda import SDA, fabric_devices, sda_job, sda_list

PATH = f"{SDA}/portChannels"
FIELDS = [
    "id",
    "fabricId",
    "networkDeviceId",
    "portChannelName",
    "interfaceNames",
    "connectedDeviceType",
    "protocol",
    "description",
    "nativeVlanId",
    "allowedVlanRanges",
]


def register(reg: ToolRegistrar) -> None:
    @reg.dangerous(title="Set fabric port channel", task=True)
    async def catc_set_fabric_port_channel(
        ctx: Context,
        device: Annotated[str, Field(description="Fabric device (hostname, IP, serial or id)")],
        port_channel: Annotated[
            str | None,
            Field(
                description="Existing port channel to change or delete (e.g. Port-channel1); omit to create "
                "one"
            ),
        ] = None,
        interfaces: Annotated[
            list[str] | None,
            Field(max_length=16, description="Member ports (create: required; update: replaces the members)"),
        ] = None,
        connected_device_type: Annotated[
            Literal["TRUNK", "EXTENDED_NODE"], Field(description="Create: what is on the other end")
        ] = "TRUNK",
        protocol: Annotated[
            Literal["LACP", "PAGP", "ON"],
            Field(description="Create: bundling protocol (PAgP for extended nodes)"),
        ] = "LACP",
        description: Annotated[
            str | None, Field(max_length=230, description="Port channel description")
        ] = None,
        native_vlan: Annotated[int | None, Field(ge=1, le=4094, description="TRUNK: native VLAN")] = None,
        allowed_vlans: Annotated[
            str | None, Field(description="TRUNK: allowed VLAN ranges, e.g. '100,200-210'")
        ] = None,
        delete: Annotated[bool, Field(description="Delete port_channel instead")] = False,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Create, change or delete a port channel on an SD-Access fabric device. Create: member ports, the
        connected device type (TRUNK to a server or switch, EXTENDED_NODE with PAgP) and the protocol
        (LACP up to 16 ports, PAgP/ON up to 8); Catalyst Center names it. Change: member ports, description,
        a trunk's native and allowed VLANs. Catalyst Center reconfigures the member ports. Preview-first:
        refuses ports that already have a port assignment or belong to another port channel."""
        app: CatcApp = get_client(ctx)
        dev = await resolve_device(app, device)
        fdevs = await fabric_devices(app, str(dev["id"]))
        if not fdevs:
            raise InvalidRequest(f"{brief([dev])[0]} is not a fabric device.")
        fid = str(fdevs[0]["fabricId"])
        channels = await sda_list(app, "portChannels", {"fabricId": fid, "networkDeviceId": dev["id"]})
        current = None
        if port_channel:
            current = next(
                (c for c in channels if str(c.get("portChannelName")).lower() == port_channel.lower()), None
            )
            if current is None:
                raise NotFound(
                    f"No {port_channel} on {brief([dev])[0]} "
                    f"(has: {', '.join(str(c.get('portChannelName')) for c in channels) or 'none'})."
                )
        blockers = device_limit_blockers(app, 1)
        body: dict[str, Any] | None = None
        method, params = "POST", None
        path = PATH
        changes: dict[str, Any] = {}
        if delete:
            if current is None:
                raise InvalidRequest("Give port_channel to delete.")
            method, path = "DELETE", f"{PATH}/{safe_id(str(current['id']), 'port channel id')}"
            action = f"Delete {current.get('portChannelName')} on {brief([dev])[0]}"
        else:
            if interfaces is not None:
                ports = await sda_list(
                    app, "portAssignments", {"fabricId": fid, "networkDeviceId": dev["id"]}
                )
                assigned = {str(p.get("interfaceName")) for p in ports}
                in_other = {
                    str(i)
                    for c in channels
                    if current is None or c.get("id") != current.get("id")
                    for i in c.get("interfaceNames") or []
                }
                for i in interfaces:
                    if i in assigned:
                        blockers.append(f"{i} has a port assignment; remove it first.")
                    if i in in_other:
                        blockers.append(f"{i} is already in another port channel.")
            if current is None:
                if not interfaces:
                    blockers.append("Give the member interfaces to create a port channel.")
                if connected_device_type == "EXTENDED_NODE" and protocol != "PAGP":
                    blockers.append("An EXTENDED_NODE port channel uses PAgP.")
                if protocol in ("PAGP", "ON") and len(interfaces or []) > 8:
                    blockers.append(f"{protocol} bundles at most 8 ports.")
                body = {
                    "fabricId": fid,
                    "networkDeviceId": dev["id"],
                    "interfaceNames": interfaces,
                    "connectedDeviceType": connected_device_type,
                    "protocol": protocol,
                    "description": description,
                    "nativeVlanId": native_vlan,
                    "allowedVlanRanges": allowed_vlans,
                }
                body = {k: v for k, v in body.items() if v is not None}
                action = (
                    f"Create a {protocol} port channel on {brief([dev])[0]} ({', '.join(interfaces or [])})"
                )
            else:
                method = "PUT"
                before = {k: current.get(k) for k in FIELDS if current.get(k) is not None}
                for k, v in (
                    ("interfaceNames", interfaces),
                    ("description", description),
                    ("nativeVlanId", native_vlan),
                    ("allowedVlanRanges", allowed_vlans),
                ):
                    if v is not None and v != before.get(k):
                        changes[k] = {"from": before.get(k), "to": v}
                body = {**before, **{k: c["to"] for k, c in changes.items()}}
                if (native_vlan is not None or allowed_vlans is not None) and current.get(
                    "connectedDeviceType"
                ) != "TRUNK":
                    blockers.append("native_vlan and allowed_vlans apply to TRUNK port channels.")
                if not changes:
                    blockers.append("Nothing to change.")
                action = f"Update {current.get('portChannelName')} on {brief([dev])[0]}"
        plan = Plan(
            action,
            details={
                "current": current,
                "changes": changes or None,
                "method": method,
                "path": path,
                "body": [body] if body else None,
                "params": params,
            },
            side_effects=["Catalyst Center reconfigures the member ports; traffic on them drops briefly."],
            fingerprint={"channels": channels},
            blockers=blockers,
            blast_radius=1,
        )

        async def apply() -> Any:
            job = await sda_job(app, method, path, [body] if body else None, ctx, f"{method} port channel")
            now = await sda_list(app, "portChannels", {"fabricId": fid, "networkDeviceId": dev["id"]})
            return {
                **job,
                "port_channels": [{k: c.get(k) for k in FIELDS if c.get(k) is not None} for c in now],
            }

        return await preview_or_apply(
            ctx,
            tool="catc_set_fabric_port_channel",
            args={
                "device": device,
                "port_channel": port_channel,
                "interfaces": interfaces,
                "connected_device_type": connected_device_type,
                "protocol": protocol,
                "description": description,
                "native_vlan": native_vlan,
                "allowed_vlans": allowed_vlans,
                "delete": delete,
            },
            confirm=confirm,
            plan=plan,
            apply=apply,
        )
