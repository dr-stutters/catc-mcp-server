"""SD-Access fabric device changes (roadmap D103): roles and border settings in place.

Without this, giving an edge the border role, adding a second control plane or moving a border's priority
means removing the device from the fabric and adding it back, which drops every client behind it. `PUT
sda/fabricDevices` takes the whole record; the fabric, the device and the border's local AS number are fixed
(the 3.2.2 spec marks them not updatable).
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import copy
import ipaddress
from typing import Annotated, Any

from fastmcp import Context
from pydantic import Field

from catc_mcp._core import Confirm, InvalidRequest, Plan, ToolRegistrar, get_client, preview_or_apply
from catc_mcp.client import CatcApp
from catc_mcp.common import resolve_device
from catc_mcp.safety import device_limit_blockers
from catc_mcp.tools.ops_writes import brief
from catc_mcp.tools.sda import SDA, Role, fabric_devices, sda_job, sda_list


def register(reg: ToolRegistrar) -> None:
    @reg.dangerous(title="Update fabric device", task=True)
    async def catc_update_fabric_device(
        ctx: Context,
        device: Annotated[str, Field(description="Fabric device (hostname, management IP, serial or id)")],
        roles: Annotated[
            list[Role] | None,
            Field(
                min_length=1,
                description="The device's full role list (CONTROL_PLANE_NODE, BORDER_NODE, EDGE_NODE)",
            ),
        ] = None,
        border_asn: Annotated[
            str | None,
            Field(
                pattern=r"^\d{1,10}(\.\d{1,5})?$", description="Only when the device becomes a border: its AS"
            ),
        ] = None,
        default_exit: Annotated[
            bool | None, Field(description="Border: gateway of last resort for the site")
        ] = None,
        import_external_routes: Annotated[
            bool | None, Field(description="Border: import external routes into the fabric")
        ] = None,
        border_priority: Annotated[
            int | None, Field(ge=1, le=9, description="Border: 1 (preferred) to 9")
        ] = None,
        prepend_as_count: Annotated[
            int | None, Field(ge=1, le=10, description="Border: AS-path prepends")
        ] = None,
        layer2_border: Annotated[
            bool | None, Field(description="Border: also a layer 2 border (for layer 2 handoffs)")
        ] = None,
        bgp_router_id: Annotated[str | None, Field(description="Border: custom BGP router id (IPv4)")] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Change a fabric device's roles or border settings in place, instead of removing it from the fabric
        and adding it back (which drops every client behind it). roles is the full new list (e.g. add
        BORDER_NODE to an edge, add CONTROL_PLANE_NODE for a second control plane); border settings: default
        exit, external route import, priority (1-9), AS-path prepends, layer 2 border, BGP router id. A new
        border needs border_asn; an existing border's AS can't change. Catalyst Center re-provisions the
        device. Preview-first: current -> new; refuses dropping the last control plane while edges remain."""
        app: CatcApp = get_client(ctx)
        dev = await resolve_device(app, device)
        fdevs = await fabric_devices(app, str(dev["id"]))
        if not fdevs:
            raise InvalidRequest(f"{brief([dev])[0]} is not a fabric device (catc_add_fabric_device).")
        fdev = fdevs[0]
        fid = str(fdev["fabricId"])
        before_roles = sorted(fdev.get("deviceRoles") or [])
        new_roles = sorted(set(roles)) if roles is not None else before_roles
        blockers = device_limit_blockers(app, 1)
        settings = copy.deepcopy(fdev.get("borderDeviceSettings") or {})
        border_args = {
            "isDefaultExit": default_exit,
            "importExternalRoutes": import_external_routes,
            "borderPriority": border_priority,
            "prependAutonomousSystemCount": prepend_as_count,
            "customBgpRouterId": bgp_router_id,
        }
        given = {k: v for k, v in border_args.items() if v is not None}
        if bgp_router_id is not None:
            try:
                ipaddress.IPv4Address(bgp_router_id)
            except ValueError:
                blockers.append(f"bgp_router_id {bgp_router_id!r} is not an IPv4 address.")
        if "BORDER_NODE" in new_roles:
            l3 = settings.setdefault("layer3Settings", {})
            if "BORDER_NODE" not in before_roles:
                if not border_asn:
                    blockers.append("A new BORDER_NODE needs border_asn (its local BGP AS number).")
                l3.setdefault("isDefaultExit", True)
                l3.setdefault("importExternalRoutes", True)
                l3["localAutonomousSystemNumber"] = border_asn
            elif border_asn and border_asn != l3.get("localAutonomousSystemNumber"):
                blockers.append("A border's local AS number can't change (remove and re-add the border).")
            l3.update(given)
            types = set(settings.get("borderTypes") or ["LAYER_3"])
            if layer2_border is not None:
                types = types | {"LAYER_2"} if layer2_border else types - {"LAYER_2"}
            settings["borderTypes"] = sorted(types | {"LAYER_3"})
        else:
            if given or layer2_border is not None or border_asn:
                blockers.append("Border settings apply only to a device with the BORDER_NODE role.")
            settings = {}
        peers = [
            d
            for d in await sda_list(app, "fabricDevices", {"fabricId": fid})
            if d.get("id") != fdev.get("id")
        ]
        drops_cp = "CONTROL_PLANE_NODE" in before_roles and "CONTROL_PLANE_NODE" not in new_roles
        other_cp = any("CONTROL_PLANE_NODE" in (d.get("deviceRoles") or []) for d in peers)
        edges_left = (
            any("EDGE_NODE" in (d.get("deviceRoles") or []) for d in peers) or "EDGE_NODE" in new_roles
        )
        if drops_cp and not other_cp and edges_left:
            blockers.append("This is the last control plane node and edges remain; add another first.")
        if "EDGE_NODE" in before_roles and "EDGE_NODE" not in new_roles:
            ports = await sda_list(app, "portAssignments", {"fabricId": fid, "networkDeviceId": dev["id"]})
            if ports:
                blockers.append(
                    f"{len(ports)} port assignment(s) on this edge; remove them before dropping EDGE_NODE."
                )
        body: dict[str, Any] = {
            "id": fdev.get("id"),
            "fabricId": fid,
            "networkDeviceId": dev["id"],
            "deviceRoles": new_roles,
        }
        if settings:
            body["borderDeviceSettings"] = settings
        before = {"deviceRoles": before_roles, "borderDeviceSettings": fdev.get("borderDeviceSettings") or {}}
        after = {"deviceRoles": new_roles, "borderDeviceSettings": settings}
        changes = {k: {"from": before[k], "to": after[k]} for k in after if before[k] != after[k]}
        if not changes:
            blockers.append("Nothing to change.")
        plan = Plan(
            f"Update {brief([dev])[0]} in its fabric site: {', '.join(changes) or 'no change'}",
            details={"changes": changes, "method": "PUT", "path": f"{SDA}/fabricDevices", "body": [body]},
            side_effects=[
                "Catalyst Center re-provisions the device's fabric configuration (LISP, border BGP)."
            ],
            fingerprint={"fdev": fdev, "peers": sorted(str(d.get("id")) for d in peers)},
            blockers=blockers,
            blast_radius=1,
        )

        async def apply() -> Any:
            job = await sda_job(app, "PUT", f"{SDA}/fabricDevices", [body], ctx, "update fabric device")
            now = await fabric_devices(app, str(dev["id"]))
            return {**job, "fabric_device": now[0] if now else None}

        return await preview_or_apply(
            ctx,
            tool="catc_update_fabric_device",
            args={
                "device": device,
                "roles": roles,
                "border_asn": border_asn,
                "default_exit": default_exit,
                "import_external_routes": import_external_routes,
                "border_priority": border_priority,
                "prepend_as_count": prepend_as_count,
                "layer2_border": layer2_border,
                "bgp_router_id": bgp_router_id,
            },
            confirm=confirm,
            plan=plan,
            apply=apply,
        )
