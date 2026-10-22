"""SD-Access fabric device changes (roadmap D103): a border's updatable settings in place.

The 3.2.2 `PUT sda/fabricDevices` takes the whole record but marks the roles, the border's local AS number,
default exit and external route import as not updatable; what it lets change is the border priority (1-9), the
AS-path prepend count (1-10), a custom BGP router id and the border types (adding or dropping LAYER_2). A
role, default-exit or route-import change still means catc_delete_fabric_device and catc_add_fabric_device.
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
from catc_mcp.tools.sda import SDA, fabric_devices, sda_job

# The PUT's ranges (unset = Catalyst Center's defaults, priority 10 and no prepends); values read back outside
# them are left out of the request rather than re-sent. Live 2026-10-22: a PUT with borderPriority 10 answers
# 400 NCHS20769, so a priority once set can't go back to unset.
RANGES = {"borderPriority": (1, 9), "prependAutonomousSystemCount": (1, 10)}
ONE_WAY = (
    "One way: the border has no priority set (Catalyst Center reads it back as 10), and once one is set it "
    "can't go back to unset: 3.2.2 refuses 10 with NCHS20769, so it can only move within 1-9 later."
)


def in_range(key: str, value: Any) -> bool:
    lo, hi = RANGES[key]
    return isinstance(value, int) and not isinstance(value, bool) and lo <= value <= hi


def register(reg: ToolRegistrar) -> None:
    @reg.dangerous(title="Update fabric border settings", task=True)
    async def catc_update_fabric_device(
        ctx: Context,
        device: Annotated[
            str, Field(description="Fabric border device (hostname, management IP, serial or id)")
        ],
        border_priority: Annotated[
            int | None,
            Field(ge=1, le=9, description="1 (preferred) to 9; once set, it can't go back to unset"),
        ] = None,
        prepend_as_count: Annotated[
            int | None, Field(ge=1, le=10, description="AS-path prepends, 1-10")
        ] = None,
        layer2_border: Annotated[
            bool | None, Field(description="Add (true) or drop (false) the layer 2 border type")
        ] = None,
        bgp_router_id: Annotated[str | None, Field(description="Custom BGP router id (IPv4)")] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Change a fabric border's updatable settings in place: border priority (1-9), AS-path prepends
        (1-10), a custom BGP router id, and the layer 2 border type. On 3.2.2 the roles, the local AS number,
        default exit and external route import can't be updated: remove the device from the fabric and add it
        back (catc_delete_fabric_device, catc_add_fabric_device). A priority is one way: a border added
        without one reads back as 10, but 3.2.2 refuses 10 on a write (NCHS20769), so once set it can only
        move within 1-9 (9 is the closest to unset). Catalyst Center re-provisions the border's BGP.
        Preview-first: current -> new."""
        app: CatcApp = get_client(ctx)
        dev = await resolve_device(app, device)
        fdevs = await fabric_devices(app, str(dev["id"]))
        if not fdevs:
            raise InvalidRequest(f"{brief([dev])[0]} is not a fabric device (catc_add_fabric_device).")
        fdev = fdevs[0]
        if "BORDER_NODE" not in (fdev.get("deviceRoles") or []):
            raise InvalidRequest(
                f"{brief([dev])[0]} is not a border: on 3.2.2 only a border's priority, AS-path prepends, "
                "BGP router id and layer 2 type can change in place (roles can't)."
            )
        blockers = device_limit_blockers(app, 1)
        before = copy.deepcopy(fdev.get("borderDeviceSettings") or {})
        settings = copy.deepcopy(before)
        l3 = settings.setdefault("layer3Settings", {})
        for key in RANGES:  # e.g. priority 10 (the unset default) is outside the PUT's 1-9
            if key in l3 and not in_range(key, l3[key]):
                l3.pop(key)
        given = {
            k: v
            for k, v in {
                "borderPriority": border_priority,
                "prependAutonomousSystemCount": prepend_as_count,
                "customBgpRouterId": bgp_router_id,
            }.items()
            if v is not None
        }
        if bgp_router_id is not None:
            try:
                ipaddress.IPv4Address(bgp_router_id)
            except ValueError:
                blockers.append(f"bgp_router_id {bgp_router_id!r} is not an IPv4 address.")
        l3.update(given)
        types = set(settings.get("borderTypes") or ["LAYER_3"])
        if layer2_border is not None:
            types = types | {"LAYER_2"} if layer2_border else types - {"LAYER_2"}
        settings["borderTypes"] = sorted(types | {"LAYER_3"})
        before_l3 = before.get("layer3Settings") or {}
        changes = {k: {"from": before_l3.get(k), "to": v} for k, v in given.items() if before_l3.get(k) != v}
        # The border's first priority (it had none, or the unset default 10 read back): no way back after it.
        first_priority = "borderPriority" in changes and not in_range(
            "borderPriority", before_l3.get("borderPriority")
        )
        if sorted(before.get("borderTypes") or ["LAYER_3"]) != settings["borderTypes"]:
            changes["borderTypes"] = {"from": before.get("borderTypes"), "to": settings["borderTypes"]}
        if not changes:
            blockers.append("Nothing to change.")
        body = {
            "id": fdev.get("id"),
            "fabricId": fdev.get("fabricId"),
            "networkDeviceId": dev["id"],
            "deviceRoles": fdev.get("deviceRoles"),  # required in the body, not updatable
            "borderDeviceSettings": settings,
        }
        plan = Plan(
            f"Update border {brief([dev])[0]}: {', '.join(changes) or 'no change'}",
            details={"changes": changes, "method": "PUT", "path": f"{SDA}/fabricDevices", "body": [body]},
            side_effects=[
                "Catalyst Center re-provisions the border's BGP/LISP configuration.",
                *([ONE_WAY] if first_priority else []),
            ],
            fingerprint={"fdev": fdev},
            blockers=blockers,
            blast_radius=1,
        )

        async def apply() -> Any:
            job = await sda_job(app, "PUT", f"{SDA}/fabricDevices", [body], ctx, "update fabric border")
            now = await fabric_devices(app, str(dev["id"]))
            return {**job, "fabric_device": now[0] if now else None}

        return await preview_or_apply(
            ctx,
            tool="catc_update_fabric_device",
            args={
                "device": device,
                "border_priority": border_priority,
                "prepend_as_count": prepend_as_count,
                "layer2_border": layer2_border,
                "bgp_router_id": bgp_router_id,
            },
            confirm=confirm,
            plan=plan,
            apply=apply,
        )
