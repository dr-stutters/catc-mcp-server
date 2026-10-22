"""SD-Access fabric site settings (roadmap D104): the control plane's pub/sub mode and the underlay transport.

Fabric sites built on releases before pub/sub became the default run LISP/BGP between the control plane and
the borders; moving to LISP pub/sub is one flag on the fabric site. Catalyst Center 3.2.2 only changes that
flag on a fabric site without fabric devices (NCHS20420, found live 2026-10-22): the devices come out, the
flag changes, and the devices added back get the new mode. The authentication template, also on the fabric
site, is catc_set_fabric_authentication_profile's.
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
from typing import Annotated, Any, Literal

from fastmcp import Context
from pydantic import Field

from catc_mcp._core import Confirm, Plan, ToolRegistrar, get_client, preview_or_apply
from catc_mcp.client import CatcApp
from catc_mcp.safety import device_limit_blockers
from catc_mcp.tools.sda import SDA, FabricRef, edge_labels, resolve_fabric, sda_job, sda_list

FIELDS = ["id", "siteId", "authenticationProfileName", "isPubSubEnabled", "underlayTransport"]
SHOWN = 10  # fabric devices named in the pub/sub blocker


def removal_order(device: dict[str, Any]) -> tuple[bool, bool]:
    """Edges first, then borders, the control plane last (catc_delete_fabric_device refuses the last control
    plane node while edges remain)."""
    roles = device.get("deviceRoles") or []
    return "CONTROL_PLANE_NODE" in roles, "BORDER_NODE" in roles


async def pub_sub_blocker(app: CatcApp, devices: list[dict[str, Any]]) -> str:
    ordered = sorted(devices, key=removal_order)
    labels = await edge_labels(app, ordered[:SHOWN])
    named = [
        f"{lbl} [{', '.join(d.get('deviceRoles') or [])}]" for lbl, d in zip(labels, ordered, strict=False)
    ]
    more = f" and {len(devices) - SHOWN} more" if len(devices) > SHOWN else ""
    return (
        "Catalyst Center refuses a change of isPubSubEnabled while the fabric site has fabric devices "
        f"(3.2.2: NCHS20420); it has {len(devices)}: {'; '.join(named)}{more}. Remove them first with "
        "catc_delete_fabric_device in this order (edges before the control plane / border), change the "
        "mode on the empty fabric site, then add them back with catc_add_fabric_device (control plane / "
        "border first). This path was proven live: the devices added back got the new mode."
    )


def register(reg: ToolRegistrar) -> None:
    @reg.dangerous(title="Update fabric site", task=True)
    async def catc_update_fabric_site(
        ctx: Context,
        fabric_site: FabricRef,
        pub_sub: Annotated[
            bool | None, Field(description="LISP pub/sub for the control plane (true) or LISP/BGP (false)")
        ] = None,
        underlay_transport: Annotated[
            Literal["IPV4", "IPV6", "IPV4_IPV6"] | None,
            Field(description="The fabric site's underlay transport"),
        ] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Change an SD-Access fabric site's control plane mode (LISP pub/sub or LISP/BGP) or underlay
        transport (IPv4, IPv6, dual stack). Catalyst Center 3.2.2 refuses a control plane mode change while
        the fabric site has any fabric device (NCHS20420), so the preview blocks it and lists them in removal
        order: remove them with catc_delete_fabric_device (edges before the control plane / border), change
        the mode, then add them back with catc_add_fabric_device (control plane / border first); proven
        live, the devices added back get the new mode. An underlay transport change was not tried live, so
        it is not blocked: Catalyst Center re-provisions every fabric device of the site, or may refuse it
        with devices in place as it does a mode change. The authentication template is changed with
        catc_set_fabric_authentication_profile. Preview-first: current -> new and the fabric devices
        affected."""
        app: CatcApp = get_client(ctx)
        fabric, site = await resolve_fabric(app, fabric_site)
        fid = str(fabric["id"])
        before = {k: fabric.get(k) for k in FIELDS if fabric.get(k) is not None}
        wanted = {
            k: v
            for k, v in {"isPubSubEnabled": pub_sub, "underlayTransport": underlay_transport}.items()
            if v is not None
        }
        changes = {k: {"from": before.get(k), "to": v} for k, v in wanted.items() if before.get(k) != v}
        body = {**before, **wanted}
        devices = await sda_list(app, "fabricDevices", {"fabricId": fid})
        blockers = [] if changes else ["Nothing to change."]
        if "isPubSubEnabled" in changes and devices:
            blockers.append(await pub_sub_blocker(app, devices))
        blockers += device_limit_blockers(app, len(devices), "fabric devices")
        side = []
        if devices:
            side.append(
                f"Catalyst Center re-provisions the fabric configuration of {len(devices)} fabric device(s)."
            )
        if "underlayTransport" in changes:
            side.append(
                "An underlay transport change was not tried live; Catalyst Center may refuse it while the "
                "fabric site has fabric devices, as it does a pub/sub change."
            )
        if "isPubSubEnabled" in changes and not devices:
            side.append(
                "The fabric site has no fabric devices, so nothing is pushed now; the fabric devices added "
                "afterwards (catc_add_fabric_device) get the new control plane mode."
            )
        if changes.get("isPubSubEnabled", {}).get("to") is False:
            side.append(
                "Going back from pub/sub to LISP/BGP may be refused by Catalyst Center; borders need BGP "
                "to the control plane again."
            )
        plan = Plan(
            f"Update fabric site {site.get('nameHierarchy')}: "
            + "; ".join(f"{k} {c['from']} -> {c['to']}" for k, c in changes.items()),
            details={"changes": changes, "method": "PUT", "path": f"{SDA}/fabricSites", "body": [body]},
            side_effects=side,
            fingerprint={"fabric": fabric, "devices": sorted(str(d.get("id")) for d in devices)},
            blockers=blockers,
            blast_radius=len(devices) or None,
        )

        async def apply() -> Any:
            job = await sda_job(app, "PUT", f"{SDA}/fabricSites", [body], ctx, "update fabric site")
            now, _ = await resolve_fabric(app, fid)
            return {**job, "fabric_site": {k: now.get(k) for k in FIELDS}}

        return await preview_or_apply(
            ctx,
            tool="catc_update_fabric_site",
            args={"fabric_site": fabric_site, "pub_sub": pub_sub, "underlay_transport": underlay_transport},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )
