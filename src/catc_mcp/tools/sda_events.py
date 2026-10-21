"""SD-Access drift (roadmap D100): pending fabric events and applying them on purpose.

Catalyst Center queues a "pending fabric event" when a fabric device's configuration no longer matches the
fabric intent and needs a push (after an RMA, a reload, a failed provision, a device-side change, or a
fabric setting that only reaches devices on the next push); the GUI shows them as a banner. These tools list
them per fabric site and apply them, one request per event as the API asks.
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
from typing import Annotated, Any

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field

from catc_mcp._core import (
    Confirm,
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
from catc_mcp.client import CatcApp
from catc_mcp.common import resolve_site
from catc_mcp.safety import device_limit_blockers
from catc_mcp.tools.sda import SDA, resolve_fabric, sda_job, sda_list

PATH = f"{SDA}/pendingFabricEvents"


async def pending(app: CatcApp, fabrics: list[dict[str, Any]], names: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    for f in fabrics:
        for e in await sda_list(app, "pendingFabricEvents", {"fabricId": f["id"]}):
            out.append(
                {
                    "id": e.get("id"),
                    "fabric_id": e.get("fabricId") or f["id"],
                    "fabric_site": names.get(str(f["id"])),
                    "detail": e.get("detail"),
                }
            )
    return out


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="Pending fabric events")
    async def catc_list_pending_fabric_events(
        ctx: Context,
        fabric_site: Annotated[
            str | None, Field(description="Only this fabric site (site name hierarchy, site id or fabric id)")
        ] = None,
        limit: Annotated[int, Field(ge=1, le=500)] = 100,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """SD-Access drift: the pending fabric events Catalyst Center has queued, per fabric site. These are
        configuration pushes it wants to make again after an RMA, a reload, a failed provision or a
        device-side change; each comes with its id and detail. Apply them on purpose with
        catc_apply_pending_fabric_events."""
        app: CatcApp = get_client(ctx)
        if fabric_site:
            fabric, site = await resolve_fabric(app, fabric_site)
            fabrics, names = [fabric], {str(fabric["id"]): site.get("nameHierarchy")}
        else:
            fabrics = await sda_list(app, "fabricSites")
            names = {}
            for f in fabrics:
                try:
                    names[str(f["id"])] = (await resolve_site(app, str(f.get("siteId")))).get("nameHierarchy")
                except NotFound:
                    names[str(f["id"])] = f.get("siteId")
        events = await pending(app, fabrics, names)
        note = (
            "No SD-Access fabric sites."
            if not fabrics
            else "No pending fabric events: the fabric devices match the intent."
            if not events
            else "Apply with catc_apply_pending_fabric_events (dangerous; it pushes configuration)."
        )
        return list_result(
            Page(events[offset : offset + limit], offset, len(events)),
            fmt=response_format,
            extra={"fabric_sites_checked": len(fabrics), "note": note},
        )

    @reg.dangerous(title="Apply pending fabric events", task=True)
    async def catc_apply_pending_fabric_events(
        ctx: Context,
        fabric_site: Annotated[
            str, Field(description="Fabric site (site name hierarchy, site id or fabric id)")
        ],
        event_ids: Annotated[
            list[str] | None,
            Field(max_length=50, description="Only these events (ids from catc_list_pending_fabric_events)"),
        ] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Apply a fabric site's pending fabric events. Catalyst Center pushes the queued fabric configuration
        to the devices concerned. Default: every pending event at the site; event_ids picks some. One request
        per event, in order; a failure stops the run and says which were applied. Preview-first: lists the
        events and their details."""
        app: CatcApp = get_client(ctx)
        fabric, site = await resolve_fabric(app, fabric_site)
        events = await pending(app, [fabric], {str(fabric["id"]): site.get("nameHierarchy")})
        if event_ids is not None:
            wanted = [e.strip() for e in event_ids]
            known = {str(e["id"]) for e in events}
            missing = [e for e in wanted if e not in known]
            if missing:
                raise NotFound(
                    f"Not pending at {site.get('nameHierarchy')}: {', '.join(missing)} "
                    "(catc_list_pending_fabric_events lists what is)."
                )
            events = [e for e in events if str(e["id"]) in wanted]
        blockers = [] if events else [f"No pending fabric events at {site.get('nameHierarchy')}."]
        devices = await sda_list(app, "fabricDevices", {"fabricId": fabric["id"]})
        blockers += device_limit_blockers(app, len(devices), "fabric devices")
        plan = Plan(
            f"Apply {len(events)} pending fabric event(s) at {site.get('nameHierarchy')}",
            details={"events": events, "method": "POST", "path": f"{PATH}/apply"},
            side_effects=[
                "Catalyst Center pushes the queued fabric configuration to the fabric devices concerned "
                f"(up to {len(devices)} at this site)."
            ],
            fingerprint={"events": sorted(str(e["id"]) for e in events)},
            blockers=blockers,
            blast_radius=len(devices) or None,
        )

        async def apply() -> Any:
            done: list[str] = []
            for e in events:
                body = [{"fabricId": e["fabric_id"], "id": e["id"]}]
                try:
                    await sda_job(app, "POST", f"{PATH}/apply", body, ctx, "apply pending fabric event")
                except UpstreamError as err:
                    raise UpstreamError(
                        f"Stopped at event {e['id']} ({len(done)} of {len(events)} applied: "
                        f"{done or 'none'}): {err}"
                    ) from err
                done.append(str(e["id"]))
            left = await pending(app, [fabric], {str(fabric["id"]): site.get("nameHierarchy")})
            return {"applied": done, "still_pending": left}

        return await preview_or_apply(
            ctx,
            tool="catc_apply_pending_fabric_events",
            args={"fabric_site": fabric_site, "event_ids": event_ids},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )
