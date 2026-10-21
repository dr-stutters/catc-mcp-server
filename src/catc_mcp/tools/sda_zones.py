"""SD-Access fabric zones (roadmap D97): a building or floor inside a fabric site with its own gateways.

A large fabric site limits which anycast gateways reach which floors with fabric zones: a zone is a site
below the fabric site, with its own authentication template, and anycast gateways can then be added at the
zone (its id is the fabricId for them). Defining a zone changes no device. Delete with catc_delete_sda_object
(kind fabric_zone) or the catc_delete_fabric_site cascade.
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import contextlib
from typing import Annotated, Any

from fastmcp import Context
from pydantic import Field

from catc_mcp._core import Confirm, NotFound, Plan, ToolRegistrar, get_client, preview_or_apply
from catc_mcp.client import CatcApp
from catc_mcp.common import resolve_site
from catc_mcp.tools.sda import SDA, AuthProfile, _under, sda_job, sda_list


async def parent_fabric(app: CatcApp, site: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]] | None:
    """The fabric site strictly above `site`, with its site record (None when there is none)."""
    best: tuple[dict[str, Any], dict[str, Any]] | None = None
    for f in await sda_list(app, "fabricSites"):
        with contextlib.suppress(NotFound):
            fsite = await resolve_site(app, str(f.get("siteId")))
            deeper = best is None or len(str(fsite.get("nameHierarchy"))) > len(
                str(best[1].get("nameHierarchy"))
            )
            if fsite["id"] != site["id"] and _under(site.get("nameHierarchy"), fsite) and deeper:
                best = (f, fsite)
    return best


def register(reg: ToolRegistrar) -> None:
    @reg.write(title="Create fabric zone")
    async def catc_create_fabric_zone(
        ctx: Context,
        site: Annotated[
            str, Field(description="Building or floor inside a fabric site (name hierarchy or id)")
        ],
        authentication_profile: Annotated[
            AuthProfile | None,
            Field(description="The zone's authentication template (default: the fabric site's)"),
        ] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Make a building or floor inside an SD-Access fabric site a fabric zone. Anycast gateways can then
        be added at the zone so only its edges carry them; its authentication template defaults to the
        fabric site's. Changes no device by itself. Preview-first: refuses a site that is not inside a fabric
        site, is a fabric site itself, or is already a zone."""
        app: CatcApp = get_client(ctx)
        s = await resolve_site(app, site)
        parent = await parent_fabric(app, s)
        blockers: list[str] = []
        if any(str(f.get("siteId")) == str(s["id"]) for f in await sda_list(app, "fabricSites")):
            blockers.append(f"{s.get('nameHierarchy')} is a fabric site itself, not a zone of one.")
        elif parent is None:
            blockers.append(
                f"{s.get('nameHierarchy')} is not inside a fabric site (catc_create_fabric_site first)."
            )
        existing = [
            z for z in await sda_list(app, "fabricZones", {"siteId": s["id"]}) if z.get("siteId") == s["id"]
        ]
        if existing:
            blockers.append(f"{s.get('nameHierarchy')} is already a fabric zone.")
        auth = authentication_profile or (parent[0].get("authenticationProfileName") if parent else None)
        body = [{"siteId": s["id"], "authenticationProfileName": auth or "No Authentication"}]
        of = parent[1].get("nameHierarchy") if parent else "(no fabric site)"
        plan = Plan(
            f"Make {s.get('nameHierarchy')} a fabric zone of {of} ({body[0]['authenticationProfileName']})",
            details={"method": "POST", "path": f"{SDA}/fabricZones", "body": body},
            side_effects=["No device changes until anycast gateways are added at the zone."],
            fingerprint={
                "site": s["id"],
                "parent": parent[0].get("id") if parent else None,
                "existing": existing,
            },
            blockers=blockers,
        )

        async def apply() -> Any:
            job = await sda_job(app, "POST", f"{SDA}/fabricZones", body, ctx, "create fabric zone")
            made = [
                z
                for z in await sda_list(app, "fabricZones", {"siteId": s["id"]})
                if z.get("siteId") == s["id"]
            ]
            return {**job, "zone_id": made[0].get("id") if made else None}

        return await preview_or_apply(
            ctx,
            tool="catc_create_fabric_zone",
            args={"site": site, "authentication_profile": authentication_profile},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )
