"""Site hierarchy writes: create and update areas, buildings and floors (delete is dangerous)."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
from typing import Annotated, Any, Literal

from fastmcp import Context
from pydantic import Field
from stutters_mcp_core import (
    Confirm,
    InvalidRequest,
    Plan,
    ToolRegistrar,
    field_changes,
    get_client,
    preview_or_apply,
)

from catc_mcp.client import CatcApp
from catc_mcp.common import ensure_list, resolve_site
from catc_mcp.tools.sites import SITE_DETAIL_PATHS

RF_MODELS = Literal[
    "Cubes And Walled Offices",
    "Drywall Office Only",
    "Indoor High Ceiling",
    "Outdoor Open Space",
    "Free Space",
]
ALLOWED_PARENTS = {"area": ("global", "area"), "building": ("area", "global"), "floor": ("building",)}
CREATE_PATHS = {
    "area": "/dna/intent/api/v1/areas",
    "building": "/dna/intent/api/v2/buildings",
    "floor": "/dna/intent/api/v2/floors",
}
EDITABLE = {
    "area": ["name", "parentId"],
    "building": ["name", "parentId", "country", "address", "latitude", "longitude"],
    "floor": ["name", "parentId", "floorNumber", "rfModel", "width", "length", "height", "unitsOfMeasure"],
}


async def site_detail(app: CatcApp, site: dict[str, Any]) -> dict[str, Any]:
    path = SITE_DETAIL_PATHS.get(str(site.get("type")))
    if path is None:
        return dict(site)
    detail = await app.get_response(path.format(id=site["id"]))
    return {**site, **detail} if isinstance(detail, dict) else dict(site)


async def child_named(app: CatcApp, parent: dict[str, Any], name: str) -> dict[str, Any] | None:
    path = f"{parent['nameHierarchy']}/{name}"
    found = ensure_list(await app.get_response("/dna/intent/api/v1/sites", {"nameHierarchy": path}))
    for s in found:
        if isinstance(s, dict) and str(s.get("nameHierarchy", "")).lower() == path.lower():
            return s
    return None


def register(reg: ToolRegistrar) -> None:
    @reg.write(title="Create site")
    async def catc_create_site(
        ctx: Context,
        site_type: Annotated[
            Literal["area", "building", "floor"], Field(description="Kind of site to create")
        ],
        name: Annotated[str, Field(min_length=1, max_length=64, description="Name of the new site")],
        parent: Annotated[
            str,
            Field(
                description="Parent site (id or name hierarchy): Global or an area for areas/buildings, "
                "a building for floors"
            ),
        ] = "Global",
        country: Annotated[
            str | None,
            Field(description="Building: country name as Catalyst Center lists it, e.g. 'Australia'"),
        ] = None,
        address: Annotated[str | None, Field(description="Building: street address")] = None,
        latitude: Annotated[float | None, Field(ge=-90, le=90, description="Building: latitude")] = None,
        longitude: Annotated[float | None, Field(ge=-180, le=180, description="Building: longitude")] = None,
        floor_number: Annotated[int | None, Field(description="Floor: floor number (default 1)")] = None,
        rf_model: Annotated[
            RF_MODELS | None, Field(description="Floor: RF model (default 'Cubes And Walled Offices')")
        ] = None,
        width: Annotated[float | None, Field(gt=0, description="Floor: width (default 100)")] = None,
        length: Annotated[float | None, Field(gt=0, description="Floor: length (default 100)")] = None,
        height: Annotated[float | None, Field(gt=0, description="Floor: height (default 10)")] = None,
        units: Annotated[
            Literal["feet", "meters"], Field(description="Floor: units for width/length/height")
        ] = "feet",
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Create an area, building or floor in the site hierarchy. Preview-first: the first call
        shows the full path and attributes and refuses duplicates or a wrong parent type; repeat with
        confirm to create it. Buildings need a country plus an address or latitude/longitude; floors
        need a parent building. Returns the new site id."""
        app: CatcApp = get_client(ctx)
        args = {k: v for k, v in locals().items() if k not in ("ctx", "confirm", "app")}
        par = await resolve_site(app, parent)
        blockers: list[str] = []
        if par.get("type") not in ALLOWED_PARENTS[site_type]:
            blockers.append(
                f"A {site_type} can't go under a {par.get('type')} ({par.get('nameHierarchy')}); "
                f"allowed parents: {', '.join(ALLOWED_PARENTS[site_type])}."
            )
        if "/" in name:
            blockers.append("Site names can't contain '/'.")
        elif await child_named(app, par, name):
            blockers.append(f"{par.get('nameHierarchy')}/{name} already exists.")
        body: dict[str, Any] = {"name": name, "parentId": par["id"]}
        if site_type == "building":
            if not country:
                blockers.append("Buildings need `country`.")
            if not address and (latitude is None or longitude is None):
                blockers.append("Buildings need `address` or both `latitude` and `longitude`.")
            body.update(
                {
                    k: v
                    for k, v in {
                        "country": country,
                        "address": address,
                        "latitude": latitude,
                        "longitude": longitude,
                    }.items()
                    if v is not None
                }
            )
        elif site_type == "floor":
            body.update(
                {
                    "floorNumber": floor_number if floor_number is not None else 1,
                    "rfModel": rf_model or "Cubes And Walled Offices",
                    "width": width or 100.0,
                    "length": length or 100.0,
                    "height": height or 10.0,
                    "unitsOfMeasure": units,
                }
            )
        full = f"{par.get('nameHierarchy')}/{name}"
        plan = Plan(
            f"Create {site_type} {full}",
            details={"method": "POST", "path": CREATE_PATHS[site_type], "body": body},
            blockers=blockers,
        )

        async def apply() -> Any:
            job = await app.run_job(
                "POST", CREATE_PATHS[site_type], body, ctx=ctx, what=f"create {site_type}"
            )
            return {"site_id": job.get("data"), "nameHierarchy": full, "task": job.get("task_id")}

        return await preview_or_apply(
            ctx, tool="catc_create_site", args=args, confirm=confirm, plan=plan, apply=apply
        )

    @reg.write(title="Update site", destructive=False)
    async def catc_update_site(
        ctx: Context,
        site: Annotated[str, Field(description="Site to change (id or name hierarchy); not Global")],
        name: Annotated[str | None, Field(min_length=1, max_length=64, description="New name")] = None,
        country: Annotated[str | None, Field(description="Building: new country")] = None,
        address: Annotated[str | None, Field(description="Building: new street address")] = None,
        latitude: Annotated[float | None, Field(ge=-90, le=90, description="Building: new latitude")] = None,
        longitude: Annotated[
            float | None, Field(ge=-180, le=180, description="Building: new longitude")
        ] = None,
        floor_number: Annotated[int | None, Field(description="Floor: new floor number")] = None,
        rf_model: Annotated[RF_MODELS | None, Field(description="Floor: new RF model")] = None,
        width: Annotated[float | None, Field(gt=0, description="Floor: new width")] = None,
        length: Annotated[float | None, Field(gt=0, description="Floor: new length")] = None,
        height: Annotated[float | None, Field(gt=0, description="Floor: new height")] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Rename a site or change a building's address/coordinates or a floor's number, RF model and
        dimensions. Preview-first: the preview lists field-by-field changes; repeat with confirm to
        apply. Moving a site to another parent isn't supported here."""
        app: CatcApp = get_client(ctx)
        args = {k: v for k, v in locals().items() if k not in ("ctx", "confirm", "app")}
        s = await resolve_site(app, site)
        stype = str(s.get("type"))
        if stype not in EDITABLE:
            raise InvalidRequest("The Global site can't be changed.")
        current = await site_detail(app, s)
        desired_all = {
            "name": name,
            "country": country,
            "address": address,
            "latitude": latitude,
            "longitude": longitude,
            "floorNumber": floor_number,
            "rfModel": rf_model,
            "width": width,
            "length": length,
            "height": height,
        }
        not_applicable = [k for k, v in desired_all.items() if v is not None and k not in EDITABLE[stype]]
        if not_applicable:
            raise InvalidRequest(f"A {stype} has no {', '.join(not_applicable)}.")
        desired = {k: v for k, v in desired_all.items() if v is not None}
        if not desired:
            raise InvalidRequest("Nothing to change: give at least one new value.")
        body = {k: current.get(k) for k in EDITABLE[stype] if current.get(k) is not None}
        body.update(desired)
        changes = field_changes(current, desired)
        path = SITE_DETAIL_PATHS[stype].format(id=s["id"])
        blockers = []
        if name and name != s.get("name"):
            parent_path = str(s.get("nameHierarchy", "")).rsplit("/", 1)[0]
            if await child_named(app, {"nameHierarchy": parent_path}, name):
                blockers.append(f"{parent_path}/{name} already exists.")
        plan = Plan(
            f"Update {stype} {s.get('nameHierarchy')}",
            details={"method": "PUT", "path": path, "changes": changes or "no change"},
            fingerprint={k: current.get(k) for k in EDITABLE[stype]},
            blockers=blockers,
        )

        async def apply() -> Any:
            job = await app.run_job("PUT", path, body, ctx=ctx, what=f"update {stype}")
            return {"site_id": s["id"], "changes": changes, "task": job.get("task_id")}

        return await preview_or_apply(
            ctx, tool="catc_update_site", args=args, confirm=confirm, plan=plan, apply=apply
        )
