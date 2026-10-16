"""Site hierarchy reads: tree, one site, network settings."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import asyncio
from typing import Annotated, Any, Literal

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field

from catc_mcp._core import (
    ResponseFormat,
    ToolRegistrar,
    UpstreamError,
    get_client,
    object_result,
    text_result,
)
from catc_mcp._core.formatting import dumps
from catc_mcp._core.http import fetch_all
from catc_mcp.client import CatcApp
from catc_mcp.common import resolve_site
from catc_mcp.tools.credentials import all_credentials

SITE_DETAIL_PATHS = {
    "area": "/dna/intent/api/v1/areas/{id}",
    "building": "/dna/intent/api/v2/buildings/{id}",
    "floor": "/dna/intent/api/v2/floors/{id}",
}

SETTINGS = {
    "aaa": "aaaSettings",
    "banner": "bannerSettings",
    "dhcp": "dhcpSettings",
    "dns": "dnsSettings",
    "ntp": "ntpSettings",
    "telemetry": "telemetrySettings",
    "timezone": "timeZoneSettings",
    "image_distribution": "imageDistributionSettings",
    "credentials": "deviceCredentials",
}

SiteRef = Annotated[
    str,
    Field(description="Site id, full name hierarchy ('Global/Area/Building/Floor') or a unique site name"),
]


async def all_sites(app: CatcApp) -> tuple[list[dict[str, Any]], bool]:
    page = await fetch_all(app.pager, app.api, "/dna/intent/api/v1/sites", cap=20_000)
    return [s for s in page.items if isinstance(s, dict)], page.complete


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="Site hierarchy")
    async def catc_get_site_hierarchy(
        ctx: Context,
        root: Annotated[
            str | None, Field(description="Only show this site and its descendants (id or name hierarchy)")
        ] = None,
        max_depth: Annotated[
            int | None, Field(ge=1, le=10, description="Levels below the root to show (default all)")
        ] = None,
        site_type: Annotated[
            Literal["area", "building", "floor"] | None, Field(description="Only list sites of this type")
        ] = None,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """The site hierarchy (Global > areas > buildings > floors) as an indented tree with each
        site's type and id. Use it to find site name hierarchies and ids for other tools (device
        assignment, health by site, site creation parents)."""
        app: CatcApp = get_client(ctx)
        sites, complete = await all_sites(app)
        base = "Global"
        if root:
            base = str((await resolve_site(app, root)).get("nameHierarchy"))
        base_depth = base.count("/")
        rows = []
        for s in sorted(sites, key=lambda s: str(s.get("nameHierarchy", "")).lower()):
            path = str(s.get("nameHierarchy", ""))
            if path != base and not path.startswith(base + "/"):
                continue
            depth = path.count("/") - base_depth
            if max_depth is not None and depth > max_depth:
                continue
            if site_type and s.get("type") != site_type:
                continue
            row: dict[str, Any] = {"nameHierarchy": path, "type": s.get("type"), "id": s.get("id")}
            rows.append({**row, "depth": depth})
        note = "" if complete else " (partial: more than 20000 sites)"
        if response_format == "json":
            return text_result(dumps({"root": base, "count": len(rows), "sites": rows, "complete": complete}))
        lines = [f"Site hierarchy under {base}: {len(rows)} sites{note}", ""]
        for r in rows:
            name = str(r["nameHierarchy"]).rsplit("/", 1)[-1]
            lines.append(f"{'  ' * int(r['depth'])}- {name} ({r['type']}) `{r['id']}`")
        return text_result("\n".join(lines))

    @reg.read(title="Get site")
    async def catc_get_site(ctx: Context, site: SiteRef) -> ToolResult:
        """One site: id, type, name hierarchy, address/coordinates (buildings), dimensions and RF model
        (floors), its direct child sites and how many network devices are assigned to it.
        Use catc_get_site_settings for its DNS/NTP/AAA/DHCP settings."""
        app: CatcApp = get_client(ctx)
        s = await resolve_site(app, site)
        out: dict[str, Any] = dict(s)
        sid = str(s["id"])
        tasks: list[Any] = []
        detail_path = SITE_DETAIL_PATHS.get(str(s.get("type")))
        tasks.append(app.get_response(detail_path.format(id=sid)) if detail_path else asyncio.sleep(0))
        tasks.append(
            app.get_response("/dna/intent/api/v1/networkDevices/assignedToSite/count", {"siteId": sid})
            if s.get("type") != "global"
            else app.get_response("/dna/intent/api/v1/network-device/count")
        )
        detail, count = await asyncio.gather(*tasks, return_exceptions=True)
        if isinstance(detail, dict):
            out.update(detail)
        if isinstance(count, dict):
            count = count.get("count")
        if isinstance(count, int):
            out["assigned_devices"] = count
        sites, _ = await all_sites(app)
        prefix = str(s.get("nameHierarchy")) + "/"
        out["children"] = [
            {"name": c.get("name"), "type": c.get("type"), "id": c.get("id")}
            for c in sites
            if str(c.get("nameHierarchy", "")).startswith(prefix)
            and "/" not in str(c.get("nameHierarchy"))[len(prefix) :]
        ]
        return object_result(out)

    @reg.read(title="Get site network settings")
    async def catc_get_site_settings(
        ctx: Context,
        site: SiteRef,
        categories: Annotated[
            list[
                Literal[
                    "aaa",
                    "banner",
                    "dhcp",
                    "dns",
                    "ntp",
                    "telemetry",
                    "timezone",
                    "image_distribution",
                    "credentials",
                ]
            ]
            | None,
            Field(description="Settings to fetch (default: all)"),
        ] = None,
        inherited: Annotated[
            bool, Field(description="Include values inherited from parent sites (default true)")
        ] = True,
    ) -> ToolResult:
        """Network settings for a site (Design > Network Settings): AAA servers, banner, DHCP, DNS,
        NTP, telemetry (syslog/SNMP/NetFlow collectors), time zone, image distribution servers and the
        device credentials the site uses (shown as 'TYPE:description', never secrets). With
        inherited=true, values set on parent sites are included (inherited_from names the site that
        sets them). Change them with
        catc_update_site_settings and catc_assign_site_credentials."""
        app: CatcApp = get_client(ctx)
        s = await resolve_site(app, site)
        cats: list[str] = list(categories) if categories else list(SETTINGS)
        results = await asyncio.gather(
            *(
                app.get_response(
                    f"/dna/intent/api/v1/sites/{s['id']}/{SETTINGS[c]}",
                    {"_inherited": str(inherited).lower()},
                )
                for c in cats
            ),
            return_exceptions=True,
        )
        out: dict[str, Any] = {"site": s.get("nameHierarchy"), "site_id": s.get("id"), "settings": {}}
        for c, r in zip(cats, results, strict=True):
            if isinstance(r, UpstreamError):
                out["settings"][c] = {"error": str(r)[:200]}
            elif isinstance(r, BaseException):
                raise r
            else:
                out["settings"][c] = r
        for cat in out["settings"].values():
            if isinstance(cat, dict):
                for v in cat.values():
                    if isinstance(v, dict) and "inheritedSiteId" in v:
                        v.pop("inheritedSiteId")
                        name = v.pop("inheritedSiteName", None)
                        if name and name != s.get("name"):
                            v["inherited_from"] = name
        creds = out["settings"].get("credentials")
        if isinstance(creds, dict):
            known = {str(x.get("id")): x for x in await all_credentials(app)}
            for v in creds.values():
                cid = v.get("credentialsId") if isinstance(v, dict) else None
                if cid and str(cid) in known:
                    k = known[str(cid)]
                    v["credential"] = f"{k.get('type')}:{k.get('description')}"
        return object_result(out, shape=True)
