"""Product safety rails (roadmap D19/D20) on top of core's G7 rails.

Core enforces MCP_DRY_RUN, MCP_CHANGE_WINDOW, MCP_MAX_BLAST_RADIUS / MCP_BLAST_RADIUS_OVERRIDES and
MCP_TWO_PERSON_TOOLS for every write. Here: device targets (explicit devices, or every device under a site
or with a tag) and Catalyst Center's own limit, CATC_MAX_DEVICES_PER_CHANGE (default 10, 0 = off), which
applies to the tools that change device configuration or software (template deploys, provisioning, SWIM,
PnP claims and device replacement, device deletion). Each of those reports `blast_radius` = devices touched.
"""

from __future__ import annotations

from typing import Any

from catc_mcp._core import InvalidRequest
from catc_mcp._core.http import fetch_all
from catc_mcp.client import CatcApp
from catc_mcp.common import ensure_list, resolve_device, resolve_site, resolve_tag
from catc_mcp.tools.sites import all_sites

ASSIGNED = "/dna/intent/api/v1/networkDevices/assignedToSite"


async def devices_by_id(app: CatcApp, ids: list[str]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for i in range(0, len(ids), 100):
        chunk = ensure_list(
            await app.get_response("/dna/intent/api/v1/network-device", {"id": ",".join(ids[i : i + 100])})
        )
        out += [d for d in chunk if isinstance(d, dict)]
    return out


class TargetsTruncated(InvalidRequest):
    pass


TRUNCATED = (
    "The target list is larger than the server reads in one go, so the device count would be wrong. "
    "Narrow the selection (a smaller site, a tag, or a device list)."
)


async def site_devices(app: CatcApp, site: dict[str, Any]) -> list[dict[str, Any]]:
    """Every device assigned to the site or any site below it (Global: the whole inventory). Refuses
    (TargetsTruncated) rather than undercount when a list is partial."""
    if site.get("type") == "global":
        page = await fetch_all(app.pager, app.api, "/dna/intent/api/v1/network-device", {}, cap=5000)
        if not page.complete:
            raise TargetsTruncated(TRUNCATED)
        return [d for d in page.items if isinstance(d, dict)]
    ids = [str(a["deviceId"]) for a in await site_assignments(app, site)]
    return await devices_by_id(app, sorted(set(ids)))


async def site_assignments(app: CatcApp, site: dict[str, Any]) -> list[dict[str, Any]]:
    """Every device assignment ({"deviceId", "siteId", "siteNameHierarchy", "siteType"}) at an area,
    building or floor and every site below it. `assignedToSite` lists only a site's own devices, so
    each child is read. Refuses (TargetsTruncated) rather than undercount when a list is partial."""
    prefix = str(site.get("nameHierarchy")) + "/"
    sites, complete = await all_sites(app)
    if not complete:
        raise TargetsTruncated(TRUNCATED)
    out: list[dict[str, Any]] = []
    for s in [site, *(c for c in sites if str(c.get("nameHierarchy", "")).startswith(prefix))]:
        if s.get("type") not in ("building", "floor", "area"):
            continue
        assigned = await fetch_all(app.pager, app.api, ASSIGNED, {"siteId": s["id"]})
        if not assigned.complete:
            raise TargetsTruncated(TRUNCATED)
        for a in assigned.items:
            if isinstance(a, dict) and a.get("deviceId"):
                out.append(
                    {
                        "siteId": s["id"],
                        "siteNameHierarchy": s.get("nameHierarchy"),
                        "siteType": s.get("type"),
                        **a,
                    }
                )
    return out


async def tag_devices(app: CatcApp, tag: dict[str, Any]) -> list[dict[str, Any]]:
    page = await fetch_all(
        app.pager, app.api, f"/dna/intent/api/v1/tag/{tag['id']}/member", {"memberType": "networkdevice"}
    )
    if not page.complete:
        raise TargetsTruncated(TRUNCATED)
    ids = [str(m.get("id") or m.get("instanceUuid")) for m in page.items if isinstance(m, dict)]
    return await devices_by_id(app, sorted({i for i in ids if i and i != "None"}))


async def resolve_targets(
    app: CatcApp, devices: list[str] | None, site: str | None, tag: str | None
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Exactly one of devices / site / tag -> (devices, {"by": ..., ...}) for the preview."""
    given = [n for n, v in (("devices", devices), ("site", site), ("tag", tag)) if v]
    if len(given) != 1:
        raise InvalidRequest("Give exactly one target: devices, site (every device under it) or tag.")
    if devices:
        out: dict[str, dict[str, Any]] = {}
        for r in devices:
            d = await resolve_device(app, r)
            out[str(d["id"])] = d
        return list(out.values()), {"by": "devices"}
    if site:
        s = await resolve_site(app, site)
        devs = await site_devices(app, s)
        return devs, {"by": "site", "site": s.get("nameHierarchy"), "includes_child_sites": True}
    t = await resolve_tag(app, str(tag))
    return await tag_devices(app, t), {"by": "tag", "tag": t.get("name")}


def device_limit_blockers(app: CatcApp, count: int, what: str = "devices") -> list[str]:
    """CATC_MAX_DEVICES_PER_CHANGE: refuse a change touching more devices than the limit."""
    limit = app.settings.max_devices_per_change
    if limit and count > limit:
        return [
            f"This change touches {count} {what}, more than CATC_MAX_DEVICES_PER_CHANGE={limit}. Split it "
            "into smaller batches (a floor, a tag, or an explicit device list), or have the operator raise "
            "the limit."
        ]
    return []


def limit_policy(app: CatcApp) -> dict[str, Any]:
    return {"max_devices_per_change": app.settings.max_devices_per_change or None}
