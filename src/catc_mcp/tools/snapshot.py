"""catc_snapshot / catc_compare_snapshot (D118): the Catalyst Center half of a pre/post change check
(core snapshot contract C53, docs/SNAPSHOTS.md in stutters-mcp-core).

Four sections, one product read each (plus one inventory lookup for device names):
- `devices`: reachability, Assurance health score (a metric; good band >= 8) and software version per
  device (/dna/intent/api/v1/device-health).
- `sites`: per site at and below the scope, device count, share of healthy devices and client count
  (/dna/data/api/v1/siteHealthSummaries).
- `compliance`: overall status and the status per compliance type per device
  (/dna/intent/api/v1/compliance/sites/{id}/networkDevices).
- `issues`: open (active) P1 and P2 Assurance issues by name and device (/dna/data/api/v1/assuranceIssues).

Timestamps, occurrence counts, CPU/memory scores and "last seen" are left out: two snapshots of an
unchanged network compare as "No change".
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import asyncio
from importlib.metadata import PackageNotFoundError, version
from typing import Any

from fastmcp import Context

from catc_mcp._core import ToolRegistrar, UpstreamError, get_client
from catc_mcp._core.http import fetch_all
from catc_mcp._core.snapshot import Metric, Snapshot, register_snapshot_tools
from catc_mcp.client import CatcApp, safe_id
from catc_mcp.common import PAGE_DEVICE_HEALTH, PAGE_ISSUES, inventory_names, is_uuid, resolve_site, window
from catc_mcp.tools.assurance import issue_attrs

GOOD_HEALTH = 8  # Assurance health bands: 1-3 poor, 4-7 fair, 8-10 good
ISSUE_HOURS = 168  # open issues last seen in the past week (a fixed window, so pre and post compare alike)
SCAN_CAP = 5000
ISSUE_CAP = 500
OK_COMPLIANCE = {"COMPLIANT", "NOT_APPLICABLE"}
BAD_COMPLIANCE = {"NON_COMPLIANT", "ERROR"}


def _server_version() -> str | None:
    try:
        return version("catc-mcp-server")
    except PackageNotFoundError:  # pragma: no cover - source tree without an install
        return None


def in_scope(path: Any, root: str) -> bool:
    """Is the site hierarchy `path` at or below `root` ('Global' = everything, unassigned included)?"""
    if root == "Global":
        return True
    p = str(path or "")
    return p == root or p.startswith(root + "/")


def _health(v: Any) -> int | float | None:
    """The health score, or None where Assurance computed none (-1, -2, missing)."""
    if isinstance(v, int | float) and not isinstance(v, bool) and v >= 0:
        return v
    return None


async def _device_health(app: CatcApp) -> list[dict[str, Any]]:
    page = await fetch_all(
        app.data_pager,
        app.api,
        "/dna/intent/api/v1/device-health",
        cap=SCAN_CAP,
        max_page=PAGE_DEVICE_HEALTH,
    )
    return [d for d in page.items if isinstance(d, dict)]


async def _site_health(app: CatcApp, root: str) -> list[dict[str, Any]]:
    params = {} if root == "Global" else {"siteHierarchy": root + "*"}
    page = await fetch_all(
        app.data_pager, app.api, "/dna/data/api/v1/siteHealthSummaries", params, cap=SCAN_CAP
    )
    return [s for s in page.items if isinstance(s, dict) and in_scope(s.get("siteHierarchy"), root)]


async def _compliance(app: CatcApp, site_id: str) -> list[dict[str, Any]]:
    sid = safe_id(site_id, "site id")
    page = await fetch_all(
        app.pager, app.api, f"/dna/intent/api/v1/compliance/sites/{sid}/networkDevices", cap=SCAN_CAP
    )
    return [r for r in page.items if isinstance(r, dict) and r.get("networkDeviceId")]


async def _issues(app: CatcApp, root: str) -> list[dict[str, Any]]:
    params: dict[str, Any] = {**window(ISSUE_HOURS), "priority": ["P1", "P2"], "status": "active"}
    if root != "Global":
        params["siteHierarchy"] = root + "*"
    page = await fetch_all(
        app.data_pager,
        app.api,
        "/dna/data/api/v1/assuranceIssues",
        params,
        cap=ISSUE_CAP,
        max_page=PAGE_ISSUES,
    )
    return [i for i in page.items if isinstance(i, dict) and in_scope(i.get("siteHierarchy"), root)]


def _upstream(res: Any) -> str | None:
    """The error text of a failed read (UpstreamError), None for a result; anything else is raised."""
    if isinstance(res, UpstreamError):
        return str(res)
    if isinstance(res, BaseException):
        raise res
    return None


async def take(ctx: Context, site: str) -> Snapshot:
    app: CatcApp = get_client(ctx)
    st = await resolve_site(app, site or "Global")
    root = str(st.get("nameHierarchy") or "Global")
    snap = Snapshot(
        "catc",
        "catc-mcp-server",
        scope={"site": root if site.strip() else ""},
        server_version=_server_version(),
    )
    results: tuple[Any, ...] = await asyncio.gather(
        _device_health(app),
        _site_health(app, root),
        _compliance(app, str(st["id"])),
        _issues(app, root),
        return_exceptions=True,
    )
    health_res, sites_res, comp_res, issues_res = results

    # Device names from the inventory: Assurance keeps records of deleted devices, which are left out.
    ids: set[str] = set()
    for res, field in ((health_res, "uuid"), (comp_res, "networkDeviceId"), (issues_res, "entityId")):
        if isinstance(res, list):
            ids |= {str(r.get(field)) for r in res if is_uuid(str(r.get(field) or ""))}
    names = await inventory_names(app, ids)

    devices = snap.section(
        "devices",
        "Device health",
        metrics={"health": Metric("higher", 1, limit=GOOD_HEALTH)},
    )
    if (err := _upstream(health_res)) is not None:
        devices.fail(err)
    else:
        for d in health_res:
            if not in_scope(d.get("location"), root):
                continue
            uid = str(d.get("uuid") or "")
            if names is not None and is_uuid(uid) and uid not in names:
                continue  # deleted from the inventory
            name = (names or {}).get(uid) or str(d.get("name") or d.get("ipAddress") or uid)
            reach = str(d.get("reachabilityHealth") or "") or None
            score = _health(d.get("overallHealth"))
            ok = reach != "UNREACHABLE" and (score is None or score >= GOOD_HEALTH)
            devices.item(
                f"device:{name}",
                ok=ok,
                state=reach,
                health=score,
                version=d.get("osVersion") or None,
                site=str(d.get("location") or "") or None,
            )

    sites = snap.section(
        "sites",
        "Site health",
        metrics={
            "devices_healthy_pct": Metric("higher", 10),
            "clients": Metric("higher", 10),
        },
    )
    if (err := _upstream(sites_res)) is not None:
        sites.fail(err)
    else:
        for s in sites_res:
            if not s.get("siteHierarchy"):
                continue
            count = s.get("networkDeviceCount")
            good = s.get("networkDeviceGoodHealthCount")
            site_ok: bool | None = None
            if isinstance(count, int) and count > 0 and isinstance(good, int):
                site_ok = good >= count
            sites.item(
                str(s.get("siteHierarchy")),
                ok=site_ok,
                devices=count,
                devices_healthy_pct=s.get("networkDeviceGoodHealthPercentage"),
                clients=s.get("clientCount"),
            )

    compliance = snap.section("compliance", "Compliance")
    if (err := _upstream(comp_res)) is not None:
        compliance.fail(err)
    else:
        for r in comp_res:
            uid = str(r["networkDeviceId"])
            if names is not None and uid not in names:
                continue
            status = str(r.get("status") or "UNKNOWN")
            per_type: dict[str, Any] = {}
            for det in r.get("details") or []:
                if isinstance(det, dict) and det.get("complianceType"):
                    per_type[str(det["complianceType"]).lower()] = str(det.get("status") or "UNKNOWN")
            comp_ok = True if status in OK_COMPLIANCE else False if status in BAD_COMPLIANCE else None
            compliance.item(f"device:{(names or {}).get(uid, uid)}", ok=comp_ok, state=status, **per_type)

    issues = snap.section("issues", "Open P1/P2 issues")
    if (err := _upstream(issues_res)) is not None:
        issues.fail(err)
    else:
        for i in issues_res:
            eid = str(i.get("entityId") or "")
            device = (names or {}).get(eid) or issue_attrs(i).get("nwDeviceName") or eid
            key = f"{i.get('name') or 'issue'}|{device}"[:200]
            if key in issues.items:
                continue  # the same issue raised again on the same device
            issues.item(
                key,
                ok=False,
                state=str(i.get("priority") or "") or None,
                label=str(i.get("summary") or "")[:150] or None,
                site=str(i.get("siteHierarchy") or "") or None,
            )
    return snap


def register(reg: ToolRegistrar) -> None:
    register_snapshot_tools(
        reg,
        take,
        product="Cisco Catalyst Center",
        covers="device reachability, health score and software version, health per site, compliance per "
        "device and type, open P1/P2 Assurance issues",
        site_doc="Site name hierarchy or id ('Global/AU/SYD-1'); the site and everything below it. "
        "Empty = every device and site",
    )
