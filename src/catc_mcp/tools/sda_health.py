"""SD-Access health (roadmap D92): fabric sites, virtual networks and transits as Assurance scores them.

The Data API keeps one health summary per fabric site, per virtual network and per transit network, each with
an overall good-health percentage and per-dimension device counts (control plane, LISP sessions, border to
control plane, pub/sub, BGP, AAA, CTS environment-data download, port channels, VN exit, multicast, ...).
This module groups those counts generically (any `<dim>{Good,Fair,Poor,No,Total}Health...` key), names the
dimensions with fair or poor devices, and adds a one-line verdict. Assurance lags a change by minutes.
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import re
from typing import Annotated, Any, Literal

from fastmcp import Context
from pydantic import Field

from catc_mcp._core import ToolRegistrar, get_client
from catc_mcp._core.http import fetch_all
from catc_mcp.client import CatcApp
from catc_mcp.common import ensure_list, gather_sections, seg, window

DATA = "/dna/data/api/v1"
_DIM = re.compile(r"^(?P<dim>[a-z][A-Za-z0-9]*?)(?P<kind>Good|Fair|Poor|No|Total)Health(?:Device)?Count$")
_ALT_TOTAL = re.compile(r"^(?P<dim>[a-z][A-Za-z0-9]*?)TotalDeviceCount$")
_PCT = re.compile(r"^(?P<dim>[a-z][A-Za-z0-9]*?)(?:Score)?(?:Good)?HealthPercentage$")
OVERALL = (
    "goodHealthDeviceCount",
    "fairHealthDeviceCount",
    "poorHealthDeviceCount",
    "totalHealthDeviceCount",
)
VN_FIELDS = ["name", "id", "layer", "vlan", "vnid", "associatedL3Vn", "totalFabricSites", "totalEndpoints"]
TREND_ATTRS = ("goodHealthPercentage", "goodHealthDeviceCount", "poorHealthDeviceCount")
TREND_INTERVALS = {
    "5min": "5 minutes",
    "10min": "10 minutes",
    "1hour": "1 hour",
    "1day": "1 day",
    "7day": "7 days",
}


def dimensions(row: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """{dimension: {good, fair, poor, no, total, pct}} from a health summary row; '' is the overall score."""
    dims: dict[str, dict[str, Any]] = {}
    for key, val in row.items():
        if not isinstance(val, int | float) or isinstance(val, bool):
            continue
        if m := _DIM.match(key):
            dims.setdefault(m["dim"], {})[m["kind"].lower()] = val
        elif m := _ALT_TOTAL.match(key):
            dims.setdefault(m["dim"], {}).setdefault("total", val)
        elif m := _PCT.match(key):
            dims.setdefault(m["dim"], {})["pct"] = val
    # The overall counts have no prefix (goodHealthDeviceCount, ...); they become dimension ''.
    overall = {k: row[k] for k in OVERALL if isinstance(row.get(k), int | float)}
    out = {d: v for d, v in dims.items() if v.get("total") or v.get("poor") or v.get("fair")}
    if overall or isinstance(row.get("goodHealthPercentage"), int | float):
        out[""] = {
            "good": overall.get("goodHealthDeviceCount"),
            "fair": overall.get("fairHealthDeviceCount"),
            "poor": overall.get("poorHealthDeviceCount"),
            "total": overall.get("totalHealthDeviceCount"),
            "pct": row.get("goodHealthPercentage"),
        }
    return out


def problems(dims: dict[str, dict[str, Any]]) -> list[str]:
    """Dimensions with fair or poor devices, worst first: 'lispSession: 1 poor of 2'."""
    bad = [
        (int(v.get("poor") or 0), int(v.get("fair") or 0), d, v)
        for d, v in dims.items()
        if d and ((v.get("poor") or 0) or (v.get("fair") or 0))
    ]
    bad.sort(key=lambda t: (-t[0], -t[1], t[2]))
    return [
        f"{d}: "
        + ", ".join(p for p in (f"{poor} poor" if poor else "", f"{fair} fair" if fair else "") if p)
        + (f" of {v['total']}" if v.get("total") else "")
        for poor, fair, d, v in bad
    ]


def entity(row: dict[str, Any], keep: list[str]) -> dict[str, Any]:
    dims = dimensions(row)
    overall = dims.pop("", {})
    out = {k: row[k] for k in keep if row.get(k) not in (None, "")}
    out["health"] = {k: v for k, v in overall.items() if v is not None}
    out["problems"] = problems(dims)
    out["dimensions"] = dims
    return out


def verdict(summary: dict[str, Any], sites: list[dict[str, Any]]) -> str:
    if not summary.get("fabricSiteCount") and not sites:
        return (
            "No SD-Access fabric sites with health data (none exist, or Assurance has not scored them yet)."
        )
    parts = []
    for s in sites:
        pct = s["health"].get("pct")
        tail = f"; {', '.join(s['problems'][:3])}" if s["problems"] else ""
        good, total = s["health"].get("good"), s["health"].get("total")
        devs = f" ({good}/{total} devices good)" if total else ""
        parts.append(
            f"{s.get('name') or s.get('id')}: {'n/a' if pct is None else f'{pct:g}% good'}{devs}{tail}"
        )
    issues = sum(int(summary.get(k) or 0) for k in ("p1IssueCount", "p2IssueCount"))
    lead = f"{len(sites)} fabric site(s)" + (f", {issues} P1/P2 issue(s)" if issues else "")
    return f"{lead}: " + "; ".join(parts)


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="SD-Access fabric health")
    async def catc_fabric_health(
        ctx: Context,
        fabric_site: Annotated[
            str | None,
            Field(description="Only this fabric site and its VNs (name hierarchy; '*' wildcards allowed)"),
        ] = None,
        include: Annotated[
            list[Literal["virtual_networks", "transits"]],
            Field(description="Also score the virtual networks and/or transit networks"),
        ] = ["virtual_networks", "transits"],  # noqa: B006 - read-only default, FastMCP schema
        hours: Annotated[
            float | None,
            Field(
                gt=0, le=720, description="Score over the last N hours (default: Catalyst Center's latest)"
            ),
        ] = None,
        trend_interval: Annotated[
            Literal["5min", "10min", "1hour", "1day", "7day"] | None,
            Field(description="Also return each fabric site's health trend in buckets of this size"),
        ] = None,
    ) -> dict[str, Any]:
        """SD-Access health as Catalyst Center Assurance scores it. Returns the fabric summary (fabric sites,
        layer 3 and layer 2 VNs, transits and fabric devices with good/fair/poor counts, P1-P3 issues), each
        fabric site's good-health percentage and device counts with the dimensions that have fair or poor
        devices (control plane, LISP sessions, border to control plane, pub/sub, BGP, AAA, CTS environment
        data, port channels, ...), the same per virtual network and transit, and a one-line verdict. With
        trend_interval, each fabric site's score over time. Assurance lags a change by minutes: an empty or
        unscored fabric right after provisioning is not a failure."""
        app: CatcApp = get_client(ctx)
        params: dict[str, Any] = window(hours) if hours else {}
        if fabric_site:
            params["siteHierarchy"] = fabric_site.strip().rstrip("/")
        calls: dict[str, Any] = {
            "summary": app.api.get(f"{DATA}/fabricSummary", params),
            "sites": fetch_all(
                app.data_pager, app.api, f"{DATA}/fabricSiteHealthSummaries", params, cap=500, max_page=100
            ),
        }
        if "virtual_networks" in include:
            calls["vns"] = fetch_all(
                app.data_pager,
                app.api,
                f"{DATA}/virtualNetworkHealthSummaries",
                params,
                cap=1000,
                max_page=100,
            )
        if "transits" in include:
            tparams = {k: v for k, v in params.items() if k != "siteHierarchy"}
            calls["transits"] = fetch_all(
                app.data_pager,
                app.api,
                f"{DATA}/transitNetworkHealthSummaries",
                tparams,
                cap=500,
                max_page=100,
            )
        sec, errors = await gather_sections(calls)
        summary_rows = ensure_list(
            ((sec.get("summary") or {}).get("response") or {}).get("protocolSummaries")
        )
        summary = next((s for s in summary_rows if isinstance(s, dict)), {})
        sites = [
            entity(r, ["name", "id", "siteHierarchy", "associatedL3VnCount", "associatedL2VnCount"])
            for r in (sec["sites"].items if "sites" in sec else [])
            if isinstance(r, dict)
        ]
        out: dict[str, Any] = {
            "verdict": verdict(summary, sites),
            "summary": {k: v for k, v in summary.items() if v is not None},
            "fabric_sites": sites,
        }
        if "vns" in sec:
            out["virtual_networks"] = [entity(r, VN_FIELDS) for r in sec["vns"].items if isinstance(r, dict)]
        if "transits" in sec:
            out["transits"] = [
                entity(r, ["name", "id", "transitType", "fabricSitesCount", "controlPlaneCount"])
                for r in sec["transits"].items
                if isinstance(r, dict)
            ]
        if trend_interval and sites:
            tp: dict[str, Any] = {"trendInterval": TREND_INTERVALS[trend_interval], **window(hours or 24)}
            trends, more = await gather_sections(
                {
                    str(s["id"]): app.api.get(
                        f"{DATA}/fabricSiteHealthSummaries/{seg(str(s['id']))}/trendAnalytics", tp
                    )
                    for s in sites
                    if s.get("id")
                }
            )
            errors |= more
            for s in sites:
                body = trends.get(str(s.get("id")))
                rows = ensure_list(body.get("response")) if isinstance(body, dict) else []
                s["trend"] = [
                    {
                        "timestamp": b.get("timestamp"),
                        **{
                            a.get("name"): a.get("value")
                            for a in ensure_list(b.get("attributes"))
                            if isinstance(a, dict) and a.get("name") in TREND_ATTRS
                        },
                    }
                    for b in rows
                    if isinstance(b, dict)
                ]
        if errors:
            out["errors"] = errors
        return out
