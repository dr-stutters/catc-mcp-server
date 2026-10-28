"""Inventory Insight link mismatches (roadmap D119), read-only.

Catalyst Center compares the two ends of every link it learned from CDP/LLDP and lists the links whose ends
disagree on speed/duplex, or on native VLAN / allowed VLANs (Inventory > Inventory Insights in the GUI). These
cause silent errors: CRC and late collisions on a duplex mismatch, spanning-tree surprises and VLAN leaking on
a native VLAN mismatch, 'works from one side' tickets on an allowed-list mismatch.

GET /dna/intent/api/v1/network-device/insight/{siteId}/device-link takes a required `category`
(speed-duplex | vlan), a 1-based offset and limit <= 500 (checked live on 3.2.2, 2026-10-28: without
`category` it answers 400; a site covers the sites below it; offset=2&limit=1 returns the second row).
The answer only covers what inventory collection read, so an empty list is never reported as clean on its own:
the tool says how many of the site's devices are not fully collected.
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
from typing import Annotated, Any, Literal

from fastmcp import Context
from pydantic import Field

from catc_mcp._core import ToolRegistrar, get_client
from catc_mcp._core.http import fetch_all
from catc_mcp.client import CatcApp
from catc_mcp.common import resolve_site, seg
from catc_mcp.safety import TargetsTruncated, site_devices

PATH = "/dna/intent/api/v1/network-device/insight/{site_id}/device-link"
CAP = 2000  # rows per category; 4 pages of 500
CATEGORIES: dict[str, tuple[str, ...]] = {
    "speed-duplex": ("Speed", "Duplex"),
    "vlan": ("NativeVlanId", "AllowedVlanIds"),
}
LABELS = {
    "Speed": "speed",
    "Duplex": "duplex",
    "NativeVlanId": "native_vlan",
    "AllowedVlanIds": "allowed_vlans",
}
HINTS = {
    "speed": (
        "Set both ends to the same speed (auto/auto on both, or the same fixed speed on both: a fixed end "
        "facing an auto end negotiates badly)."
    ),
    "duplex": (
        "A duplex mismatch shows as late collisions and CRC errors on the full-duplex end: set both ends "
        "to auto, or the same fixed duplex."
    ),
    "native_vlan": (
        "Native VLAN differs: untagged traffic crosses between two VLANs and CDP logs 'native VLAN "
        "mismatch'. Set 'switchport trunk native vlan <id>' to the same value on both ends (a template: "
        "catc_create_template -> catc_preview_template -> catc_deploy_template)."
    ),
    "allowed_vlans": (
        "Allowed VLAN lists differ: a VLAN allowed on one end only is dropped on the link. Make "
        "'switchport trunk allowed vlan' match on both ends with a template; 'none' or an empty list on one "
        "end usually means that end is not a trunk (access or routed port) while the other is."
    ),
}
COLLECTED = "managed"


def fmt_speed(raw: Any) -> str | None:
    """Speed as Catalyst Center gives it (kbit/s, '1000000') -> '1 Gbps'; anything else unchanged."""
    if raw in (None, ""):
        return None
    try:
        kbps = int(str(raw))
    except ValueError:
        return str(raw)
    if kbps >= 1_000_000 and kbps % 1_000_000 == 0:
        return f"{kbps // 1_000_000} Gbps"
    if kbps >= 1000 and kbps % 1000 == 0:
        return f"{kbps // 1000} Mbps"
    return f"{kbps} kbps"


def _value(row: dict[str, Any], side: str, field: str) -> Any:
    v = row.get(f"{side}Port{field}")
    return fmt_speed(v) if field == "Speed" else v


def _norm(v: Any) -> str:
    return str(v if v is not None else "").strip().lower().replace(" ", "")


def summarise(row: dict[str, Any], category: str) -> dict[str, Any]:
    """One mismatch: both ends, the compared values per end and which of them differ, with a fix hint."""
    fields = CATEGORIES[category]
    a: dict[str, Any] = {
        "device": row.get("startDeviceHostName"),
        "ip": row.get("startDeviceIpAddress"),
        "interface": row.get("startPortName"),
    }
    b: dict[str, Any] = {
        "device": row.get("endDeviceHostName"),
        "ip": row.get("endDeviceIpAddress"),
        "interface": row.get("endPortName"),
    }
    differs = []
    for f in fields:
        av, bv = _value(row, "start", f), _value(row, "end", f)
        a[LABELS[f]], b[LABELS[f]] = av, bv
        if _norm(av) != _norm(bv):
            differs.append(LABELS[f])
    # Catalyst Center flagged the link: when the values it returned look equal (it compares more than it
    # returns, e.g. 'auto' vs a negotiated speed), keep every field of the category in the hint.
    hint_keys = differs or [LABELS[f] for f in fields]
    out: dict[str, Any] = {
        "category": category,
        "a": {k: v for k, v in a.items() if v not in (None, "")},
        "b": {k: v for k, v in b.items() if v not in (None, "")},
        "mismatch": differs or ["(Catalyst Center flagged it; the values it returned look equal)"],
        "fix": " ".join(HINTS[k] for k in hint_keys),
        "link_status": row.get("linkStatus"),
    }
    if row.get("lastUpdated"):
        out["last_updated"] = row["lastUpdated"]
    return {k: v for k, v in out.items() if v not in (None, "")}


def line(m: dict[str, Any]) -> str:
    """'A Gi1/0/5 <-> B Gi1/0/5: native_vlan 1 vs 20' as one finding line (for reports)."""
    a, b = m.get("a", {}), m.get("b", {})
    diffs = [f"{k} {a.get(k, '-')} vs {b.get(k, '-')}" for k in m.get("mismatch", []) if k in LABELS.values()]
    what = "; ".join(diffs) or m["category"]
    return f"{a.get('device')} {a.get('interface')} <-> {b.get('device')} {b.get('interface')}: {what}"


async def collection_gaps(app: CatcApp, site: dict[str, Any]) -> dict[str, Any]:
    """How much of the site inventory collection actually read: devices whose collection status isn't
    Managed (or that are unreachable) were not compared."""
    try:
        devices = await site_devices(app, site)
    except TargetsTruncated:
        return {"note": "The site has more devices than one read covers: collection status not checked."}
    bad = [
        {
            "device": d.get("hostname") or d.get("managementIpAddress"),
            "collection_status": d.get("collectionStatus"),
            "reachability": d.get("reachabilityStatus"),
        }
        for d in devices
        if str(d.get("collectionStatus", "")).lower() != COLLECTED
        or str(d.get("reachabilityStatus", "")).lower() not in ("reachable", "")
    ]
    out: dict[str, Any] = {"devices": len(devices), "not_fully_collected": len(bad)}
    if bad:
        out["devices_not_collected"] = bad[:50]
    return out


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="Link mismatches (speed/duplex, VLAN)")
    async def catc_link_mismatch(
        ctx: Context,
        site: Annotated[
            str,
            Field(description="Site path ('Global/AU/SYD-1'), unique name or id; covers the sites below it"),
        ],
        category: Annotated[
            Literal["speed-duplex", "vlan", "both"],
            Field(description="speed-duplex, vlan (native VLAN and allowed VLANs) or both"),
        ] = "both",
    ) -> dict[str, Any]:
        """Links whose two ends disagree, from Catalyst Center's Inventory Insight: speed/duplex mismatches
        and native VLAN / allowed VLAN mismatches at a site (and the sites below it). Each row gives both ends
        (device, IP, interface), the values per end, which ones differ and a fix hint; `findings` has one line
        per link for reports. The check only covers what inventory collection read, so an empty result also
        says how many of the site's devices are not fully collected: it never claims a clean site on its own.
        Read-only; refresh after a change with catc_resync_devices."""
        app: CatcApp = get_client(ctx)
        s = await resolve_site(app, site)
        cats = list(CATEGORIES) if category == "both" else [category]
        mismatches: list[dict[str, Any]] = []
        partial: list[str] = []
        for c in cats:
            page = await fetch_all(
                app.pager, app.api, PATH.format(site_id=seg(str(s["id"]))), {"category": c}, cap=CAP
            )
            if not page.complete:
                partial.append(c)
            mismatches += [summarise(r, c) for r in page.items if isinstance(r, dict)]
        mismatches.sort(
            key=lambda m: (str(m["a"].get("device")), str(m["a"].get("interface")), m["category"])
        )
        out: dict[str, Any] = {
            "site": s.get("nameHierarchy"),
            "categories": cats,
            "count": len(mismatches),
            "findings": [line(m) for m in mismatches],
            "mismatches": mismatches,
        }
        if partial:
            out["truncated"] = f"More than {CAP} {', '.join(partial)} mismatches: showing the first {CAP}."
        if not mismatches:
            gaps = await collection_gaps(app, s)
            out["collection"] = gaps
            if "devices" in gaps:
                out["note"] = (
                    f"No mismatches found by Catalyst Center ({gaps['not_fully_collected']} of "
                    f"{gaps['devices']} devices at the site are not fully collected"
                    + (", so their links were not compared" if gaps["not_fully_collected"] else "")
                    + "). Insight is computed from the last inventory collection: run catc_resync_devices "
                    "after a change."
                )
            else:
                out["note"] = "No mismatches found by Catalyst Center. " + gaps["note"]
        return out
