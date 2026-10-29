"""Site inventory (roadmap D61), read-only: what is at a site, what is not assigned yet, and how it is wired.

`catc_site_inventory(site)` answers "what is at this site, and what is not assigned to any site yet" in one
call:
- the members of the site and every site below it (GET /dna/intent/api/v1/membership/{siteId}): the child
  sites (areas, buildings, floors) and the devices assigned to each, grouped by device family and role, with
  management IP, platform, software version and reachability;
- the site tree with addresses (GET /dna/intent/api/v1/topology/site-topology, filtered to the site);
- devices in the inventory that are not assigned to any site (GET .../networkDevices/notAssignedToSite and
  .../notAssignedToSite/count), with their hostname, address, family and role;
- the site's links (GET /dna/intent/api/v1/topology/physical-topology, devices only): links between two of
  the site's devices, and uplinks from a site device to a device outside the site.

`format='mermaid'` or `'drawio'` draws the site (devices grouped by floor, labelled with role, management IP
and version; links labelled with ports and speed) through core's shared renderer, the one cml_export_topology
uses.

Shapes recorded on the 3.2.2 lab appliance (2026-10-29): membership answers {"site": {"response": [every
descendant site, with "System Settings" member.count.total]}, "device": [{"siteId", "response": [network
device records with instanceUuid instead of id]}]}, one `device` entry per site in the subtree (the site
itself and each descendant), an empty `response` plus a "doesn't not have device member" message for a site
without devices; notAssignedToSite answers {"response": {"siteId": null, "deviceIds": [...]}}, 1-based offset,
500 per page; site-topology answers {"response": {"sites": [...]}} for the whole hierarchy (no links); the
physical topology's device node ids are the network device ids.
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
from collections import Counter
from typing import Annotated, Any, Literal

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field

from catc_mcp._core import ToolRegistrar, get_client, object_result, text_result
from catc_mcp._core.render import Edge, Graph, Node, diagram_result, short_if
from catc_mcp.client import CatcApp, safe_id
from catc_mcp.common import ensure_list, gather_sections, resolve_site
from catc_mcp.safety import devices_by_id

MEMBERSHIP = "/dna/intent/api/v1/membership/{}"
NOT_ASSIGNED = "/dna/intent/api/v1/networkDevices/notAssignedToSite"
SITE_TOPOLOGY = "/dna/intent/api/v1/topology/site-topology"
PHYSICAL = "/dna/intent/api/v1/topology/physical-topology"
PAGE = 500  # notAssignedToSite: at most 500 per page
UNASSIGNED_CAP = 2000  # unassigned device ids read
UNASSIGNED_LISTED = 200  # unassigned devices resolved to names and shown
MAX_LINKS = 400

Format = Literal["markdown", "json", "mermaid", "drawio"]

# Device family -> diagram shape (the families Catalyst Center reports).
SHAPES = {
    "Routers": "round",
    "Wireless Controller": "hexagon",
    "Unified AP": "circle",
    "Switches and Hubs": "box",
}


def as_dict(v: Any) -> dict[str, Any]:
    return v if isinstance(v, dict) else {}


def device_id(d: dict[str, Any]) -> str:
    return str(d.get("id") or d.get("instanceUuid") or "")


def device_row(d: dict[str, Any], site: str | None = None) -> dict[str, Any]:
    row = {
        "hostname": d.get("hostname"),
        "ip": d.get("managementIpAddress"),
        "family": d.get("family"),
        "role": d.get("role"),
        "platform": d.get("platformId"),
        "version": d.get("softwareVersion"),
        "reachability": d.get("reachabilityStatus"),
        "serial": d.get("serialNumber"),
        "site": site,
        "id": device_id(d) or None,
    }
    return {k: v for k, v in row.items() if v not in (None, "")}


def site_type(rec: dict[str, Any]) -> str | None:
    """A site's type from a site-topology record (locationType) or a membership record (Location type)."""
    if rec.get("locationType"):
        return str(rec["locationType"])
    for info in ensure_list(rec.get("additionalInfo")):
        if isinstance(info, dict) and info.get("nameSpace") == "Location":
            t = as_dict(info.get("attributes")).get("type")
            return str(t) if t else None
    return None


async def unassigned_ids(app: CatcApp) -> tuple[list[str], bool]:
    """Device ids not assigned to any site (1-based pages of 500), and whether the list is complete."""
    ids: list[str] = []
    offset = 1
    while len(ids) < UNASSIGNED_CAP:
        resp = await app.api.get(NOT_ASSIGNED, {"offset": offset, "limit": PAGE})
        inner = as_dict(as_dict(resp).get("response"))
        chunk = [str(i) for i in ensure_list(inner.get("deviceIds")) if i]
        ids += chunk
        if len(chunk) < PAGE:
            return ids, True
        offset += PAGE
    return ids[:UNASSIGNED_CAP], False


def site_links(
    topo: Any, members: dict[str, dict[str, Any]], site_of: dict[str, str]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, dict[str, Any]]]:
    """Physical links touching the site's devices: (internal links, uplinks to devices outside the site,
    {node id: outside node})."""
    topo = as_dict(topo)
    nodes = {str(n.get("id")): n for n in ensure_list(topo.get("nodes")) if isinstance(n, dict)}
    internal: list[dict[str, Any]] = []
    uplinks: list[dict[str, Any]] = []
    outside: dict[str, dict[str, Any]] = {}
    seen: set[tuple[str, str, str, str]] = set()
    for link in ensure_list(topo.get("links")):
        if not isinstance(link, dict):
            continue
        a, b = str(link.get("source")), str(link.get("target"))
        a_port, b_port = str(link.get("startPortName") or ""), str(link.get("endPortName") or "")
        if a not in members and b in members:  # site device first
            a, b, a_port, b_port = b, a, b_port, a_port
        if a not in members:
            continue
        key = (a, a_port, b, b_port) if a <= b else (b, b_port, a, a_port)
        if key in seen:
            continue
        seen.add(key)
        other = members.get(b) or nodes.get(b) or {}
        row = {
            "a": members[a].get("hostname") or a,
            "a_port": a_port,
            "b": other.get("hostname") or other.get("label") or b,
            "b_port": b_port,
            "status": link.get("linkStatus"),
            "speed": link.get("startPortSpeed") or link.get("endPortSpeed"),
            "_a": a,
            "_b": b,
        }
        if b in members:
            internal.append(row)
        else:
            if b in nodes:
                outside[b] = nodes[b]
            uplinks.append(row)
    return internal, uplinks, outside


def public(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [{k: v for k, v in r.items() if not k.startswith("_") and v not in (None, "")} for r in rows]


def speed_text(v: Any) -> str:
    """Catalyst Center reports port speed in kbit/s ('1000000' = 1G)."""
    try:
        kbps = int(str(v))
    except (TypeError, ValueError):
        return str(v) if v else ""
    if kbps >= 1_000_000 and kbps % 1_000_000 == 0:
        return f"{kbps // 1_000_000}G"
    if kbps >= 1000 and kbps % 1000 == 0:
        return f"{kbps // 1000}M"
    return f"{kbps}k"


def link_status(v: Any) -> Literal["ok", "down"] | None:
    s = str(v or "").lower()
    if s == "up":
        return "ok"
    if s in ("down", "deleted"):
        return "down"
    return None


def to_graph(
    title: str,
    root: str,
    devices: list[dict[str, Any]],
    site_of: dict[str, str],
    links: list[dict[str, Any]],
    outside: dict[str, dict[str, Any]],
) -> Graph:
    g = Graph(title=title, direction="TB")
    for d in devices:
        did = device_id(d)
        site = site_of.get(did, root)
        reach = str(d.get("reachabilityStatus") or "").lower()
        g.nodes.append(
            Node(
                id=did,
                label=str(d.get("hostname") or d.get("managementIpAddress") or did),
                lines=[
                    str(x)
                    for x in (d.get("role"), d.get("managementIpAddress"), d.get("softwareVersion"))
                    if x not in (None, "")
                ],
                shape=SHAPES.get(str(d.get("family")), "box"),  # type: ignore[arg-type]
                group=site.removeprefix(root.rsplit("/", 1)[0] + "/") if "/" in root else site,
                status="ok" if reach == "reachable" else ("down" if reach == "unreachable" else "unknown"),
            )
        )
    for oid, n in outside.items():
        g.nodes.append(
            Node(
                id=oid,
                label=str(n.get("label") or n.get("ip") or oid),
                lines=[str(x) for x in (n.get("role"), n.get("ip")) if x not in (None, "")],
                group="outside the site",
                status="unknown",
            )
        )
    known = {n.id for n in g.nodes}
    for x in links:
        if x["_a"] not in known or x["_b"] not in known:
            continue
        ports = " - ".join(p for p in (short_if(x.get("a_port") or ""), short_if(x.get("b_port") or "")) if p)
        label = " ".join(p for p in (ports, speed_text(x.get("speed"))) if p)
        g.edges.append(Edge(x["_a"], x["_b"], label=label, status=link_status(x.get("status"))))
    if not devices:
        g.notes.append("No devices are assigned to this site or the sites below it.")
    return g


def link_line(x: dict[str, Any]) -> str:
    a = f"{x['a']} {x.get('a_port', '')}".strip()
    b = f"{x['b']} {x.get('b_port', '')}".strip()
    return f"- {a} <-> {b} ({x.get('status', '?')})"


def as_markdown(out: dict[str, Any]) -> str:
    site = out["site"]
    lines = [f"Site inventory: {site['name']} ({site.get('type') or 'site'})", ""]
    sites = out.get("sites") or []
    if sites:
        by_type = Counter(str(s.get("type") or "?") for s in sites)
        lines.append(
            "Sites below it: "
            + ", ".join(f"{n} {t}{'s' if n != 1 else ''}" for t, n in sorted(by_type.items()))
        )
        for s in sites:
            lines.append(f"- {s['name']} ({s.get('type') or '?'}): {s.get('devices', 0)} devices")
        lines.append("")
    members = out.get("members") or {}
    lines.append(f"Devices: {members.get('device_count', 0)}")
    for fam, n in (members.get("by_family") or {}).items():
        lines.append(f"- {fam}: {n}")
    if members.get("by_role"):
        lines.append("By role: " + ", ".join(f"{r} {n}" for r, n in members["by_role"].items()))
    for d in out.get("devices") or []:
        lines.append(
            f"- {d.get('hostname')} {d.get('ip', '')} {d.get('role', '')} {d.get('platform', '')} "
            f"{d.get('version', '')} {d.get('reachability', '')} [{d.get('site', '')}]".replace("  ", " ")
        )
    lines.append("")
    if "physical_links" in out:
        lk = out["physical_links"]
        lines.append(f"Links inside the site: {len(lk['internal'])}")
        for x in lk["internal"]:
            lines.append(link_line(x))
        lines.append(f"Uplinks to devices outside the site: {len(lk['uplinks'])}")
        for x in lk["uplinks"]:
            lines.append(link_line(x))
        lines.append("")
    if "unassigned" in out:
        un = out["unassigned"]
        lines.append(f"Devices not assigned to any site: {un.get('count', 0)}")
        for d in un.get("devices") or []:
            lines.append(
                f"- {d.get('hostname') or d.get('id')} {d.get('ip', '')} {d.get('family', '')}".rstrip()
            )
        if un.get("note"):
            lines.append(un["note"])
        lines.append("")
    for n in out.get("notes") or []:
        lines.append(f"Note: {n}")
    if out.get("unavailable"):
        lines.append("Unavailable: " + "; ".join(f"{k}: {v}" for k, v in out["unavailable"].items()))
    return "\n".join(lines).rstrip() + "\n"


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="Site inventory")
    async def catc_site_inventory(
        ctx: Context,
        site: Annotated[
            str, Field(description="Site id, name hierarchy ('Global/AU/SYD-1') or unique site name")
        ],
        include_unassigned: Annotated[
            bool, Field(description="Also list the devices not assigned to any site (default true)")
        ] = True,
        include_links: Annotated[
            bool, Field(description="Also read the physical topology for the site's links (default true)")
        ] = True,
        format: Annotated[
            Format,
            Field(
                description="markdown (default), json, or a diagram: mermaid (fenced, for chat) or drawio "
                "(a .drawio file for diagrams.net)"
            ),
        ] = "markdown",
    ) -> ToolResult:
        """What is at a site, in one read: the sites below it (areas, buildings, floors) and the devices
        assigned to the site or any site below it, grouped by family and role, each with management IP,
        platform, software version, reachability and the floor or building it is on; the devices in the
        inventory not assigned to any site yet; and the site's physical links (between its own devices, and
        uplinks to devices outside it). format='mermaid' or 'drawio' draws the site: devices grouped by
        floor, labelled with role, management IP and version, links with ports and speed. Read-only;
        catc_assign_devices_to_site assigns the unassigned devices."""
        app: CatcApp = get_client(ctx)
        s = await resolve_site(app, site)
        sid = str(s["id"])
        root = str(s.get("nameHierarchy") or s.get("name") or sid)
        sections: dict[str, Any] = {
            "membership": app.api.get(MEMBERSHIP.format(safe_id(sid))),
            "site_topology": app.get_response(SITE_TOPOLOGY),
        }
        if include_unassigned:
            sections["unassigned"] = unassigned_ids(app)
            sections["unassigned_count"] = app.get_response(f"{NOT_ASSIGNED}/count")
        if include_links:
            sections["physical"] = app.get_response(PHYSICAL, {"nodeType": "device"})
        data, errors = await gather_sections(sections)
        notes: list[str] = []

        # The site tree: site-topology (name, type, address), else membership's site records.
        member = as_dict(data.get("membership"))
        msites = [r for r in ensure_list(as_dict(member.get("site")).get("response")) if isinstance(r, dict)]
        name_of: dict[str, str] = {sid: root}
        tree: list[dict[str, Any]] = []
        topo_sites = ensure_list(as_dict(data.get("site_topology")).get("sites"))
        prefix = root + "/"
        for r in topo_sites or msites:
            if not isinstance(r, dict):
                continue
            path = str(r.get("groupNameHierarchy") or "")
            if not path.startswith(prefix):
                continue
            name_of[str(r.get("id"))] = path
            row: dict[str, Any] = {"name": path, "type": site_type(r)}
            if r.get("locationAddress"):
                row["address"] = r["locationAddress"]
            tree.append(row)
        for r in msites:  # membership names sites site-topology may not have
            name_of.setdefault(str(r.get("id")), str(r.get("groupNameHierarchy") or r.get("id")))
        tree.sort(key=lambda r: r["name"].lower())

        devices: list[dict[str, Any]] = []
        site_of: dict[str, str] = {}
        for entry in ensure_list(member.get("device")):
            if not isinstance(entry, dict):
                continue
            where = name_of.get(str(entry.get("siteId")), str(entry.get("siteId")))
            for d in ensure_list(entry.get("response")):
                if isinstance(d, dict) and device_id(d) and device_id(d) not in site_of:
                    site_of[device_id(d)] = where
                    devices.append(d)
        devices.sort(key=lambda d: (site_of[device_id(d)].lower(), str(d.get("hostname") or "").lower()))
        per_site = Counter(site_of.values())
        for row in tree:
            row["devices"] = per_site.get(row["name"], 0)

        out: dict[str, Any] = {
            "site": {"name": root, "type": s.get("type"), "id": sid, "devices_here": per_site.get(root, 0)},
            "sites": tree,
            "members": {
                "device_count": len(devices),
                "by_family": dict(Counter(str(d.get("family") or "?") for d in devices).most_common()),
                "by_role": dict(Counter(str(d.get("role") or "?") for d in devices).most_common()),
                "by_site": dict(per_site),
            },
            "devices": [device_row(d, site_of[device_id(d)]) for d in devices],
        }
        if not devices and "membership" in data:
            notes.append("No devices are assigned to this site or the sites below it.")

        links: list[dict[str, Any]] = []
        outside: dict[str, dict[str, Any]] = {}
        if "physical" in data:
            members = {device_id(d): d for d in devices}
            internal, uplinks, outside = site_links(data["physical"], members, site_of)
            links = internal + uplinks
            out["physical_links"] = {
                "internal": public(internal[:MAX_LINKS]),
                "uplinks": public(uplinks[:MAX_LINKS]),
            }
            if len(internal) > MAX_LINKS or len(uplinks) > MAX_LINKS:
                notes.append(f"Showing the first {MAX_LINKS} links of each kind.")

        if include_unassigned and "unassigned" in data:
            ids, complete = data["unassigned"]
            cnt = as_dict(data.get("unassigned_count")).get("count")
            un: dict[str, Any] = {"count": cnt if isinstance(cnt, int) else len(ids)}
            listed = sorted(set(ids))[:UNASSIGNED_LISTED]
            found: dict[str, dict[str, Any]] = {}
            if listed:
                looked, lerr = await gather_sections({"lookup": devices_by_id(app, listed)})
                found = {device_id(d): d for d in looked.get("lookup") or []}
                if lerr:
                    errors.update({"unassigned_lookup": lerr["lookup"]})
            un["devices"] = [
                {k: v for k, v in device_row(found[i]).items() if k != "site"} if i in found else {"id": i}
                for i in listed
            ]
            if not complete or un["count"] > len(listed):
                un["note"] = f"Showing {len(listed)} of {un['count']} unassigned devices."
            out["unassigned"] = un

        if notes:
            out["notes"] = notes
        if errors:
            out["unavailable"] = errors
        if format in ("mermaid", "drawio"):
            graph = to_graph(f"Site {root}", root, devices, site_of, links, outside)
            return diagram_result(graph, format, host="catc-mcp-server")
        if format == "json":
            return object_result(out)
        return text_result(as_markdown(out))
