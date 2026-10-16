"""Topology reads: physical, layer 3 (per routing protocol), VLAN / layer 2."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
from typing import Annotated, Any, Literal

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field

from catc_mcp._core import ResponseFormat, ToolRegistrar, get_client, object_result, text_result
from catc_mcp.client import CatcApp
from catc_mcp.common import ensure_list, pick, seg

NODE_FIELDS = [
    "label",
    "ip",
    "platformId",
    "role",
    "deviceType",
    "family",
    "softwareVersion",
    "nodeType",
    "id",
]
MAX_ROWS = 400


def summarise(topo: Any, *, device: str | None = None) -> dict[str, Any]:
    """Nodes with their key fields and links as 'A port <-> B port (status)', optionally restricted
    to the links touching one device (label or IP)."""
    topo = topo if isinstance(topo, dict) else {}
    nodes = [n for n in ensure_list(topo.get("nodes")) if isinstance(n, dict)]
    by_id = {n.get("id"): n for n in nodes}
    links_out = []
    for link in ensure_list(topo.get("links")):
        if not isinstance(link, dict):
            continue
        a, b = by_id.get(link.get("source"), {}), by_id.get(link.get("target"), {})
        row = {
            "a": a.get("label") or link.get("source"),
            "a_port": link.get("startPortName"),
            "b": b.get("label") or link.get("target"),
            "b_port": link.get("endPortName"),
            "status": link.get("linkStatus"),
        }
        for key in ("startPortIpv4Address", "endPortIpv4Address", "startPortSpeed"):
            if link.get(key):
                row[key] = link[key]
        links_out.append({k: v for k, v in row.items() if v not in (None, "")})
    if device:
        d = device.lower()
        keep = {
            n.get("id") for n in nodes if d in (str(n.get("label", "")).lower(), str(n.get("ip", "")).lower())
        }
        labels = {str(by_id[i].get("label")) for i in keep if i in by_id}
        links_out = [x for x in links_out if x.get("a") in labels or x.get("b") in labels]
        neighbours = {x.get("a") for x in links_out} | {x.get("b") for x in links_out}
        nodes = [n for n in nodes if n.get("label") in neighbours or n.get("id") in keep]
    out: dict[str, Any] = {
        "node_count": len(nodes),
        "link_count": len(links_out),
        "nodes": [pick(n, NODE_FIELDS) for n in nodes[:MAX_ROWS]],
        "links": links_out[:MAX_ROWS],
    }
    if len(nodes) > MAX_ROWS or len(links_out) > MAX_ROWS:
        out["note"] = f"Showing the first {MAX_ROWS} nodes/links; filter with `device`."
    return out


def as_markdown(title: str, s: dict[str, Any]) -> str:
    lines = [f"{title}: {s['node_count']} nodes, {s['link_count']} links", "", "Nodes:"]
    for n in s["nodes"]:
        lines.append(
            f"- {n.get('label')} {n.get('ip', '')} {n.get('platformId', '')} {n.get('role', '')}".rstrip()
        )
    lines += ["", "Links:"]
    for x in s["links"]:
        a = f"{x.get('a')} {x.get('a_port', '')}".strip()
        b = f"{x.get('b')} {x.get('b_port', '')}".strip()
        lines.append(f"- {a} <-> {b} ({x.get('status', '?')})")
    if s.get("note"):
        lines += ["", s["note"]]
    return "\n".join(lines)


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="Physical topology")
    async def catc_get_physical_topology(
        ctx: Context,
        device: Annotated[
            str | None, Field(description="Only show this device (label/hostname or IP) and its neighbours")
        ] = None,
        include_hosts: Annotated[
            bool, Field(description="Include end hosts as nodes (default false)")
        ] = False,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """Physical (CDP/LLDP-derived) topology: devices and the links between them with port names,
        link status and addresses. Pass `device` to see one device's neighbours."""
        app: CatcApp = get_client(ctx)
        params = None if include_hosts else {"nodeType": "device"}
        topo = await app.get_response("/dna/intent/api/v1/topology/physical-topology", params)
        s = summarise(topo, device=device)
        if response_format == "json":
            return object_result(s)
        return text_result(as_markdown("Physical topology", s))

    @reg.read(title="Layer 3 topology")
    async def catc_get_l3_topology(
        ctx: Context,
        protocol: Annotated[
            Literal["ospf", "eigrp", "isis", "static", "bgp"],
            Field(description="Routing protocol whose adjacencies to show"),
        ] = "ospf",
        device: Annotated[
            str | None, Field(description="Only this device (label or IP) and its peers")
        ] = None,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """Layer 3 topology for one routing protocol: routers and the adjacencies between them with
        interface names and addresses."""
        app: CatcApp = get_client(ctx)
        topo = await app.get_response(f"/dna/intent/api/v1/topology/l3/{protocol}")
        s = summarise(topo, device=device)
        if response_format == "json":
            return object_result(s)
        return text_result(as_markdown(f"L3 topology ({protocol.upper()})", s))

    @reg.read(title="VLAN topology")
    async def catc_get_vlan_topology(
        ctx: Context,
        vlan: Annotated[
            str | None,
            Field(description="VLAN name or id (as listed with no vlan given) whose L2 topology to show"),
        ] = None,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """Without `vlan`: the VLAN names Catalyst Center knows about. With `vlan`: the layer 2
        topology of that VLAN (switches carrying it and the trunk links between them)."""
        app: CatcApp = get_client(ctx)
        if not vlan:
            names = ensure_list(await app.get_response("/dna/intent/api/v1/topology/vlan/vlan-names"))
            return object_result({"vlans": names, "count": len(names)})
        topo = await app.get_response(f"/dna/intent/api/v1/topology/l2/{seg(vlan)}")
        s = summarise(topo)
        if response_format == "json":
            return object_result(s)
        return text_result(as_markdown(f"L2 topology for VLAN {vlan}", s))
