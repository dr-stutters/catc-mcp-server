"""SD-Access multi-site: anchored virtual networks (roadmap D105).

An anchored VN has its gateways and its way out at one fabric site (the anchor) and is extended to other
fabric sites over an SD-Access transit (LISP pub/sub or BGP between sites): guest and IoT networks keep one
gateway and one policy point across a campus. `PUT sda/layer3VirtualNetworks` assigns the sites and sets
`anchoredSiteId`; if anchoring fails, Catalyst Center keeps the site assignment (the 3.2.2 spec says so).
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
from typing import Annotated, Any

from fastmcp import Context
from pydantic import Field

from catc_mcp._core import Confirm, NotFound, Plan, ToolRegistrar, get_client, preview_or_apply
from catc_mcp.client import CatcApp
from catc_mcp.common import ensure_list
from catc_mcp.safety import device_limit_blockers
from catc_mcp.tools.sda import SDA, resolve_fabric, sda_job, sda_list

SDA_TRANSITS = ("SDA_LISP_PUB_SUB_TRANSIT", "SDA_LISP_BGP_TRANSIT")


def register(reg: ToolRegistrar) -> None:
    @reg.dangerous(title="Anchor virtual network", task=True)
    async def catc_anchor_virtual_network(
        ctx: Context,
        virtual_network: Annotated[str, Field(description="Layer 3 VN to anchor")],
        anchor_site: Annotated[
            str | None, Field(description="Fabric site that hosts the VN's gateways (site path or fabric id)")
        ] = None,
        fabric_sites: Annotated[
            list[str] | None,
            Field(description="Fabric sites the anchored VN extends to (added to the VN's current sites)"),
        ] = None,
        remove_anchor: Annotated[
            bool, Field(description="Stop anchoring the VN (it stays at its sites)")
        ] = False,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Anchor a layer 3 virtual network at one fabric site and extend it to others (multi-site SD-Access).
        The anchor hosts the VN's gateways and exit; the other sites reach it over an SD-Access transit (guest
        or IoT networks with one gateway across a campus). remove_anchor stops anchoring it. Catalyst Center
        pushes the VN to the fabric devices of the sites. Preview-first: refuses without an SD-Access transit
        and with fewer than two sites."""
        app: CatcApp = get_client(ctx)
        vn = next(
            (
                v
                for v in await sda_list(app, "layer3VirtualNetworks", {"virtualNetworkName": virtual_network})
                if v.get("virtualNetworkName") == virtual_network
            ),
            None,
        )
        if vn is None:
            raise NotFound(f"No layer 3 virtual network {virtual_network} (catc_create_virtual_network).")
        fids = [str(f) for f in ensure_list(vn.get("fabricIds"))]
        names: list[Any] = []
        for ref in fabric_sites or []:
            f, s = await resolve_fabric(app, ref)
            if str(f["id"]) not in fids:
                fids.append(str(f["id"]))
            names.append(s.get("nameHierarchy"))
        blockers: list[str] = []
        anchor_id: str | None = None
        anchor_name = None
        if remove_anchor:
            if anchor_site or fabric_sites:
                blockers.append("Give only virtual_network with remove_anchor.")
            if not vn.get("anchoredSiteId"):
                blockers.append(f"{virtual_network} is not anchored.")
        else:
            if not anchor_site:
                blockers.append("Give anchor_site (or remove_anchor).")
            else:
                af, asite = await resolve_fabric(app, anchor_site)
                anchor_id, anchor_name = str(af["id"]), asite.get("nameHierarchy")
                if anchor_id not in fids:
                    fids.append(anchor_id)
                if vn.get("anchoredSiteId") == anchor_id and not fabric_sites:
                    blockers.append(f"{virtual_network} is already anchored at {anchor_name}.")
            if len(fids) < 2:
                blockers.append("An anchored VN needs at least two fabric sites (the anchor and one more).")
            transits = [t for t in await sda_list(app, "transitNetworks") if t.get("type") in SDA_TRANSITS]
            if not transits:
                blockers.append(
                    "No SD-Access transit (LISP pub/sub or BGP) exists to join the sites "
                    "(catc_create_transit_network)."
                )
        body: dict[str, Any] = {
            "id": vn.get("id"),
            "virtualNetworkName": virtual_network,
            "fabricIds": sorted(fids),
        }
        if anchor_id:
            body["anchoredSiteId"] = anchor_id
        devices = [d for f in fids for d in await sda_list(app, "fabricDevices", {"fabricId": f})]
        blockers += device_limit_blockers(app, len(devices), "fabric devices")
        plan = Plan(
            f"Stop anchoring {virtual_network}"
            if remove_anchor
            else f"Anchor {virtual_network} at {anchor_name} across {len(fids)} fabric site(s)",
            details={
                "current": vn,
                "method": "PUT",
                "path": f"{SDA}/layer3VirtualNetworks",
                "body": [body],
                "sites_added": names or None,
            },
            side_effects=[
                f"Catalyst Center pushes the VN to {len(devices)} fabric device(s); if anchoring fails the "
                "site assignment still applies."
            ],
            fingerprint={"vn": vn},
            blockers=blockers,
            blast_radius=len(devices) or None,
        )

        async def apply() -> Any:
            job = await sda_job(
                app, "PUT", f"{SDA}/layer3VirtualNetworks", [body], ctx, "anchor virtual network"
            )
            now = [
                v
                for v in await sda_list(app, "layer3VirtualNetworks", {"virtualNetworkName": virtual_network})
                if v.get("virtualNetworkName") == virtual_network
            ]
            after = now[0] if now else {}
            anchored_at = after.get("anchoredSiteId") or None
            out: dict[str, Any] = {**job, "virtual_network": after or None, "anchored_at": anchored_at}
            # Read back: the PUT reports success even when only the site assignment applied.
            want = None if remove_anchor else anchor_id
            out["anchor_verified"] = anchored_at == want
            if not out["anchor_verified"]:
                why = (
                    "leaving anchoredSiteId out did not clear the anchor here (clear it in the GUI)"
                    if remove_anchor
                    else "the site assignment applied but the anchoring did not (check the transit)"
                )
                out["warning"] = (
                    f"Catalyst Center reports {virtual_network} anchored at {anchored_at or 'nothing'}, "
                    f"not {want or 'unanchored'}: {why}."
                )
            return out

        return await preview_or_apply(
            ctx,
            tool="catc_anchor_virtual_network",
            args={
                "virtual_network": virtual_network,
                "anchor_site": anchor_site,
                "fabric_sites": fabric_sites,
                "remove_anchor": remove_anchor,
            },
            confirm=confirm,
            plan=plan,
            apply=apply,
        )
