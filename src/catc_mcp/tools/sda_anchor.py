"""SD-Access multi-site: anchored virtual networks (roadmap D105).

An anchored VN has its gateways and its way out at one fabric site (the anchor) and is extended to other
fabric sites over an SD-Access transit (LISP pub/sub or BGP between sites): guest and IoT networks keep one
gateway and one policy point across a campus.

What Catalyst Center 3.2.2 accepts (live 2026-10-22, labs mcp-catc-fabric and mcp-catc-fabric2, #190):
- A VN is anchored only in the request that creates it: `POST sda/layer3VirtualNetworks` with the anchor site
  alone and `anchoredSiteId`. Anchoring an existing VN with a PUT fails task validation with NCSO20386, and a
  PUT naming the anchor and other sites at once with NCHS20464 ("each VN could only be anchored to one site").
- A later `PUT sda/layer3VirtualNetworks` that keeps `anchoredSiteId` extends it to the other sites. If the
  anchoring part of a PUT fails, the site assignment still applies (the spec says so): the tool reads it back.
- Nothing reaches the devices until the VN has an anycast gateway. A gateway at the anchor gave the anchor
  site's devices the VRF but not the remote site's; those got it (VRF, SVI, the anchor's LISP instance id and
  a LISP session to the anchor's control plane) once the remote site had its own anycast gateway for the
  anchor's pool, which is reserved at the anchor site only (catc_add_anycast_gateway looks it up there).
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import contextlib
import re
from typing import Annotated, Any

from fastmcp import Context
from pydantic import Field

from catc_mcp._core import Confirm, NotFound, Plan, ToolRegistrar, get_client, preview_or_apply
from catc_mcp.client import CatcApp
from catc_mcp.common import ensure_list
from catc_mcp.safety import device_limit_blockers
from catc_mcp.tools.sda import SDA, resolve_fabric, sda_job, sda_list

SDA_TRANSITS = ("SDA_LISP_PUB_SUB_TRANSIT", "SDA_LISP_BGP_TRANSIT")
VNS = f"{SDA}/layer3VirtualNetworks"
VN_NAME = re.compile(r"^[A-Za-z0-9_-]{1,16}$")  # catc_create_virtual_network's rule
NEW_ID = "(the new VN's id)"
NOT_AT_CREATION = (
    "Catalyst Center 3.2.2 anchors a VN only in the request that creates it: anchoring an existing VN fails "
    "task validation with NCSO20386 (live 2026-10-22)"
)


async def find_vn(app: CatcApp, name: str) -> dict[str, Any] | None:
    return next(
        (
            v
            for v in await sda_list(app, "layer3VirtualNetworks", {"virtualNetworkName": name})
            if v.get("virtualNetworkName") == name
        ),
        None,
    )


def register(reg: ToolRegistrar) -> None:
    @reg.dangerous(title="Anchor virtual network", task=True)
    async def catc_anchor_virtual_network(
        ctx: Context,
        virtual_network: Annotated[
            str, Field(description="Layer 3 VN to create anchored, or an anchored VN to extend")
        ],
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
        """Create a layer 3 virtual network anchored at one fabric site and extend it to others (multi-site
        SD-Access), extend an anchored VN to more sites, or stop anchoring one (remove_anchor). The anchor
        hosts the VN's gateways and exit; the other sites reach it over an SD-Access transit (guest or IoT
        networks with one gateway across a campus). 3.2.2 anchors a VN only when it creates it, so a VN
        that doesn't exist yet is created at the anchor site alone with the anchor (POST), then extended to
        the other sites (PUT); an existing VN that isn't anchored is refused (NCSO20386): anchor a new VN
        instead. The VN reaches a site's devices only once that site has an anycast gateway:
        catc_add_anycast_gateway at the anchor, then at each remote site with the anchor's pool (a gateway
        at the anchor alone left the remote devices without the VRF, #190). Preview-first: refuses without
        an SD-Access transit and with fewer than two sites."""
        app: CatcApp = get_client(ctx)
        vn = await find_vn(app, virtual_network)
        if vn is None and remove_anchor:
            raise NotFound(f"No layer 3 virtual network {virtual_network}.")
        create = vn is None
        have = [] if vn is None else [str(f) for f in ensure_list(vn.get("fabricIds"))]
        fids = list(have)
        names: list[Any] = []
        for ref in fabric_sites or []:
            f, s = await resolve_fabric(app, ref)
            if str(f["id"]) not in fids:
                fids.append(str(f["id"]))
            names.append(s.get("nameHierarchy"))
        anchored = None if vn is None else (vn.get("anchoredSiteId") or None)
        blockers: list[str] = []
        anchor_id: str | None = None
        anchor_name = None
        if remove_anchor:
            if anchor_site or fabric_sites:
                blockers.append("Give only virtual_network with remove_anchor.")
            if not anchored:
                blockers.append(f"{virtual_network} is not anchored.")
        else:
            if not anchor_site:
                blockers.append("Give anchor_site (or remove_anchor).")
            else:
                af, asite = await resolve_fabric(app, anchor_site)
                anchor_id, anchor_name = str(af["id"]), asite.get("nameHierarchy")
                if anchor_id not in fids:
                    fids.insert(0, anchor_id)
                if create:
                    if not VN_NAME.match(virtual_network):
                        blockers.append(
                            f"{virtual_network!r} can't be a VN name: 1-16 letters, digits, '_' or '-'."
                        )
                elif not anchored:
                    blockers.append(
                        f"{virtual_network} already exists and is not anchored. {NOT_AT_CREATION}. "
                        "Anchor a new VN instead: give a name that doesn't exist yet and this tool creates "
                        "it anchored."
                    )
                elif anchored != anchor_id:
                    where: Any = anchored
                    with contextlib.suppress(NotFound):
                        where = (await resolve_fabric(app, anchored))[1].get("nameHierarchy")
                    blockers.append(
                        f"{virtual_network} is anchored at {where}. {NOT_AT_CREATION}, so its anchor can't "
                        f"move: anchor a new VN at {anchor_name}."
                    )
                elif set(fids) == set(have):
                    blockers.append(
                        f"{virtual_network} is already anchored at {anchor_name} and on those sites."
                    )
            if len(fids) < 2:
                blockers.append("An anchored VN needs at least two fabric sites (the anchor and one more).")
            transits = [t for t in await sda_list(app, "transitNetworks") if t.get("type") in SDA_TRANSITS]
            if not transits:
                blockers.append(
                    "No SD-Access transit (LISP pub/sub or BGP) exists to join the sites "
                    "(catc_create_transit_network)."
                )
        update: dict[str, Any] = {
            "id": NEW_ID if vn is None else vn.get("id"),
            "virtualNetworkName": virtual_network,
            "fabricIds": sorted(fids),
        }
        if anchor_id:
            update["anchoredSiteId"] = anchor_id
        requests: list[tuple[str, dict[str, Any]]] = [("PUT", update)]
        if create and anchor_id:
            # Created with the anchor site alone (a PUT that anchors with several sites: NCHS20464), then
            # extended with a PUT that keeps the anchor.
            first = {
                "virtualNetworkName": virtual_network,
                "fabricIds": [anchor_id],
                "anchoredSiteId": anchor_id,
            }
            requests = [("POST", first), ("PUT", update)]
        devices = [d for f in fids for d in await sda_list(app, "fabricDevices", {"fabricId": f})]
        blockers += device_limit_blockers(app, len(devices), "fabric devices")
        if remove_anchor:
            action = f"Stop anchoring {virtual_network}"
        elif create:
            at = anchor_name or "(no anchor site)"
            action = f"Create {virtual_network} anchored at {at} across {len(fids)} fabric site(s)"
        else:
            action = f"Extend {virtual_network}, anchored at {anchor_name}, to {len(fids)} fabric site(s)"
        plan = Plan(
            action,
            details={
                "current": vn,
                "path": VNS,
                "requests": [{"method": m, "body": [b]} for m, b in requests],
                "sites_added": names or None,
            },
            side_effects=[
                f"No device changes yet ({len(devices)} fabric device(s) at its sites): a site's devices get "
                "the VN with its first anycast gateway there (catc_add_anycast_gateway).",
                "Each remote site needs its own anycast gateway for the anchor's pool (reserved at the "
                "anchor site only) before its devices get the VN; its edges register with the anchor's "
                "control plane.",
                "If the anchoring part of a PUT fails, the site assignment still applies (read back: "
                "anchor_verified).",
            ],
            fingerprint={"vn": vn},
            blockers=blockers,
            blast_radius=len(devices) or None,
        )

        async def apply() -> Any:
            job: dict[str, Any] = {}
            n = len(requests)
            for i, (method, body) in enumerate(requests, 1):
                step = "anchor virtual network" + (f" ({i}/{n})" if n > 1 else "")
                if body.get("id") == NEW_ID:
                    made = await find_vn(app, virtual_network)
                    if made is None or made.get("anchoredSiteId") != anchor_id:
                        # Don't extend a VN that came back unanchored: it would be an ordinary multi-site VN.
                        got = (made or {}).get("anchoredSiteId") or "nothing"
                        return {
                            **job,
                            "virtual_network": made,
                            "anchored_at": (made or {}).get("anchoredSiteId") or None,
                            "anchor_verified": False,
                            "warning": f"Catalyst Center created {virtual_network} but reports it "
                            f"anchored at {got}, not {anchor_name}: the anchoring did not apply, so it was "
                            "not extended to the other sites.",
                        }
                    body = {**body, "id": made.get("id")}
                job = await sda_job(app, method, VNS, [body], ctx, step)
            after = await find_vn(app, virtual_network) or {}
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
