"""SD-Access extranet policies (roadmap D95): shared services between virtual networks.

An extranet policy lets subscriber VNs reach a provider VN (shared services: DHCP, DNS, AD, printers) through
LISP route leaking inside the fabric, instead of leaking routes on a fusion router. One tool creates, updates
(provider, subscribers, fabric sites) or deletes a policy; the preview names the route-leaking consequence.
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
from typing import Annotated, Any

from fastmcp import Context
from pydantic import Field

from catc_mcp._core import (
    Confirm,
    NotFound,
    Plan,
    ToolRegistrar,
    get_client,
    preview_or_apply,
)
from catc_mcp.client import CatcApp
from catc_mcp.common import ensure_list
from catc_mcp.safety import device_limit_blockers
from catc_mcp.tools.sda import SDA, resolve_fabric, sda_job, sda_list

PATH = f"{SDA}/extranetPolicies"


def same(a: Any, b: Any) -> bool:
    """Equal, comparing lists as sets (the API may reorder them)."""
    if isinstance(a, list) or isinstance(b, list):
        return sorted(map(str, ensure_list(a))) == sorted(map(str, ensure_list(b)))
    return bool(a == b)


def register(reg: ToolRegistrar) -> None:
    @reg.dangerous(title="Set extranet policy", task=True)
    async def catc_set_extranet_policy(
        ctx: Context,
        name: Annotated[
            str,
            Field(
                min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_-]+$", description="Extranet policy name"
            ),
        ],
        provider_vn: Annotated[
            str | None, Field(description="Provider layer 3 VN (the shared services); required to create")
        ] = None,
        subscriber_vns: Annotated[
            list[str] | None,
            Field(description="Subscriber layer 3 VNs that reach the provider (replaces the list on update)"),
        ] = None,
        fabric_sites: Annotated[
            list[str] | None,
            Field(
                description="Fabric sites it applies at (site path or fabric id; replaces the list on update)"
            ),
        ] = None,
        delete: Annotated[bool, Field(description="Delete the policy instead")] = False,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Create, update or delete an SD-Access extranet policy. The subscriber VNs reach the provider VN's
        prefixes (shared services) through LISP route leaking inside the fabric. On update, unset arguments
        keep their value. Catalyst Center pushes the leaking to the fabric devices of the sites concerned.
        Preview-first: current -> new provider, subscribers and sites."""
        app: CatcApp = get_client(ctx)
        current = next(
            (
                p
                for p in await sda_list(app, "extranetPolicies", {"extranetPolicyName": name})
                if p.get("extranetPolicyName") == name
            ),
            None,
        )
        vns = {str(v.get("virtualNetworkName")): v for v in await sda_list(app, "layer3VirtualNetworks")}
        fids: list[str] | None = None
        names: list[Any] = []
        if fabric_sites is not None:
            fids = []
            for ref in fabric_sites:
                f, s = await resolve_fabric(app, ref)
                fids.append(str(f["id"]))
                names.append(s.get("nameHierarchy"))
        blockers: list[str] = []
        if delete:
            if current is None:
                raise NotFound(f"No extranet policy {name}.")
            if provider_vn or subscriber_vns or fabric_sites:
                blockers.append("Give only the name to delete a policy.")
            method, body, params = "DELETE", None, {"extranetPolicyName": name}
            action = f"Delete extranet policy {name}"
            fids_now = [str(f) for f in ensure_list(current.get("fabricIds"))]
        else:
            cur = current or {}
            provider: str | None = provider_vn or cur.get("providerVirtualNetworkName")
            subs: list[str] = (
                list(subscriber_vns)
                if subscriber_vns is not None
                else [str(v) for v in ensure_list(cur.get("subscriberVirtualNetworkNames"))]
            )
            fids_now = fids if fids is not None else [str(f) for f in ensure_list(cur.get("fabricIds"))]
            body = {
                "extranetPolicyName": name,
                "providerVirtualNetworkName": provider,
                "subscriberVirtualNetworkNames": subs,
                "fabricIds": fids_now,
            }
            if current is not None:
                body["id"] = current.get("id")
            method, params = ("PUT" if current else "POST"), None
            action = f"{'Update' if current else 'Create'} extranet policy {name}"
            if not provider:
                blockers.append("provider_vn is required to create a policy.")
            if not subs:
                blockers.append("Give at least one subscriber VN.")
            for vn in [provider, *subs]:
                if vn and vn not in vns:
                    blockers.append(f"No layer 3 virtual network {vn}.")
            if provider in subs:
                blockers.append("The provider VN can't also be a subscriber.")
            if current is not None and all(same(current.get(k), v) for k, v in body.items()):
                blockers.append(f"Nothing to change: {name} already has those settings.")
        devices = [d for f in fids_now for d in await sda_list(app, "fabricDevices", {"fabricId": f})]
        blockers += device_limit_blockers(app, len(devices), "fabric devices")
        plan = Plan(
            action,
            details={
                "current": current,
                "method": method,
                "path": PATH,
                "body": [body] if body else None,
                "params": params,
                "fabric_sites": names or None,
            },
            side_effects=[
                f"The subscriber VNs lose the provider's prefixes; {len(devices)} fabric device(s) change."
                if delete
                else "Subscriber VNs reach the provider VN's prefixes (and the provider theirs) across the "
                f"fabric; Catalyst Center pushes the route leaking to {len(devices)} fabric device(s)."
            ],
            fingerprint={"current": current},
            blockers=blockers,
            blast_radius=len(devices) or None,
        )

        async def apply() -> Any:
            job = await sda_job(
                app, method, PATH, [body] if body else None, ctx, f"{method} extranet policy", params=params
            )
            now = [
                p
                for p in await sda_list(app, "extranetPolicies", {"extranetPolicyName": name})
                if p.get("extranetPolicyName") == name
            ]
            return {**job, "policy": now[0] if now else None}

        return await preview_or_apply(
            ctx,
            tool="catc_set_extranet_policy",
            args={
                "name": name,
                "provider_vn": provider_vn,
                "subscriber_vns": subscriber_vns,
                "fabric_sites": fabric_sites,
                "delete": delete,
            },
            confirm=confirm,
            plan=plan,
            apply=apply,
        )
