"""SD-Access multicast (roadmap D96): a fabric site's replication mode and multicast per virtual network.

The fabric site carries multicast either natively in the underlay (NATIVE_MULTICAST, needs underlay multicast)
or by head-end replication (HEADEND_REPLICATION, unicast copies from the source's edge). Each VN that carries
multicast needs an IP pool for the multicast loopbacks and, for any-source multicast, rendezvous points:
fabric RPs (up to two fabric devices) or an external RP address; source-specific multicast needs SSM ranges.
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
from typing import Annotated, Any, Literal

from fastmcp import Context
from pydantic import Field

from catc_mcp._core import Confirm, NotFound, Plan, ToolRegistrar, get_client, preview_or_apply
from catc_mcp.client import CatcApp, safe_id
from catc_mcp.common import ensure_list, resolve_device
from catc_mcp.safety import device_limit_blockers
from catc_mcp.tools.sda import SDA, FabricRef, resolve_fabric, sda_job, sda_list

MODES = {"native": "NATIVE_MULTICAST", "headend": "HEADEND_REPLICATION"}


async def multicast_state(app: CatcApp, fid: str) -> dict[str, Any]:
    rows = await sda_list(app, "multicast", {"fabricId": fid})
    vns = await sda_list(app, "multicast/virtualNetworks", {"fabricId": fid})
    return {"replication": rows[0].get("replicationMode") if rows else None, "virtual_networks": vns}


def ranges_to_existing_rp(rps: list[dict[str, Any]], ranges: list[str]) -> bool:
    """Put ASM ranges given without `rp` on the VN's one non-default IPv4 RP. Catalyst Center refuses ASM
    ranges on the default RP ("Default Rendezvous Point ... can't have ASM Group Ranges configured": it serves
    every group), so a VN whose only RP is the default has nowhere to put them. False when there isn't exactly
    one non-default RP."""
    target = [r for r in rps if not r.get("isDefaultV4RP")]
    if len(target) != 1:
        return False
    target[0]["ipv4AsmRanges"] = ranges
    return True


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="Fabric multicast")
    async def catc_get_fabric_multicast(ctx: Context, fabric_site: FabricRef) -> dict[str, Any]:
        """Multicast at an SD-Access fabric site. Returns the replication mode (native or head-end) and, per
        virtual network, the multicast IP pool, the rendezvous points (fabric RP devices or an external RP
        address, with their ASM ranges) and the SSM ranges. Change it with catc_set_fabric_multicast."""
        app: CatcApp = get_client(ctx)
        fabric, site = await resolve_fabric(app, fabric_site)
        st = await multicast_state(app, str(fabric["id"]))
        return {"fabric_site": site.get("nameHierarchy"), "fabric_id": fabric["id"], **st}

    @reg.dangerous(title="Set fabric multicast", task=True)
    async def catc_set_fabric_multicast(
        ctx: Context,
        fabric_site: FabricRef,
        replication: Annotated[
            Literal["native", "headend"] | None, Field(description="The fabric site's replication mode")
        ] = None,
        virtual_network: Annotated[
            str | None, Field(description="VN to enable (or change, or remove) multicast for")
        ] = None,
        ip_pool: Annotated[
            str | None, Field(description="VN: IP pool (reserved at the site) for the multicast loopbacks")
        ] = None,
        rp: Annotated[
            Literal["fabric", "external"] | None, Field(description="VN: where the rendezvous point is (ASM)")
        ] = None,
        rp_devices: Annotated[
            list[str] | None, Field(max_length=2, description="rp=fabric: up to two fabric devices as RPs")
        ] = None,
        external_rp_ip: Annotated[str | None, Field(description="rp=external: the RP's IPv4 address")] = None,
        asm_ranges: Annotated[
            str | None,
            Field(
                description="VN: IPv4 ASM group ranges, e.g. '239.1.0.0/16'. With rp: that RP becomes a "
                "non-default RP for just these ranges (the default RP serves every group, takes no ranges)"
            ),
        ] = None,
        ssm_ranges: Annotated[
            str | None, Field(description="VN: IPv4 SSM ranges, e.g. '232.0.0.0/8'")
        ] = None,
        remove_vn: Annotated[
            bool, Field(description="Remove multicast from virtual_network instead")
        ] = False,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Set multicast at an SD-Access fabric site. Sets its replication mode (native multicast in the
        underlay or head-end replication) and/or multicast for one virtual network (its IP pool, a fabric or
        external rendezvous point with ASM ranges, SSM ranges), or removes a VN's multicast. Catalyst Center
        pushes PIM/LISP multicast configuration to the fabric devices. Preview-first: current -> new."""
        app: CatcApp = get_client(ctx)
        fabric, site = await resolve_fabric(app, fabric_site)
        fid = str(fabric["id"])
        st = await multicast_state(app, fid)
        blockers: list[str] = []
        steps: list[tuple[str, str, str, Any]] = []
        changes: dict[str, Any] = {}
        if replication and MODES[replication] != st["replication"]:
            steps.append(
                (
                    "replication mode",
                    "PUT",
                    f"{SDA}/multicast",
                    [{"fabricId": fid, "replicationMode": MODES[replication]}],
                )
            )
            changes["replication"] = {"from": st["replication"], "to": MODES[replication]}
        current = None
        if virtual_network:
            current = next(
                (v for v in st["virtual_networks"] if v.get("virtualNetworkName") == virtual_network), None
            )
            if remove_vn:
                if current is None:
                    raise NotFound(f"{virtual_network} has no multicast at {site.get('nameHierarchy')}.")
                steps.append(
                    (
                        f"remove multicast from {virtual_network}",
                        "DELETE",
                        f"{SDA}/multicast/virtualNetworks/{safe_id(str(current['id']), 'multicast VN id')}",
                        None,
                    )
                )
                changes[virtual_network] = {"from": current, "to": None}
            else:
                vn_names = {
                    str(v.get("virtualNetworkName"))
                    for v in await sda_list(app, "layer3VirtualNetworks")
                    if fid in map(str, ensure_list(v.get("fabricIds")))
                }
                if virtual_network not in vn_names:
                    blockers.append(f"{virtual_network} is not a layer 3 VN of this fabric site.")
                item: dict[str, Any] = {
                    "fabricId": fid,
                    "virtualNetworkName": virtual_network,
                    "ipPoolName": ip_pool or (current or {}).get("ipPoolName"),
                }
                if not item["ipPoolName"]:
                    blockers.append("ip_pool is required to enable multicast on a VN.")
                if ssm_ranges is not None:
                    item["ipv4SsmRanges"] = [r.strip() for r in ssm_ranges.split(",") if r.strip()]
                elif current and current.get("ipv4SsmRanges"):
                    item["ipv4SsmRanges"] = current["ipv4SsmRanges"]
                if rp == "fabric":
                    if not rp_devices:
                        blockers.append("rp=fabric needs rp_devices.")
                    devs = [await resolve_device(app, d) for d in rp_devices or []]
                    rp_entry: dict[str, Any] = {
                        "rpDeviceLocation": "FABRIC",
                        "networkDeviceIds": [str(d["id"]) for d in devs],
                    }
                elif rp == "external":
                    if not external_rp_ip:
                        blockers.append("rp=external needs external_rp_ip.")
                    rp_entry = {
                        "rpDeviceLocation": "EXTERNAL",
                        "ipv4Address": external_rp_ip,
                    }
                else:
                    rp_entry = {}
                ranges = [r.strip() for r in (asm_ranges or "").split(",") if r.strip()]
                if rp_entry:
                    # The default RP serves every group and Catalyst Center refuses ASM ranges on it, so an
                    # RP given with ranges is a non-default RP for just those ranges.
                    rp_entry["isDefaultV4RP"] = not ranges
                    if ranges:
                        rp_entry["ipv4AsmRanges"] = ranges
                    item["multicastRPs"] = [rp_entry]
                elif current and current.get("multicastRPs"):
                    rps = [dict(r) for r in current["multicastRPs"] if isinstance(r, dict)]
                    if ranges and not ranges_to_existing_rp(rps, ranges):
                        blockers.append(
                            f"{virtual_network} has no single non-default rendezvous point for asm_ranges "
                            "(the default RP serves every group and Catalyst Center refuses ranges on it): "
                            "give rp (and rp_devices or external_rp_ip) to add an RP for these ranges."
                        )
                    item["multicastRPs"] = rps
                elif ranges:
                    blockers.append("asm_ranges need a rendezvous point: give rp (fabric or external).")
                if not item.get("multicastRPs") and not item.get("ipv4SsmRanges"):
                    blockers.append("Give a rendezvous point (rp) for ASM, ssm_ranges for SSM, or both.")
                if current is not None:
                    item["id"] = current["id"]
                    diff = {
                        k: {"from": current.get(k), "to": v} for k, v in item.items() if current.get(k) != v
                    }
                    if diff:
                        steps.append(
                            (
                                f"multicast for {virtual_network}",
                                "PUT",
                                f"{SDA}/multicast/virtualNetworks",
                                [item],
                            )
                        )
                        changes[virtual_network] = diff
                else:
                    steps.append(
                        (
                            f"multicast for {virtual_network}",
                            "POST",
                            f"{SDA}/multicast/virtualNetworks",
                            [item],
                        )
                    )
                    changes[virtual_network] = {"from": None, "to": item}
        elif remove_vn or any(
            x is not None for x in (ip_pool, rp, rp_devices, external_rp_ip, asm_ranges, ssm_ranges)
        ):
            blockers.append("Give virtual_network for the per-VN settings.")
        if not steps and not blockers:
            blockers.append("Nothing to change.")
        devices = await sda_list(app, "fabricDevices", {"fabricId": fid})
        blockers += device_limit_blockers(app, len(devices), "fabric devices")
        plan = Plan(
            f"Multicast at {site.get('nameHierarchy')}: " + ("; ".join(s[0] for s in steps) or "no change"),
            details={
                "current": st,
                "changes": changes,
                "requests": [{"method": m, "path": p, "body": b} for _, m, p, b in steps],
            },
            side_effects=[
                f"Catalyst Center pushes PIM/LISP multicast configuration to {len(devices)} fabric device(s)."
            ],
            fingerprint={"state": st},
            blockers=blockers,
            blast_radius=len(devices) or None,
        )

        async def apply() -> Any:
            for label, method, path, body in steps:  # one request at a time, as the API asks
                await sda_job(app, method, path, body, ctx, f"set {label}")
            return await multicast_state(app, fid)

        return await preview_or_apply(
            ctx,
            tool="catc_set_fabric_multicast",
            args={
                "fabric_site": fabric_site,
                "replication": replication,
                "virtual_network": virtual_network,
                "ip_pool": ip_pool,
                "rp": rp,
                "rp_devices": rp_devices,
                "external_rp_ip": external_rp_ip,
                "asm_ranges": asm_ranges,
                "ssm_ranges": ssm_ranges,
                "remove_vn": remove_vn,
            },
            confirm=confirm,
            plan=plan,
            apply=apply,
        )
