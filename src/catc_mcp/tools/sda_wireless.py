"""SD-Access fabric wireless writes (roadmap D124): the fabric WLC and the SSID-to-VLAN mappings.

A fabric site carries wireless in the fabric once its Catalyst 9800 is a fabric WLC (Catalyst Center
configures the WLC's LISP peering with the control plane nodes) and each fabric SSID is mapped to the VLAN of
an anycast gateway flagged as a wireless pool, so wireless clients land in that VN and pool with the same
SGT-based segmentation as wired ones. Order: provision the WLC at the fabric site's building
(catc_provision_wireless_controller) -> catc_add_fabric_wlc -> a wireless anycast gateway
(catc_update_anycast_gateway wireless_pool=true) -> catc_set_fabric_ssid_mapping. Read back with
catc_get_fabric_wireless.
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import contextlib
from typing import Annotated, Any

from fastmcp import Context
from pydantic import BaseModel, Field

from catc_mcp._core import (
    Confirm,
    InvalidRequest,
    Plan,
    ToolRegistrar,
    UpstreamError,
    get_client,
    preview_or_apply,
)
from catc_mcp.client import CatcApp, safe_id
from catc_mcp.common import ensure_list, resolve_device, resolve_site
from catc_mcp.safety import device_limit_blockers
from catc_mcp.tools.ops_writes import brief, device_site
from catc_mcp.tools.sda import SDA, FabricRef, edge_labels, resolve_fabric, sda_job, sda_list
from catc_mcp.tools.wireless import site_ssids

WLC_PATH = "/dna/intent/api/v1/business/sda/wireless-controller"
WLC_ROLE = "WIRELESS_CONTROLLER_NODE"


class SsidRow(BaseModel):
    """The SSIDs one fabric VLAN carries."""

    vlan: str = Field(description="The anycast gateway: its VLAN name, IP pool name or VLAN id")
    ssids: list[str] = Field(
        min_length=1, description="Fabric SSIDs mapped to this VLAN (replaces the VLAN's current SSIDs)"
    )
    security_group: str | None = Field(
        None, description="Security group (SGT name) the SSIDs' clients get; unset keeps the current one"
    )


def wlc_record(devices: list[dict[str, Any]], did: str) -> dict[str, Any] | None:
    return next(
        (
            d
            for d in devices
            if str(d.get("networkDeviceId")) == did and WLC_ROLE in ensure_list(d.get("deviceRoles"))
        ),
        None,
    )


async def vlan_mapping(app: CatcApp, fid: str) -> list[dict[str, Any]]:
    """The fabric site's VLAN-to-SSID rows ({vlanName, ssidDetails[{name, securityGroupTag}]})."""
    rows = await sda_list(app, f"fabrics/{safe_id(fid, 'fabric id')}/vlanToSsids")
    return [
        {
            "vlanName": r.get("vlanName"),
            "ssidDetails": [
                {k: s[k] for k in ("name", "securityGroupTag") if s.get(k) not in (None, "")}
                for s in ensure_list(r.get("ssidDetails"))
                if isinstance(s, dict)
            ],
        }
        for r in rows
        if r.get("vlanName")
    ]


def find_gateway(gws: list[dict[str, Any]], ref: str) -> dict[str, Any] | None:
    ref = ref.strip()
    return next(
        (g for g in gws if ref in (g.get("vlanName"), g.get("ipPoolName"), str(g.get("vlanId") or ""))),
        None,
    )


async def known_ssids(app: CatcApp, site_id: str) -> set[str] | None:
    """SSID names defined at Global or the fabric site; None when they can't be read (don't block then)."""
    names: set[str] = set()
    try:
        g = await resolve_site(app, "Global")
        names |= {str(s.get("ssid")) for s in await site_ssids(app, str(g["id"]))}
    except UpstreamError:
        return None
    with contextlib.suppress(UpstreamError):
        names |= {str(s.get("ssid")) for s in await site_ssids(app, site_id)}
    return names


def register(reg: ToolRegistrar) -> None:
    @reg.dangerous(title="Add fabric WLC", task=True)
    async def catc_add_fabric_wlc(
        ctx: Context,
        wlc: Annotated[
            str, Field(description="The Catalyst 9800 WLC: hostname, management IP, serial or id")
        ],
        fabric_site: FabricRef,
        remove: Annotated[bool, Field(description="Remove the WLC from the fabric site instead")] = False,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Add a wireless controller to an SD-Access fabric site (or remove it, remove=true). Catalyst Center
        configures the WLC for fabric (LISP map-server peering with the site's control plane nodes, fabric
        profiles) and the control plane nodes for the WLC, so the fabric SSIDs can then be mapped to wireless
        pools (catc_set_fabric_ssid_mapping). The WLC must be provisioned at the fabric site's building first.
        Removing it takes fabric wireless away from every AP and client on that WLC. Preview-first."""
        app: CatcApp = get_client(ctx)
        fabric, site = await resolve_fabric(app, fabric_site)
        fid = str(fabric["id"])
        site_name = str(site.get("nameHierarchy"))
        dev = await resolve_device(app, wlc)
        did = safe_id(str(dev["id"]), "device id")
        label = brief([dev])[0]
        devices = await sda_list(app, "fabricDevices", {"fabricId": fid})
        current = wlc_record(devices, did)
        cps = [d for d in devices if "CONTROL_PLANE_NODE" in ensure_list(d.get("deviceRoles"))]
        blockers = device_limit_blockers(app, 1 + len(cps), "devices (the WLC and the control plane nodes)")
        if "Wireless Controller" not in str(dev.get("family")):
            blockers.append(f"{label} is a {dev.get('family')}, not a wireless controller.")
        at = await device_site(app, did)
        noop = False
        if remove:
            if current is None:
                noop = True
            body = None
            if not dev.get("managementIpAddress"):
                blockers.append(f"{label} has no management IP (the remove request names the WLC by it).")
        else:
            noop = current is not None
            if not at:
                blockers.append(
                    f"{label} isn't assigned to a site: assign it to the fabric site's building and "
                    "provision it (catc_provision_wireless_controller) first."
                )
            elif not (at == site_name or at.startswith(site_name + "/") or site_name.startswith(at + "/")):
                blockers.append(f"{label} is at {at}, outside the fabric site {site_name}.")
            if not cps:
                blockers.append(
                    f"{site_name} has no control plane node: the fabric WLC peers with it "
                    "(catc_add_fabric_device role CONTROL_PLANE_NODE first)."
                )
            if not dev.get("hostname"):
                blockers.append(f"{label} has no hostname yet (the add request names the WLC by it).")
            body = {"deviceName": dev.get("hostname"), "siteNameHierarchy": site_name}
        request = (
            {
                "method": "DELETE",
                "path": WLC_PATH,
                "params": {"deviceIPAddress": dev.get("managementIpAddress")},
            }
            if remove
            else {"method": "POST", "path": WLC_PATH, "body": body}
        )
        plan = Plan(
            f"{'Remove' if remove else 'Add'} WLC {label} {'from' if remove else 'to'} "
            f"the fabric site {site_name}",
            details={
                "wlc": label,
                "wlc_site": at,
                "in_fabric": current is not None,
                "control_plane_nodes": await edge_labels(app, cps),
                "request": request,
            },
            side_effects=[
                (
                    f"Catalyst Center removes the fabric configuration from {label} and its control plane "
                    "peering: fabric SSIDs on it stop working for every AP and client."
                )
                if remove
                else (
                    f"Catalyst Center pushes fabric (LISP) configuration to {label} and to "
                    f"{len(cps)} control plane node(s)."
                ),
            ],
            fingerprint={"record": current, "site": at},
            blockers=blockers,
            blast_radius=1 + len(cps),
            noop=noop and not blockers,
            noop_reason=(
                (
                    f"{label} is not a fabric WLC at {site_name}"
                    if remove
                    else f"{label} is already a fabric WLC"
                )
                if noop and not blockers
                else None
            ),
        )

        async def apply() -> Any:
            if remove:
                job = await sda_job(
                    app,
                    "DELETE",
                    WLC_PATH,
                    None,
                    ctx,
                    "remove fabric WLC",
                    params={"deviceIPAddress": dev.get("managementIpAddress")},
                )
            else:
                job = await sda_job(app, "POST", WLC_PATH, body, ctx, "add fabric WLC")
            now = wlc_record(await sda_list(app, "fabricDevices", {"fabricId": fid}), did)
            return {**job, "fabric_wlc": now}

        return await preview_or_apply(
            ctx,
            tool="catc_add_fabric_wlc",
            args={"wlc": wlc, "fabric_site": fabric_site, "remove": remove},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.write(title="Set fabric SSID mapping")
    async def catc_set_fabric_ssid_mapping(
        ctx: Context,
        fabric_site: FabricRef,
        rows: Annotated[
            list[SsidRow] | None,
            Field(description="VLANs to set: each anycast gateway VLAN and the fabric SSIDs it carries"),
        ] = None,
        remove: Annotated[
            list[str] | None,
            Field(description="VLANs (VLAN name, pool name or VLAN id) whose SSIDs are all unmapped"),
        ] = None,
        wireless_multicast: Annotated[
            bool | None, Field(description="Also turn fabric wireless multicast on or off at the site")
        ] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Map fabric SSIDs to the VLANs of an SD-Access fabric site (wireless clients on the SSID land in
        that anycast gateway's VN and pool), unmap them, and optionally turn fabric wireless multicast on or
        off. Each row replaces the SSIDs of one VLAN; other VLANs keep theirs; an SSID moved to a new VLAN
        leaves its old one. Only gateways flagged as wireless pools can carry SSIDs. Preview-first: the
        mapping before and after."""
        app: CatcApp = get_client(ctx)
        if not rows and not remove and wireless_multicast is None:
            raise InvalidRequest("Give rows to map, remove to unmap, or wireless_multicast.")
        fabric, site = await resolve_fabric(app, fabric_site)
        fid = safe_id(str(fabric["id"]), "fabric id")
        site_name = str(site.get("nameHierarchy"))
        before = await vlan_mapping(app, fid)
        gws = await sda_list(app, "anycastGateways", {"fabricId": fid})
        blockers: list[str] = []
        warnings: list[str] = []
        after: dict[str, list[dict[str, Any]]] = {
            str(r["vlanName"]): [dict(s) for s in r["ssidDetails"]] for r in before
        }
        old_sgt = {s["name"]: s.get("securityGroupTag") for r in before for s in r["ssidDetails"]}
        moved: dict[str, dict[str, str]] = {}
        for ref in remove or []:
            gw = find_gateway(gws, ref)
            name = str(gw.get("vlanName")) if gw else ref
            if name not in after:
                blockers.append(f"{ref} has no SSID mapping at {site_name}.")
            else:
                after[name] = []
        wanted: dict[str, list[dict[str, Any]]] = {}
        for row in rows or []:
            gw = find_gateway(gws, row.vlan)
            if gw is None:
                blockers.append(
                    f"No anycast gateway {row.vlan!r} at {site_name} "
                    f"(have: {', '.join(str(g.get('vlanName')) for g in gws) or 'none'})."
                )
                continue
            name = str(gw.get("vlanName"))
            if gw.get("virtualNetworkName") == "INFRA_VN":
                blockers.append(f"{name} is an INFRA_VN (AP/extended node) pool: SSIDs map to user VN pools.")
            if not gw.get("isWirelessPool"):
                warnings.append(
                    f"{name} ({gw.get('ipPoolName')}) is not flagged as a wireless pool: Catalyst Center "
                    "maps SSIDs only to wireless pools; set it with "
                    "catc_update_anycast_gateway(wireless_pool=true)."
                )
            for ssid in row.ssids:
                sgt = row.security_group if row.security_group is not None else old_sgt.get(ssid)
                wanted.setdefault(name, []).append(
                    {"name": ssid, **({"securityGroupTag": sgt} if sgt else {})}
                )
        for name, ssids in wanted.items():
            names = {s["name"] for s in ssids}
            if len(names) != len(ssids):
                blockers.append(f"An SSID is listed twice for {name}.")
            for other, cur in after.items():
                if other == name or other in wanted:
                    continue
                left = [s for s in cur if s["name"] not in names]
                for s in cur:
                    if s["name"] in names:
                        moved[s["name"]] = {"from": other, "to": name}
                after[other] = left
            after[name] = ssids
        claimed = [s["name"] for ssids in wanted.values() for s in ssids]
        dupes = sorted({n for n in claimed if claimed.count(n) > 1})
        if dupes:
            blockers.append(
                f"An SSID maps to one VLAN per fabric site: {', '.join(dupes)} given for several."
            )
        if claimed:
            known = await known_ssids(app, str(site["id"]))
            missing = sorted({n for n in claimed if known is not None and n not in known})
            if missing:
                blockers.append(
                    f"No SSID {', '.join(missing)} at Global or {site_name} "
                    "(catc_create_ssid, catc_list_ssids)."
                )
        before_map = {str(r["vlanName"]): r["ssidDetails"] for r in before}
        body = [{"vlanName": n, "ssidDetails": s} for n, s in after.items() if s or n in before_map]
        mapping_changes = {
            n: {"from": before_map.get(n, []), "to": s}
            for n, s in after.items()
            if before_map.get(n, []) != s
        }
        multicast_now = None
        if wireless_multicast is not None:
            with contextlib.suppress(UpstreamError):
                mc = await app.get_response(f"{SDA}/fabrics/{fid}/wirelessMulticast")
                multicast_now = mc.get("multicastEnabled") if isinstance(mc, dict) else None
        steps: list[tuple[str, str, Any]] = []
        if mapping_changes:
            steps.append(("SSID mapping", f"{SDA}/fabrics/{fid}/vlanToSsids", body))
        if wireless_multicast is not None and multicast_now != wireless_multicast:
            steps.append(
                (
                    "wireless multicast",
                    f"{SDA}/fabrics/{fid}/wirelessMulticast",
                    {"multicastEnabled": wireless_multicast},
                )
            )
        devices = await sda_list(app, "fabricDevices", {"fabricId": fid})
        wlcs = [d for d in devices if WLC_ROLE in ensure_list(d.get("deviceRoles"))]
        if not wlcs and mapping_changes:
            warnings.append(
                f"{site_name} has no fabric WLC yet: the mapping is stored but no WLC carries it "
                "(catc_add_fabric_wlc)."
            )
        plan = Plan(
            f"Fabric wireless at {site_name}: " + ("; ".join(s[0] for s in steps) or "no change"),
            details={
                "before": before_map,
                "after": {n: s for n, s in after.items() if s},
                "changes": mapping_changes,
                **({"moved": moved} if moved else {}),
                **(
                    {"wireless_multicast": {"from": multicast_now, "to": wireless_multicast}}
                    if wireless_multicast is not None
                    else {}
                ),
                "fabric_wlcs": await edge_labels(app, wlcs),
                "requests": [{"method": "PUT", "path": p, "body": b} for _, p, b in steps],
                **({"warnings": warnings} if warnings else {}),
            },
            side_effects=[
                f"Catalyst Center pushes the fabric WLAN/policy profile change to {len(wlcs)} fabric WLC(s); "
                "clients on a changed SSID move to the new VLAN at their next association."
            ],
            fingerprint={"mapping": before, "multicast": multicast_now},
            blockers=blockers,
            noop=not steps and not blockers,
            noop_reason="The mapping already matches." if not steps and not blockers else None,
        )

        async def apply() -> Any:
            jobs = [await sda_job(app, "PUT", p, b, ctx, f"set {label}") for label, p, b in steps]
            return {"jobs": jobs, "vlan_to_ssids": await vlan_mapping(app, fid)}

        return await preview_or_apply(
            ctx,
            tool="catc_set_fabric_ssid_mapping",
            args={
                "fabric_site": fabric_site,
                "rows": [r.model_dump() for r in rows or []],
                "remove": remove,
                "wireless_multicast": wireless_multicast,
            },
            confirm=confirm,
            plan=plan,
            apply=apply,
        )
