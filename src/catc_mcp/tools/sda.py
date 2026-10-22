"""SD-Access writes (roadmap D13): fabric sites, fabric device roles, layer 3 virtual networks, anycast
gateways and edge port assignments. Preview-first.

Tiers: defining a fabric site or a virtual network changes no device (write tier). Adding a fabric device,
an anycast gateway or a port assignment pushes LISP/VRF/SVI/port configuration to the fabric devices
(dangerous tier), as does removing anything (catc_delete_sda_object). Order: provision the devices at the
fabric site's building -> catc_create_fabric_site -> catc_add_fabric_device (border + control plane first,
then edges) -> catc_create_virtual_network -> reserve an IP pool at the site (catc_create_ip_pool) ->
catc_add_anycast_gateway -> catc_assign_fabric_port. Read it all back with catc_get_sda_fabric. Tear down with
catc_delete_fabric_device or catc_delete_fabric_site (cascade=true: everything in reverse order).
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import contextlib
from typing import Annotated, Any, Literal

from fastmcp import Context
from pydantic import Field

from catc_mcp._core import (
    Confirm,
    InvalidRequest,
    NotFound,
    Plan,
    ToolRegistrar,
    UpstreamError,
    get_client,
    preview_or_apply,
)
from catc_mcp._core.http import fetch_all
from catc_mcp.client import CatcApp, safe_id
from catc_mcp.common import ensure_list, resolve_device, resolve_site
from catc_mcp.safety import device_limit_blockers
from catc_mcp.tools.ops_writes import brief, device_site

SDA = "/dna/intent/api/v1/sda"
AuthProfile = Literal["No Authentication", "Open Authentication", "Closed Authentication", "Low Impact"]
Role = Literal["CONTROL_PLANE_NODE", "BORDER_NODE", "EDGE_NODE"]
FabricRef = Annotated[
    str, Field(description="Fabric site: its site (name hierarchy or site id) or fabric id")
]


async def sda_list(app: CatcApp, what: str, params: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    page = await fetch_all(app.pager, app.api, f"{SDA}/{what}", params or {}, cap=5000)
    return [x for x in page.items if isinstance(x, dict)]


async def fabric_devices(app: CatcApp, network_device_id: str | None = None) -> list[dict[str, Any]]:
    """Fabric device records across every fabric site (the API needs fabricId on every query)."""
    out: list[dict[str, Any]] = []
    for f in await sda_list(app, "fabricSites"):
        params: dict[str, Any] = {"fabricId": f["id"]}
        if network_device_id:
            params["networkDeviceId"] = network_device_id
        out += await sda_list(app, "fabricDevices", params)
    return out


async def edge_labels(app: CatcApp, devices: list[dict[str, Any]]) -> list[str]:
    """'hostname (management IP)' of each fabric device record, for previews; the device id when the
    inventory has none."""
    ids = [str(d["networkDeviceId"]) for d in devices if d.get("networkDeviceId")]
    if not ids:
        return []
    found: dict[str, dict[str, Any]] = {}
    with contextlib.suppress(UpstreamError):
        rows = ensure_list(
            await app.get_response("/dna/intent/api/v1/network-device", {"id": ",".join(ids[:100])})
        )
        found = {str(r.get("id")): r for r in rows if isinstance(r, dict)}
    return [brief([found[i]])[0] if i in found else i for i in ids]


async def resolve_fabric(app: CatcApp, ref: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """(fabric site record, site) from a site name/id or a fabric id."""
    fabrics = await sda_list(app, "fabricSites")
    for f in fabrics:
        if str(f.get("id")) == ref.strip():
            return f, await resolve_site(app, str(f["siteId"]))
    site = await resolve_site(app, ref)
    for f in fabrics:
        if str(f.get("siteId")) == str(site["id"]):
            return f, site
    raise NotFound(
        f"{site.get('nameHierarchy')} is not a fabric site; create it with catc_create_fabric_site."
    )


SDA_MISSING = (
    "Catalyst Center refused the SD-Access request: {err}. On an appliance without the SD-Access "
    "application running (NCSP11008 'Package required ... ConnectivityDomain', seen on the lab 3.2.2 "
    "image) fabric sites and virtual networks can't be created; catc_status shows the 'SD Access' and "
    "'Access Control Application' packages. Install them in System > Software Management (optional "
    "packages) or with POST /dna/system/api/v1/installOptionalPackages."
)
# The SD Access package and the one it depends on. Both ship with every 3.x release as optional packages;
# /dnac-packages lists them even when they were skipped at install, so only installedRelease tells.
SDA_PACKAGES = ("sda", "aca")


async def sda_application(app: CatcApp) -> dict[str, Any]:
    """Whether the SD-Access application is deployed (for catc_status). The fabric APIs answer reads
    either way; without it, fabric site and VN creation fail with NCSP11008."""
    rel = await app.get_response("/dna/system/api/v1/installedRelease")
    pkgs = {p.get("name"): p for p in (rel.get("packages") or []) if isinstance(p, dict)}
    states = {n: str(pkgs[n].get("status") or "UNKNOWN") if n in pkgs else "ABSENT" for n in SDA_PACKAGES}
    out: dict[str, Any] = {"available": all(v == "DEPLOYED" for v in states.values()), "packages": states}
    if not out["available"]:
        out["reason"] = (
            "SD Access is not deployed on this Catalyst Center, so fabric site and virtual network "
            "creation fail with NCSP11008 ('Package required ... No application found for type "
            "ConnectivityDomain'); SDA write tools preview only. Install the optional packages "
            "'Access Control Application' and 'SD Access' (System > Software Management)."
        )
    return out


async def sda_job(app: CatcApp, method: str, path: str, body: Any, ctx: Context, what: str, **kw: Any) -> Any:
    """run_job with a clear message when the SD-Access application isn't available."""
    try:
        return await app.run_job(method, path, body, ctx=ctx, what=what, **kw)
    except UpstreamError as e:
        if "NCSP11008" in str(e) or ("NCSP11000" in str(e) and "provision" in str(e)):
            raise UpstreamError(SDA_MISSING.format(err=str(e)[:300])) from e
        raise


# Per-device handoffs; the API lists and deletes them per (fabricId, networkDeviceId).
HANDOFFS = (
    ("layer 3 handoff (IP transit)", "fabricDevices/layer3Handoffs/ipTransits"),
    ("layer 3 handoff (SD-Access transit)", "fabricDevices/layer3Handoffs/sdaTransits"),
    ("layer 2 handoff", "fabricDevices/layer2Handoffs"),
)
# The cascade leaves INFRA_VN's membership to go with the fabric site. 3.2.2 doesn't attach INFRA_VN to a
# fabric site by itself (live 2026-10-22, #191: catc_create_virtual_network attaches it, which an INFRA_VN
# gateway needs); deleting a fabric site that still has it attached is not proven live.
SYSTEM_VNS = {"INFRA_VN"}


async def fabric_contents(app: CatcApp, fabric: dict[str, Any], site: dict[str, Any]) -> dict[str, Any]:
    """Everything that lives in a fabric site (and its fabric zones), grouped in removal order."""
    fid = str(fabric["id"])
    zones = []
    for z in await sda_list(app, "fabricZones"):
        if str(z.get("siteId")) == str(site["id"]):
            continue
        with contextlib.suppress(NotFound):
            zsite = await resolve_site(app, str(z.get("siteId")))
            if _under(zsite.get("nameHierarchy"), site):
                zones.append({**z, "nameHierarchy": zsite.get("nameHierarchy")})
    fids = [fid] + [str(z["id"]) for z in zones]
    out: dict[str, Any] = {"fabric_ids": fids, "zones": zones}
    for key, what in (
        ("port_assignments", "portAssignments"),
        ("port_channels", "portChannels"),
        ("multicast_vns", "multicast/virtualNetworks"),
        ("anycast_gateways", "anycastGateways"),
        ("layer2_vns", "layer2VirtualNetworks"),
    ):
        out[key] = [x for f in fids for x in await sda_list(app, what, {"fabricId": f})]
    devices = await sda_list(app, "fabricDevices", {"fabricId": fid})
    out["handoffs"] = [
        {"kind": label, "path": what, "networkDeviceId": d.get("networkDeviceId"), "count": len(found)}
        for d in devices
        for label, what in HANDOFFS
        if (
            found := await sda_list(app, what, {"fabricId": fid, "networkDeviceId": d.get("networkDeviceId")})
        )
    ]
    out["virtual_networks"] = [
        v
        for v in await sda_list(app, "layer3VirtualNetworks")
        if set(map(str, ensure_list(v.get("fabricIds")))) & set(fids)
        and v.get("virtualNetworkName") not in SYSTEM_VNS
    ]
    # Edges first: the control plane and border go last.
    out["fabric_devices"] = sorted(devices, key=lambda d: "EDGE_NODE" not in (d.get("deviceRoles") or []))
    return out


def _contents_summary(c: dict[str, Any]) -> dict[str, Any]:
    return {
        "port_assignments": [
            f"{p.get('interfaceName')} ({p.get('dataVlanName')})" for p in c["port_assignments"]
        ],
        "port_channels": [str(p.get("portChannelName")) for p in c["port_channels"]],
        "multicast_vns": [str(m.get("virtualNetworkName")) for m in c["multicast_vns"]],
        "anycast_gateways": [
            f"{g.get('ipPoolName')} in {g.get('virtualNetworkName')}" for g in c["anycast_gateways"]
        ],
        "layer2_vns": [str(v.get("vlanName")) for v in c["layer2_vns"]],
        "handoffs": [f"{h['kind']} on {h['networkDeviceId']}" for h in c["handoffs"]],
        "virtual_networks_left_by_this_site": [
            str(v.get("virtualNetworkName")) for v in c["virtual_networks"]
        ],
        "fabric_zones": [str(z.get("nameHierarchy")) for z in c["zones"]],
        "fabric_devices": [f"{d.get('networkDeviceId')} {d.get('deviceRoles')}" for d in c["fabric_devices"]],
    }


def _under(site_path: str | None, fabric_site: dict[str, Any]) -> bool:
    root = str(fabric_site.get("nameHierarchy"))
    return bool(site_path) and (site_path == root or str(site_path).startswith(root + "/"))


def register(reg: ToolRegistrar) -> None:
    @reg.write(title="Create fabric site")
    async def catc_create_fabric_site(
        ctx: Context,
        site: Annotated[
            str, Field(description="Area or building to make a fabric site (name hierarchy or id)")
        ],
        authentication_profile: Annotated[
            AuthProfile,
            Field(description="Default host onboarding authentication for the fabric's edge ports"),
        ] = "No Authentication",
        pub_sub: Annotated[bool, Field(description="LISP pub/sub control plane (the 3.x default)")] = True,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Make a site an SD-Access fabric site. Changes no device yet: devices join with
        catc_add_fabric_device. Preview-first; refuses a site that is already a fabric site."""
        app: CatcApp = get_client(ctx)
        s = await resolve_site(app, site)
        blockers = []
        if s.get("type") not in ("area", "building"):
            blockers.append(f"A fabric site is an area or building, not a {s.get('type')}.")
        existing = await sda_list(app, "fabricSites", {"siteId": s["id"]})
        if existing:
            blockers.append(f"{s.get('nameHierarchy')} is already a fabric site.")
        body = [
            {
                "siteId": s["id"],
                "authenticationProfileName": authentication_profile,
                "isPubSubEnabled": pub_sub,
            }
        ]
        plan = Plan(
            f"Make {s.get('nameHierarchy')} an SD-Access fabric site ({authentication_profile})",
            details={"method": "POST", "path": f"{SDA}/fabricSites", "body": body},
            fingerprint={"site": s["id"], "existing": existing},
            blockers=blockers,
        )

        async def apply() -> Any:
            job = await sda_job(app, "POST", f"{SDA}/fabricSites", body, ctx=ctx, what="create fabric site")
            made = await sda_list(app, "fabricSites", {"siteId": s["id"]})
            return {**job, "fabric_id": made[0].get("id") if made else None}

        return await preview_or_apply(
            ctx,
            tool="catc_create_fabric_site",
            args={"site": site, "authentication_profile": authentication_profile, "pub_sub": pub_sub},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.dangerous(title="Add fabric device", task=True)
    async def catc_add_fabric_device(
        ctx: Context,
        device: Annotated[str, Field(description="Device hostname, management IP, serial or id")],
        fabric_site: FabricRef,
        roles: Annotated[
            list[Role],
            Field(min_length=1, description="CONTROL_PLANE_NODE, BORDER_NODE and/or EDGE_NODE"),
        ],
        border_asn: Annotated[
            str | None,
            Field(
                pattern=r"^\d{1,10}(\.\d{1,5})?$",
                description="BORDER_NODE: local BGP AS number, e.g. '65001'",
            ),
        ] = None,
        default_exit: Annotated[bool, Field(description="BORDER_NODE: default exit for the fabric")] = True,
        import_external_routes: Annotated[
            bool, Field(description="BORDER_NODE: import external routes")
        ] = True,
        border_priority: Annotated[
            int | None,
            Field(ge=1, le=9, description="BORDER_NODE: 1 (preferred) to 9; default: Catalyst Center's (10)"),
        ] = None,
        prepend_as_count: Annotated[
            int | None, Field(ge=1, le=10, description="BORDER_NODE: AS-path prepends (1-10); default: none")
        ] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Give a provisioned device a fabric role (control plane, border, edge) at a fabric site.
        Catalyst Center pushes the LISP, VRF and underlay-facing fabric configuration to the device. Add
        the border/control plane before the edges. The device must be provisioned at a site inside the
        fabric site (catc_provision_devices). Preview-first."""
        app: CatcApp = get_client(ctx)
        dev = await resolve_device(app, device)
        fabric, fsite = await resolve_fabric(app, fabric_site)
        roles = sorted(set(roles))
        blockers = device_limit_blockers(app, 1)
        at = await device_site(app, str(dev["id"]))
        if not _under(at, fsite):
            blockers.append(
                f"{brief([dev])[0]} is at {at or 'no site'}, not inside the fabric site "
                f"{fsite.get('nameHierarchy')}; assign and provision it there first."
            )
        prov = ensure_list(await app.get_response(f"{SDA}/provisionDevices", {"networkDeviceId": dev["id"]}))
        if not prov:
            blockers.append(f"{brief([dev])[0]} is not provisioned; run catc_provision_devices first.")
        existing = await sda_list(
            app, "fabricDevices", {"fabricId": fabric["id"], "networkDeviceId": dev["id"]}
        )
        if existing:
            blockers.append(f"Already a fabric device here with roles {existing[0].get('deviceRoles')}.")
        item: dict[str, Any] = {"networkDeviceId": dev["id"], "fabricId": fabric["id"], "deviceRoles": roles}
        if "BORDER_NODE" in roles:
            if not border_asn:
                blockers.append("A BORDER_NODE needs border_asn (the local BGP AS number).")
            item["borderDeviceSettings"] = {
                "borderTypes": ["LAYER_3"],
                "layer3Settings": {
                    "localAutonomousSystemNumber": border_asn,
                    "isDefaultExit": default_exit,
                    "importExternalRoutes": import_external_routes,
                },
            }
            # 3.2.2: priority 1-9 (unset = 10), prepend 1-10 (unset = none); out-of-range values are refused.
            l3 = item["borderDeviceSettings"]["layer3Settings"]
            if border_priority is not None:
                l3["borderPriority"] = border_priority
            if prepend_as_count is not None:
                l3["prependAutonomousSystemCount"] = prepend_as_count
        has_cp = any(
            "CONTROL_PLANE_NODE" in (d.get("deviceRoles") or [])
            for d in await sda_list(app, "fabricDevices", {"fabricId": fabric["id"]})
        )
        if "EDGE_NODE" in roles and not has_cp and "CONTROL_PLANE_NODE" not in roles:
            blockers.append("The fabric site has no control plane node yet; add it before the edges.")
        plan = Plan(
            f"Add {brief([dev])[0]} to fabric {fsite.get('nameHierarchy')} as {', '.join(roles)}",
            details={"method": "POST", "path": f"{SDA}/fabricDevices", "body": [item]},
            side_effects=["Pushes the fabric (LISP, VRF, border handoff) configuration to the device."],
            fingerprint={
                "device": dev["id"],
                "fabric": fabric["id"],
                "at": at,
                "existing": existing,
                "provisioned": sorted(str(p.get("id")) for p in prov if isinstance(p, dict)),
                "has_cp": has_cp,
            },
            blockers=blockers,
            blast_radius=1,
        )

        async def apply() -> Any:
            return await sda_job(
                app, "POST", f"{SDA}/fabricDevices", [item], ctx=ctx, what="add fabric device"
            )

        return await preview_or_apply(
            ctx,
            tool="catc_add_fabric_device",
            args={
                "device": device,
                "fabric_site": fabric_site,
                "roles": roles,
                "border_asn": border_asn,
                "default_exit": default_exit,
                "import_external_routes": import_external_routes,
                "border_priority": border_priority,
                "prepend_as_count": prepend_as_count,
            },
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.write(title="Create virtual network")
    async def catc_create_virtual_network(
        ctx: Context,
        name: Annotated[
            str,
            Field(min_length=1, max_length=16, pattern=r"^[A-Za-z0-9_-]+$", description="Layer 3 VN name"),
        ],
        fabric_sites: Annotated[
            list[str] | None,
            Field(description="Fabric sites to make it available at (site path or fabric id)"),
        ] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Create a layer 3 virtual network (VRF) or add an existing one to more fabric sites. Defining it
        changes no device; it reaches the fabric devices with the first anycast gateway. A VN to be anchored
        across sites must be created by catc_anchor_virtual_network instead (3.2.2 anchors a VN only when it
        creates it). Preview-first."""
        app: CatcApp = get_client(ctx)
        fids: list[str] = []
        names: list[Any] = []
        for ref in fabric_sites or []:
            f, s = await resolve_fabric(app, ref)
            fids.append(str(f["id"]))
            names.append(s.get("nameHierarchy"))
        current = await sda_list(app, "layer3VirtualNetworks", {"virtualNetworkName": name})
        current = [v for v in current if v.get("virtualNetworkName") == name]
        blockers: list[str] = []
        if current:
            have = set(ensure_list(current[0].get("fabricIds")))
            if set(fids) <= have:
                blockers.append(f"Virtual network {name} exists and is already at those fabric sites.")
            body: dict[str, Any] = {
                "id": current[0].get("id"),
                "virtualNetworkName": name,
                "fabricIds": sorted(have | set(fids)),
            }
            if current[0].get("anchoredSiteId"):
                # A PUT without it could unanchor an anchored VN (catc_anchor_virtual_network).
                body["anchoredSiteId"] = current[0]["anchoredSiteId"]
            method, action = "PUT", f"Add virtual network {name} to {', '.join(map(str, names))}"
        else:
            body = {"virtualNetworkName": name, **({"fabricIds": fids} if fids else {})}
            method, action = (
                "POST",
                f"Create virtual network {name}" + (f" at {', '.join(map(str, names))}" if names else ""),
            )
        plan = Plan(
            action,
            details={"method": method, "path": f"{SDA}/layer3VirtualNetworks", "body": [body]},
            fingerprint={"current": current, "fabrics": fids},
            blockers=blockers,
        )

        async def apply() -> Any:
            return await sda_job(
                app, method, f"{SDA}/layer3VirtualNetworks", [body], ctx=ctx, what="virtual network"
            )

        return await preview_or_apply(
            ctx,
            tool="catc_create_virtual_network",
            args={"name": name, "fabric_sites": fabric_sites},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.dangerous(title="Add anycast gateway", task=True)
    async def catc_add_anycast_gateway(
        ctx: Context,
        fabric_site: FabricRef,
        virtual_network: Annotated[str, Field(description="Layer 3 VN (must be at this fabric site)")],
        ip_pool: Annotated[
            str,
            Field(description="IP pool reserved at the fabric site (anchored VN: at the anchor site)"),
        ],
        vlan_name: Annotated[
            str | None, Field(description="VLAN name; default: generated by Catalyst Center")
        ] = None,
        vlan_id: Annotated[int | None, Field(ge=2, le=4093, description="VLAN id; default: auto")] = None,
        traffic_type: Annotated[Literal["DATA", "VOICE"], Field(description="Traffic type")] = "DATA",
        critical_pool: Annotated[bool, Field(description="Critical VLAN pool (ISE unreachable)")] = False,
        layer2_flooding: Annotated[bool, Field(description="Layer 2 flooding")] = False,
        pool_type: Annotated[
            Literal["EXTENDED_NODE", "FABRIC_AP"] | None,
            Field(description="INFRA_VN only (required there): extended-node or fabric AP pool"),
        ] = None,
        supplicant_based_onboarding: Annotated[
            bool | None,
            Field(description="INFRA_VN extended-node pool: supplicant-based extended node onboarding"),
        ] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Add an anycast gateway (the client subnet's default gateway, the same IP on every edge) for an IP
        pool in a virtual network at a fabric site. Catalyst Center pushes the VLAN, SVI and LISP instance
        to every edge node of the fabric site. In INFRA_VN (the global routing table) the pool is for
        extended nodes or fabric APs (pool_type); 3.2.2 doesn't attach INFRA_VN to a fabric site by itself,
        so attach it first (catc_create_virtual_network name='INFRA_VN'). For a VN anchored at another
        fabric site (catc_anchor_virtual_network) the pool is the anchor's, reserved at the anchor site
        only, and the remote site needs this gateway before its devices get the VN; its edges register with
        the anchor's control plane, so they need underlay reachability to it. Preview-first: lists the
        edges that get it."""
        app: CatcApp = get_client(ctx)
        fabric, fsite = await resolve_fabric(app, fabric_site)
        blockers: list[str] = []
        vns = [
            v
            for v in await sda_list(app, "layer3VirtualNetworks", {"virtualNetworkName": virtual_network})
            if v.get("virtualNetworkName") == virtual_network
        ]
        if not vns:
            blockers.append(
                f"No virtual network {virtual_network}; create it with catc_create_virtual_network."
            )
        elif str(fabric["id"]) not in map(str, ensure_list(vns[0].get("fabricIds"))):
            # INFRA_VN too: 3.2.2 doesn't attach it to a fabric site by itself and answers the gateway with
            # 404 NCHS20216 (live 2026-10-22, #191).
            why = (
                " (3.2.2 doesn't attach INFRA_VN to a fabric site by itself; the gateway would fail with 404 "
                "NCHS20216 '... has no virtual network with the name INFRA_VN')"
                if virtual_network == "INFRA_VN"
                else ""
            )
            blockers.append(
                f"{virtual_network} is not at this fabric site{why}. Add it first: "
                f"catc_create_virtual_network(name='{virtual_network}', "
                f"fabric_sites=['{fsite.get('nameHierarchy')}'])."
            )
        # A VN anchored at another fabric site takes the anchor's pool, reserved at the anchor site only
        # (live 2026-10-22, #190: a gateway at the remote site with the anchor's pool gave its edge the VRF,
        # the SVI, the anchor's LISP instance id and a LISP session to the anchor's control plane).
        anchor: dict[str, Any] | None = None
        anchor_id = str(vns[0].get("anchoredSiteId") or "") if vns else ""
        if anchor_id and anchor_id != str(fabric["id"]):
            with contextlib.suppress(NotFound):
                anchor = (await resolve_fabric(app, anchor_id))[1]
        pool_site = anchor or fsite
        pools = ensure_list(
            await app.get_response("/dna/intent/api/v1/ipam/siteIpAddressPools", {"siteId": pool_site["id"]})
        )
        pool = next((p for p in pools if isinstance(p, dict) and p.get("name") == ip_pool), None)
        if pool is None:
            where = (
                f"the anchor site {pool_site.get('nameHierarchy')}" if anchor else fsite.get("nameHierarchy")
            )
            blockers.append(
                f"No IP pool {ip_pool!r} is reserved at {where}"
                + (f" ({virtual_network} is anchored there)" if anchor else "")
                + " (catc_create_ip_pool)."
            )
        gws = await sda_list(app, "anycastGateways", {"fabricId": fabric["id"]})
        if any(g.get("ipPoolName") == ip_pool for g in gws):
            blockers.append(f"{ip_pool} already has an anycast gateway at this fabric site.")
        devices = await sda_list(app, "fabricDevices", {"fabricId": fabric["id"]})
        edges = [d for d in devices if "EDGE_NODE" in (d.get("deviceRoles") or [])]
        if not edges:
            blockers.append("The fabric site has no edge nodes yet; add them first (catc_add_fabric_device).")
        blockers += device_limit_blockers(app, len(edges), "edge devices")
        item: dict[str, Any] = {
            "fabricId": fabric["id"],
            "virtualNetworkName": virtual_network,
            "ipPoolName": ip_pool,
            "trafficType": traffic_type,
            "autoGenerateVlanName": vlan_name is None,
            "isCriticalPool": critical_pool,
            "isIntraSubnetRoutingEnabled": False,
            "isIpDirectedBroadcast": False,
            "isLayer2FloodingEnabled": layer2_flooding,
            "isMultipleIpToMacAddresses": False,
            "isWirelessPool": False,
        }
        if virtual_network == "INFRA_VN":
            if pool_type is None:
                blockers.append("An INFRA_VN gateway needs pool_type (EXTENDED_NODE or FABRIC_AP).")
            else:
                item["poolType"] = pool_type
            if supplicant_based_onboarding is not None:
                if pool_type != "EXTENDED_NODE":
                    blockers.append("supplicant_based_onboarding applies to an EXTENDED_NODE pool.")
                item["isSupplicantBasedExtendedNodeOnboarding"] = supplicant_based_onboarding
        elif pool_type is not None or supplicant_based_onboarding is not None:
            blockers.append("pool_type and supplicant_based_onboarding apply to INFRA_VN gateways only.")
        if vlan_name:
            item["vlanName"] = vlan_name
        if vlan_id:
            item["vlanId"] = vlan_id
        plan = Plan(
            f"Add an anycast gateway for {ip_pool} in {virtual_network} at {fsite.get('nameHierarchy')}",
            details={
                "edges": await edge_labels(app, edges),
                "method": "POST",
                "path": f"{SDA}/anycastGateways",
                "body": [item],
                "anchored_at": anchor.get("nameHierarchy") if anchor else None,
            },
            side_effects=[
                f"Pushes the VLAN/SVI/LISP instance to {len(edges)} edge device(s).",
                *(
                    [
                        f"{virtual_network} is anchored at {anchor.get('nameHierarchy')}: the gateway "
                        f"uses the anchor's pool {ip_pool} (reserved there, not at this site).",
                        "The edges here register with the anchor site's control plane, so they need underlay "
                        "reachability to it.",
                    ]
                    if anchor
                    else []
                ),
            ],
            fingerprint={
                "fabric": fabric["id"],
                "edges": sorted(str(d.get("id")) for d in edges),
                "gws": sorted(str(g.get("id")) for g in gws),
                "vn": vns[0] if vns else None,
                "pool": pool,
            },
            blockers=blockers,
            blast_radius=len(edges),
        )

        async def apply() -> Any:
            job = await sda_job(
                app, "POST", f"{SDA}/anycastGateways", [item], ctx=ctx, what="anycast gateway"
            )
            made = [
                g
                for g in await sda_list(app, "anycastGateways", {"fabricId": fabric["id"]})
                if g.get("ipPoolName") == ip_pool
            ]
            return {**job, "gateway": made[0] if made else None}

        return await preview_or_apply(
            ctx,
            tool="catc_add_anycast_gateway",
            args={
                "fabric_site": fabric_site,
                "virtual_network": virtual_network,
                "ip_pool": ip_pool,
                "vlan_name": vlan_name,
                "vlan_id": vlan_id,
                "traffic_type": traffic_type,
                "critical_pool": critical_pool,
                "layer2_flooding": layer2_flooding,
                "pool_type": pool_type,
                "supplicant_based_onboarding": supplicant_based_onboarding,
            },
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.dangerous(title="Assign fabric edge port")
    async def catc_assign_fabric_port(
        ctx: Context,
        device: Annotated[str, Field(description="Fabric edge device (hostname, IP, serial or id)")],
        interface: Annotated[str, Field(description="Interface name, e.g. GigabitEthernet1/0/3")],
        data_vlan: Annotated[
            str | None,
            Field(
                description="Data VLAN name or IP pool name of an anycast gateway "
                "(USER_DEVICE / TRUNKING_DEVICE)"
            ),
        ] = None,
        voice_vlan: Annotated[str | None, Field(description="Voice VLAN name or pool")] = None,
        connected_device_type: Annotated[
            Literal[
                "USER_DEVICE",
                "ACCESS_POINT",
                "TRUNKING_DEVICE",
                "AUTHENTICATOR_SWITCH",
                "SUPPLICANT_BASED_EXTENDED_NODE",
            ],
            Field(
                description="What is plugged in: a host, an AP, a trunk, or an extended node "
                "(AUTHENTICATOR_SWITCH: a policy extended node that authenticates its own hosts; "
                "SUPPLICANT_BASED_EXTENDED_NODE: one that onboards with 802.1X)"
            ),
        ] = "USER_DEVICE",
        authentication: Annotated[
            AuthProfile | None,
            Field(description="Port authentication template (default: the fabric site's profile)"),
        ] = None,
        description: Annotated[str | None, Field(max_length=230, description="Interface description")] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Assign an edge port to a fabric VLAN (host onboarding): Catalyst Center configures the access
        port (VLAN, authentication template) on the edge. Preview-first: refuses a port that already has
        an assignment or a VLAN that has no anycast gateway at the device's fabric site."""
        app: CatcApp = get_client(ctx)
        dev = await resolve_device(app, device)
        fdevs = await fabric_devices(app, str(dev["id"]))
        fdev = next((d for d in fdevs if "EDGE_NODE" in (d.get("deviceRoles") or [])), None)
        if fdev is None:
            raise InvalidRequest(f"{brief([dev])[0]} is not a fabric edge node (catc_add_fabric_device).")
        fid = str(fdev["fabricId"])
        blockers = device_limit_blockers(app, 1)
        gws = await sda_list(app, "anycastGateways", {"fabricId": fid})

        def vlan_of(ref: str | None) -> str | None:
            if not ref:
                return None
            for g in gws:
                if ref in (g.get("vlanName"), g.get("ipPoolName")):
                    return str(g.get("vlanName"))
            blockers.append(f"No anycast gateway with VLAN or pool {ref!r} at this fabric site.")
            return ref

        data, voice = vlan_of(data_vlan), vlan_of(voice_vlan)
        if connected_device_type == "USER_DEVICE" and not (data or voice):
            # 3.2.2: a VLAN is required unless the port's template is Closed Authentication (ISE assigns it).
            template = authentication or next(
                (
                    f.get("authenticationProfileName")
                    for f in await sda_list(app, "fabricSites")
                    if str(f.get("id")) == fid
                ),
                None,
            )
            if template == "Closed Authentication":
                # The spec exempts the VLAN only when the request names Closed Authentication: send it.
                authentication = "Closed Authentication"
            else:
                blockers.append(
                    "A USER_DEVICE port needs data_vlan and/or voice_vlan unless its template is Closed "
                    "Authentication (then ISE assigns the VLAN)."
                )
        if connected_device_type in ("AUTHENTICATOR_SWITCH", "SUPPLICANT_BASED_EXTENDED_NODE") and (
            data or voice
        ):
            blockers.append("An extended-node port takes no data or voice VLAN (it onboards over INFRA_VN).")
        current = await sda_list(
            app,
            "portAssignments",
            {"fabricId": fid, "networkDeviceId": dev["id"], "interfaceName": interface},
        )
        if current:
            blockers.append(f"{interface} already has a port assignment ({current[0].get('dataVlanName')}).")
        item: dict[str, Any] = {
            "fabricId": fid,
            "networkDeviceId": dev["id"],
            "interfaceName": interface,
            "connectedDeviceType": connected_device_type,
        }
        if data:
            item["dataVlanName"] = data
        if voice:
            item["voiceVlanName"] = voice
        if authentication and connected_device_type == "USER_DEVICE":
            item["authenticateTemplateName"] = authentication
        if description:
            item["interfaceDescription"] = description
        plan = Plan(
            f"Assign {brief([dev])[0]} {interface} to {data or voice or connected_device_type}",
            details={"method": "POST", "path": f"{SDA}/portAssignments", "body": [item]},
            side_effects=[f"Reconfigures {interface} on the edge (any existing port config is replaced)."],
            fingerprint={
                "device": dev["id"],
                "fabric": fid,
                "current": current,
                "vlans": {"data": data, "voice": voice},
                "gws": sorted((str(g.get("id")), str(g.get("vlanName"))) for g in gws),
            },
            blockers=blockers,
            blast_radius=1,
        )

        async def apply() -> Any:
            return await sda_job(
                app, "POST", f"{SDA}/portAssignments", [item], ctx=ctx, what="port assignment"
            )

        return await preview_or_apply(
            ctx,
            tool="catc_assign_fabric_port",
            args={
                "device": device,
                "interface": interface,
                "data_vlan": data_vlan,
                "voice_vlan": voice_vlan,
                "connected_device_type": connected_device_type,
                "authentication": authentication,
                "description": description,
            },
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.dangerous(title="Delete SDA object")
    async def catc_delete_sda_object(
        ctx: Context,
        kind: Annotated[
            Literal[
                "port_assignment",
                "anycast_gateway",
                "virtual_network",
                "fabric_device",
                "fabric_zone",
                "fabric_site",
            ],
            Field(description="What to remove"),
        ],
        id: Annotated[  # noqa: A002 - the API's term
            str | None,
            Field(description="Its id (catc_get_sda_fabric); for virtual_network give name instead"),
        ] = None,
        name: Annotated[str | None, Field(description="virtual_network: the VN name")] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Remove an SD-Access object: a port assignment, an anycast gateway, a layer 3 virtual network, a
        device's fabric role, a fabric zone or a fabric site. Catalyst Center removes the matching
        configuration from the fabric devices. Remove in reverse order (ports -> gateways -> VNs -> devices ->
        zones -> site); the preview refuses a fabric site, zone or VN that is still in use."""
        app: CatcApp = get_client(ctx)
        blockers: list[str] = []
        params: dict[str, Any] | None = None
        dependents: list[str] = []
        paths = {
            "port_assignment": "portAssignments",
            "anycast_gateway": "anycastGateways",
            "fabric_device": "fabricDevices",
            "fabric_zone": "fabricZones",
            "fabric_site": "fabricSites",
        }
        if kind == "virtual_network":
            if not name:
                raise InvalidRequest("Give the virtual network's name.")
            found = [
                v
                for v in await sda_list(app, "layer3VirtualNetworks", {"virtualNetworkName": name})
                if v.get("virtualNetworkName") == name
            ]
            if not found:
                raise NotFound(f"No virtual network {name}.")
            obj = found[0]
            gws = [g for g in await sda_list(app, "anycastGateways") if g.get("virtualNetworkName") == name]
            dependents = sorted(str(g.get("id")) for g in gws)
            if gws:
                blockers.append(f"{len(gws)} anycast gateway(s) still use {name}; remove them first.")
            path, params = f"{SDA}/layer3VirtualNetworks", {"virtualNetworkName": name}
            radius = None
        else:
            if not id:
                raise InvalidRequest(f"Give the {kind}'s id (catc_get_sda_fabric).")
            oid = safe_id(id, f"{kind} id")
            if kind == "fabric_device":
                candidates = await fabric_devices(app)
            elif kind == "port_assignment":
                candidates = []
                for f in await sda_list(app, "fabricSites"):
                    candidates += await sda_list(app, "portAssignments", {"fabricId": f["id"]})
            else:
                candidates = await sda_list(app, paths[kind], {"id": oid})
            found = [x for x in candidates if str(x.get("id")) == oid]
            if not found:
                raise NotFound(f"No {kind} with id {oid}.")
            obj = found[0]
            path = f"{SDA}/{paths[kind]}/{oid}"
            radius = 1
            if kind == "fabric_site":
                devs = await sda_list(app, "fabricDevices", {"fabricId": oid})
                gws = await sda_list(app, "anycastGateways", {"fabricId": oid})
                vns = [
                    str(v.get("virtualNetworkName"))
                    for v in await sda_list(app, "layer3VirtualNetworks")
                    if oid in ensure_list(v.get("fabricIds"))
                ]
                dependents = [str(x.get("id")) for x in devs + gws] + vns
                if devs:
                    blockers.append(
                        f"{len(devs)} fabric device(s) are still in this fabric site; remove them first."
                    )
                if gws:
                    blockers.append(f"{len(gws)} anycast gateway(s) still exist here; remove them first.")
                if vns:
                    blockers.append(f"Virtual networks still at this fabric site: {', '.join(vns)}.")
            if kind == "fabric_zone":
                gws = await sda_list(app, "anycastGateways", {"fabricId": oid})
                ports = await sda_list(app, "portAssignments", {"fabricId": oid})
                dependents = sorted(str(x.get("id")) for x in gws + ports)
                if gws or ports:
                    blockers.append(
                        f"The zone still has {len(gws)} anycast gateway(s) and {len(ports)} port "
                        "assignment(s); remove them first."
                    )
                radius = None
            if kind == "fabric_device":
                fid = obj.get("fabricId")
                ports = await sda_list(
                    app, "portAssignments", {"fabricId": fid, "networkDeviceId": obj.get("networkDeviceId")}
                )
                peers = [
                    d for d in await sda_list(app, "fabricDevices", {"fabricId": fid}) if d.get("id") != oid
                ]
                dependents = [str(p.get("id")) for p in ports] + sorted(str(d.get("id")) for d in peers)
                if ports:
                    blockers.append(f"{len(ports)} port assignment(s) on this device; remove them first.")
                last_cp = "CONTROL_PLANE_NODE" in (obj.get("deviceRoles") or []) and not any(
                    "CONTROL_PLANE_NODE" in (d.get("deviceRoles") or []) for d in peers
                )
                if last_cp and any("EDGE_NODE" in (d.get("deviceRoles") or []) for d in peers):
                    blockers.append(
                        "This is the last control plane node and edges remain; remove the edges first."
                    )
            if kind == "anycast_gateway":
                edges = [
                    d
                    for d in await sda_list(app, "fabricDevices", {"fabricId": obj.get("fabricId")})
                    if "EDGE_NODE" in (d.get("deviceRoles") or [])
                ]
                radius = len(edges)
                ports = [
                    p
                    for p in await sda_list(app, "portAssignments", {"fabricId": obj.get("fabricId")})
                    if obj.get("vlanName") in (p.get("dataVlanName"), p.get("voiceVlanName"))
                ]
                dependents = [str(p.get("id")) for p in ports] + sorted(str(d.get("id")) for d in edges)
                if ports:
                    blockers.append(
                        f"{len(ports)} port assignment(s) still use this gateway's VLAN; remove them first."
                    )
        if radius:
            blockers += device_limit_blockers(app, radius)
        plan = Plan(
            f"Delete {kind.replace('_', ' ')} {name or id}",
            details={"object": obj, "method": "DELETE", "path": path, "params": params},
            side_effects=["Catalyst Center removes the matching configuration from the fabric devices."],
            fingerprint={"object": obj, "dependents": dependents},
            blockers=blockers,
            blast_radius=radius,
        )

        async def apply() -> Any:
            return await sda_job(app, "DELETE", path, None, ctx, f"delete {kind}", params=params)

        return await preview_or_apply(
            ctx,
            tool="catc_delete_sda_object",
            args={"kind": kind, "id": id, "name": name},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    async def _run_steps(
        ctx: Context, app: CatcApp, steps: list[tuple[str, str, str, Any, dict[str, Any] | None]]
    ) -> dict[str, Any]:
        """Run (label, method, path, body, params) jobs in order; on a failure report what was removed."""
        done: list[str] = []
        for label, method, path, body, params in steps:
            try:
                await sda_job(app, method, path, body, ctx, label, params=params)
            except UpstreamError as e:
                raise UpstreamError(
                    f"Stopped at '{label}' ({len(done)} of {len(steps)} steps done): {e}. Removed so far: "
                    f"{done or 'nothing'}. Fix the cause and run the tool again (it starts from what is "
                    "left)."
                ) from e
            done.append(label)
        return {"removed": done, "steps": len(done)}

    def _handoff_steps(
        fid: str, handoffs: list[dict[str, Any]]
    ) -> list[tuple[str, str, str, Any, dict[str, Any]]]:
        return [
            (
                f"delete {h['kind']} on {h['networkDeviceId']}",
                "DELETE",
                f"{SDA}/{h['path']}",
                None,
                {"fabricId": fid, "networkDeviceId": h["networkDeviceId"]},
            )
            for h in handoffs
        ]

    @reg.dangerous(title="Delete fabric site", task=True)
    async def catc_delete_fabric_site(
        ctx: Context,
        fabric_site: FabricRef,
        cascade: Annotated[
            bool,
            Field(
                description="Also remove everything in it first (ports, port channels, multicast, gateways, "
                "layer 2 VNs, handoffs, VN memberships, fabric zones, fabric devices); default: refuse while "
                "anything is left"
            ),
        ] = False,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Remove an SD-Access fabric site; the site itself stays in the hierarchy. Without cascade the
        preview refuses while the fabric still holds anything and lists it. With cascade=true the preview
        lists everything that goes, and the apply removes it in reverse order (edge ports -> port channels ->
        multicast VNs -> anycast gateways -> layer 2 VNs -> border handoffs -> the site from each layer 3 VN
        (the VN itself stays) -> fabric zones -> fabric devices, edges first -> the fabric site). Catalyst
        Center removes the fabric configuration from every fabric device. A failure stops the run and says
        what was removed; running it again continues from what is left."""
        app: CatcApp = get_client(ctx)
        fabric, fsite = await resolve_fabric(app, fabric_site)
        fid = str(fabric["id"])
        c = await fabric_contents(app, fabric, fsite)
        summary = _contents_summary(c)
        left = {k: v for k, v in summary.items() if v}
        blockers = []
        if left and not cascade:
            blockers.append(
                f"{fsite.get('nameHierarchy')} still holds "
                f"{', '.join(f'{len(v)} {k}' for k, v in left.items())}; remove them first or pass "
                "cascade=true."
            )
        devices = c["fabric_devices"]
        blockers += device_limit_blockers(app, len(devices), "fabric devices")
        steps: list[tuple[str, str, str, Any, dict[str, Any] | None]] = []
        if cascade:
            for key, what, name in (
                ("port_assignments", "portAssignments", "interfaceName"),
                ("port_channels", "portChannels", "portChannelName"),
                ("multicast_vns", "multicast/virtualNetworks", "virtualNetworkName"),
                ("anycast_gateways", "anycastGateways", "ipPoolName"),
                ("layer2_vns", "layer2VirtualNetworks", "vlanName"),
            ):
                for x in c[key]:
                    oid = safe_id(str(x.get("id")), key)
                    steps.append(
                        (
                            f"delete {key[:-1].replace('_', ' ')} {x.get(name)}",
                            "DELETE",
                            f"{SDA}/{what}/{oid}",
                            None,
                            None,
                        )
                    )
            steps += _handoff_steps(fid, c["handoffs"])
            fids = set(c["fabric_ids"])
            for v in c["virtual_networks"]:
                keep = [f for f in map(str, ensure_list(v.get("fabricIds"))) if f not in fids]
                body = {
                    "id": v.get("id"),
                    "virtualNetworkName": v.get("virtualNetworkName"),
                    "fabricIds": keep,
                }
                if v.get("anchoredSiteId"):
                    body["anchoredSiteId"] = v["anchoredSiteId"]
                steps.append(
                    (
                        f"remove the site from VN {v.get('virtualNetworkName')}",
                        "PUT",
                        f"{SDA}/layer3VirtualNetworks",
                        [body],
                        None,
                    )
                )
            for z in c["zones"]:
                steps.append(
                    (
                        f"delete fabric zone {z.get('nameHierarchy')}",
                        "DELETE",
                        f"{SDA}/fabricZones/{safe_id(str(z['id']), 'zone id')}",
                        None,
                        None,
                    )
                )
            for d in devices:
                steps.append(
                    (
                        f"delete fabric device {d.get('networkDeviceId')} {d.get('deviceRoles')}",
                        "DELETE",
                        f"{SDA}/fabricDevices/{safe_id(str(d['id']), 'fabric device id')}",
                        None,
                        None,
                    )
                )
        steps.append(
            (
                f"delete fabric site {fsite.get('nameHierarchy')}",
                "DELETE",
                f"{SDA}/fabricSites/{safe_id(fid, 'fabric id')}",
                None,
                None,
            )
        )
        plan = Plan(
            f"Delete fabric site {fsite.get('nameHierarchy')}"
            + (f" and everything in it ({len(steps) - 1} objects)" if cascade and len(steps) > 1 else ""),
            details={"fabric_id": fid, "contents": left, "order": [s[0] for s in steps]},
            side_effects=[
                f"Catalyst Center removes the fabric configuration from {len(devices)} fabric device(s).",
                "Edge ports lose their fabric VLAN and authentication; clients on them go offline.",
            ]
            if devices
            else ["The site is no longer a fabric site (no device configuration changes)."],
            fingerprint={"contents": c},
            blockers=blockers,
            blast_radius=len(devices) or None,
        )

        async def apply() -> Any:
            return await _run_steps(ctx, app, steps)

        return await preview_or_apply(
            ctx,
            tool="catc_delete_fabric_site",
            args={"fabric_site": fabric_site, "cascade": cascade},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.dangerous(title="Delete fabric device", task=True)
    async def catc_delete_fabric_device(
        ctx: Context,
        device: Annotated[str, Field(description="Fabric device hostname, management IP, serial or id")],
        cascade: Annotated[
            bool,
            Field(
                description="Also remove its edge port assignments, port channels and border handoffs first"
            ),
        ] = False,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Take a device out of its SD-Access fabric site (all its fabric roles). Catalyst Center removes the
        fabric configuration (LISP, VRFs, fabric VLANs and SVIs) from it; the device stays in the inventory
        and provisioned. Without cascade the preview refuses while the device still has port assignments, port
        channels or handoffs; with cascade=true they go first. Refuses the last control plane node while edges
        remain."""
        app: CatcApp = get_client(ctx)
        dev = await resolve_device(app, device)
        did = str(dev["id"])
        fdevs = await fabric_devices(app, did)
        if not fdevs:
            raise NotFound(f"{brief([dev])[0]} is not a fabric device.")
        fdev = fdevs[0]
        fid = str(fdev["fabricId"])
        ports = await sda_list(app, "portAssignments", {"fabricId": fid, "networkDeviceId": did})
        channels = await sda_list(app, "portChannels", {"fabricId": fid, "networkDeviceId": did})
        handoffs = [
            {"kind": label, "path": what, "networkDeviceId": did, "count": len(found)}
            for label, what in HANDOFFS
            if (found := await sda_list(app, what, {"fabricId": fid, "networkDeviceId": did}))
        ]
        peers = [
            d
            for d in await sda_list(app, "fabricDevices", {"fabricId": fid})
            if d.get("id") != fdev.get("id")
        ]
        blockers = device_limit_blockers(app, 1)
        held: dict[str, list[str]] = {
            "port_assignments": [str(p.get("interfaceName")) for p in ports],
            "port_channels": [str(p.get("portChannelName")) for p in channels],
            "handoffs": [str(h["kind"]) for h in handoffs],
        }
        held = {k: v for k, v in held.items() if v}
        if held and not cascade:
            blockers.append(
                f"{brief([dev])[0]} still has {', '.join(f'{len(v)} {k}' for k, v in held.items())}; "
                "remove them first or pass cascade=true."
            )
        last_cp = "CONTROL_PLANE_NODE" in (fdev.get("deviceRoles") or []) and not any(
            "CONTROL_PLANE_NODE" in (d.get("deviceRoles") or []) for d in peers
        )
        if last_cp and any("EDGE_NODE" in (d.get("deviceRoles") or []) for d in peers):
            blockers.append("This is the last control plane node and edges remain; remove the edges first.")
        steps: list[tuple[str, str, str, Any, dict[str, Any] | None]] = []
        if cascade:
            for p in ports:
                steps.append(
                    (
                        f"delete port assignment {p.get('interfaceName')}",
                        "DELETE",
                        f"{SDA}/portAssignments/{safe_id(str(p['id']), 'port assignment id')}",
                        None,
                        None,
                    )
                )
            for p in channels:
                steps.append(
                    (
                        f"delete port channel {p.get('portChannelName')}",
                        "DELETE",
                        f"{SDA}/portChannels/{safe_id(str(p['id']), 'port channel id')}",
                        None,
                        None,
                    )
                )
            steps += _handoff_steps(fid, handoffs)
        steps.append(
            (
                f"remove {brief([dev])[0]} from the fabric",
                "DELETE",
                f"{SDA}/fabricDevices/{safe_id(str(fdev['id']), 'fabric device id')}",
                None,
                None,
            )
        )
        plan = Plan(
            f"Remove {brief([dev])[0]} ({', '.join(fdev.get('deviceRoles') or [])}) from its fabric site",
            details={"fabric_device": fdev, "holds": held, "order": [s[0] for s in steps]},
            side_effects=["Catalyst Center removes the LISP/VRF/fabric VLAN configuration from the device."],
            fingerprint={
                "fdev": fdev,
                "ports": ports,
                "channels": channels,
                "handoffs": handoffs,
                "peers": peers,
            },
            blockers=blockers,
            blast_radius=1,
        )

        async def apply() -> Any:
            return await _run_steps(ctx, app, steps)

        return await preview_or_apply(
            ctx,
            tool="catc_delete_fabric_device",
            args={"device": device, "cascade": cascade},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )
