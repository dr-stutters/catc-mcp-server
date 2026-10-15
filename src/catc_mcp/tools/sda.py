"""SD-Access writes (roadmap D13): fabric sites, fabric device roles, layer 3 virtual networks, anycast
gateways and edge port assignments. Preview-first.

Tiers: defining a fabric site or a virtual network changes no device (write tier). Adding a fabric device,
an anycast gateway or a port assignment pushes LISP/VRF/SVI/port configuration to the fabric devices
(dangerous tier), as does removing anything (catc_delete_sda_object). Order: provision the devices at the
fabric site's building -> catc_create_fabric_site -> catc_add_fabric_device (border + control plane first,
then edges) -> catc_create_virtual_network -> reserve an IP pool at the site (catc_create_ip_pool) ->
catc_add_anycast_gateway -> catc_assign_fabric_port. Read it all back with catc_get_sda_fabric.
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
from typing import Annotated, Any, Literal

from fastmcp import Context
from pydantic import Field
from stutters_mcp_core import (
    Confirm,
    InvalidRequest,
    NotFound,
    Plan,
    ToolRegistrar,
    UpstreamError,
    get_client,
    preview_or_apply,
)
from stutters_mcp_core.http import fetch_all

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
    "application running (NCSP11008 'Package required ... ConnectivityDomain', seen on the dCloud 3.2.2 "
    "image) fabric sites and virtual networks can't be created; check System > Software Management."
)


async def sda_job(app: CatcApp, method: str, path: str, body: Any, ctx: Context, what: str, **kw: Any) -> Any:
    """run_job with a clear message when the SD-Access application isn't available."""
    try:
        return await app.run_job(method, path, body, ctx=ctx, what=what, **kw)
    except UpstreamError as e:
        if "NCSP11008" in str(e) or ("NCSP11000" in str(e) and "provision" in str(e)):
            raise UpstreamError(SDA_MISSING.format(err=str(e)[:300])) from e
        raise


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
        if await sda_list(app, "fabricSites", {"siteId": s["id"]}):
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
            fingerprint={"site": s["id"]},
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

    @reg.dangerous(title="Add fabric device")
    async def catc_add_fabric_device(
        ctx: Context,
        device: Annotated[str, Field(description="Device hostname, management IP, serial or id")],
        fabric_site: FabricRef,
        roles: Annotated[
            list[Role],
            Field(min_length=1, description="CONTROL_PLANE_NODE, BORDER_NODE and/or EDGE_NODE"),
        ],
        border_asn: Annotated[
            str | None, Field(description="BORDER_NODE: local BGP AS number (layer 3 handoff), e.g. '65001'")
        ] = None,
        default_exit: Annotated[bool, Field(description="BORDER_NODE: default exit for the fabric")] = True,
        import_external_routes: Annotated[
            bool, Field(description="BORDER_NODE: import external routes")
        ] = True,
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
                    "borderPriority": 10,
                    "prependAutonomousSystemCount": 0,
                },
            }
        if (
            "EDGE_NODE" in roles
            and not any(
                "CONTROL_PLANE_NODE" in (d.get("deviceRoles") or [])
                for d in await sda_list(app, "fabricDevices", {"fabricId": fabric["id"]})
            )
            and "CONTROL_PLANE_NODE" not in roles
        ):
            blockers.append("The fabric site has no control plane node yet; add it before the edges.")
        plan = Plan(
            f"Add {brief([dev])[0]} to fabric {fsite.get('nameHierarchy')} as {', '.join(roles)}",
            details={"method": "POST", "path": f"{SDA}/fabricDevices", "body": [item]},
            side_effects=["Pushes the fabric (LISP, VRF, border handoff) configuration to the device."],
            fingerprint={"device": dev["id"], "fabric": fabric["id"], "at": at, "existing": existing},
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
        changes no device; it reaches the fabric devices with the first anycast gateway. Preview-first."""
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
            body: dict[str, Any] = {**current[0], "fabricIds": sorted(have | set(fids))}
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

    @reg.dangerous(title="Add anycast gateway")
    async def catc_add_anycast_gateway(
        ctx: Context,
        fabric_site: FabricRef,
        virtual_network: Annotated[str, Field(description="Layer 3 VN (must be at this fabric site)")],
        ip_pool: Annotated[str, Field(description="Name of the IP pool reserved at the fabric site")],
        vlan_name: Annotated[
            str | None, Field(description="VLAN name; default: generated by Catalyst Center")
        ] = None,
        vlan_id: Annotated[int | None, Field(ge=2, le=4093, description="VLAN id; default: auto")] = None,
        traffic_type: Annotated[Literal["DATA", "VOICE"], Field(description="Traffic type")] = "DATA",
        critical_pool: Annotated[bool, Field(description="Critical VLAN pool (ISE unreachable)")] = False,
        layer2_flooding: Annotated[bool, Field(description="Layer 2 flooding")] = False,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Add an anycast gateway (the client subnet's default gateway, the same IP on every edge) for an IP
        pool in a virtual network at a fabric site. Catalyst Center pushes the VLAN, SVI and LISP instance
        to every edge node of the fabric site. Preview-first: lists the edges that get it."""
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
        elif (
            str(fabric["id"]) not in ensure_list(vns[0].get("fabricIds")) and virtual_network != "DEFAULT_VN"
        ):
            blockers.append(
                f"{virtual_network} is not at this fabric site; add it with catc_create_virtual_network."
            )
        pools = ensure_list(
            await app.get_response("/dna/intent/api/v1/ipam/siteIpAddressPools", {"siteId": fsite["id"]})
        )
        if not any(isinstance(p, dict) and p.get("name") == ip_pool for p in pools):
            blockers.append(
                f"No IP pool {ip_pool!r} is reserved at {fsite.get('nameHierarchy')} (catc_create_ip_pool)."
            )
        gws = await sda_list(app, "anycastGateways", {"fabricId": fabric["id"]})
        if any(g.get("ipPoolName") == ip_pool for g in gws):
            blockers.append(f"{ip_pool} already has an anycast gateway at this fabric site.")
        devices = await sda_list(app, "fabricDevices", {"fabricId": fabric["id"]})
        edges = [d for d in devices if "EDGE_NODE" in (d.get("deviceRoles") or [])]
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
        if vlan_name:
            item["vlanName"] = vlan_name
        if vlan_id:
            item["vlanId"] = vlan_id
        plan = Plan(
            f"Add an anycast gateway for {ip_pool} in {virtual_network} at {fsite.get('nameHierarchy')}",
            details={
                "edges": [d.get("networkDeviceId") for d in edges],
                "method": "POST",
                "path": f"{SDA}/anycastGateways",
                "body": [item],
            },
            side_effects=[f"Pushes the VLAN/SVI/LISP instance to {len(edges)} edge device(s)."],
            fingerprint={
                "fabric": fabric["id"],
                "edges": sorted(str(d.get("id")) for d in edges),
                "gws": len(gws),
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
            Literal["USER_DEVICE", "ACCESS_POINT", "TRUNKING_DEVICE"], Field(description="What is plugged in")
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
        fdevs = await sda_list(app, "fabricDevices", {"networkDeviceId": dev["id"]})
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
            blockers.append("A USER_DEVICE port needs data_vlan and/or voice_vlan.")
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
            fingerprint={"device": dev["id"], "fabric": fid, "current": current, "gws": len(gws)},
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
            Literal["port_assignment", "anycast_gateway", "virtual_network", "fabric_device", "fabric_site"],
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
        device's fabric role or a fabric site. Catalyst Center removes the matching configuration from the
        fabric devices. Remove in reverse order (ports -> gateways -> VNs -> devices -> site); the preview
        refuses a fabric site or VN that is still in use."""
        app: CatcApp = get_client(ctx)
        blockers: list[str] = []
        params: dict[str, Any] | None = None
        paths = {
            "port_assignment": "portAssignments",
            "anycast_gateway": "anycastGateways",
            "fabric_device": "fabricDevices",
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
            if gws:
                blockers.append(f"{len(gws)} anycast gateway(s) still use {name}; remove them first.")
            path, params = f"{SDA}/layer3VirtualNetworks", {"virtualNetworkName": name}
            radius = None
        else:
            if not id:
                raise InvalidRequest(f"Give the {kind}'s id (catc_get_sda_fabric).")
            oid = safe_id(id, f"{kind} id")
            found = [x for x in await sda_list(app, paths[kind], {"id": oid}) if str(x.get("id")) == oid]
            if not found:
                raise NotFound(f"No {kind} with id {oid}.")
            obj = found[0]
            path = f"{SDA}/{paths[kind]}/{oid}"
            radius = 1
            if kind == "fabric_site":
                devs = await sda_list(app, "fabricDevices", {"fabricId": oid})
                if devs:
                    blockers.append(
                        f"{len(devs)} fabric device(s) are still in this fabric site; remove them first."
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
            fingerprint=obj,
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
