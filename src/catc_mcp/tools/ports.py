"""Port actions (roadmap D48, amended by G103): one switch port's admin state, access VLAN, voice VLAN or
description through Catalyst Center's own interface API.

`PUT /dna/intent/api/v1/interface/{interfaceUuid}` takes adminStatus ('UP'/'DOWN'), description, vlanId and
voiceVlanId; `deploymentMode=Preview` asks Catalyst Center for the change without pushing it (the dry run
shown in the preview) and `Deploy` pushes it. `GET .../interface/{id}/legit-operation` says which of those
properties the port takes (3.2.2 refuses VLAN changes on fabric devices: "VLAN changes are not supported on
devices that are part of the fabric").

The guard: uplinks (a port with a device neighbour in the physical topology), trunks and dynamic ports,
port channels and virtual interfaces are refused unless `allow_uplink`; shutting the port that carries the
device's management address is refused outright. The undo is the pre-change row re-applied.

The engine (`load_ports`, `uplink_ports`, `plan_port_change`, `apply_port_change`) takes one port at a time
so a bulk port table (D81) can run every row through the same checks.
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import re
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
from catc_mcp.client import CatcApp, safe_id
from catc_mcp.common import ensure_list, resolve_device
from catc_mcp.safety import device_limit_blockers
from catc_mcp.tools.inventory import redact_config
from catc_mcp.tools.ops_writes import brief

IFACE = "/dna/intent/api/v1/interface"
TOPOLOGY = "/dna/intent/api/v1/topology/physical-topology"
Action = Literal["shut", "no_shut", "access_vlan", "voice_vlan", "description"]
# action -> the PUT body property it sets
PROPERTY = {
    "shut": "adminStatus",
    "no_shut": "adminStatus",
    "access_vlan": "vlanId",
    "voice_vlan": "voiceVlanId",
    "description": "description",
}
TRUNK_MODES = {"trunk", "dynamic_auto", "dynamic_desirable", "dynamic"}
PORT_FIELDS = [
    "portName",
    "id",
    "status",
    "adminStatus",
    "portMode",
    "interfaceType",
    "vlanId",
    "voiceVlan",
    "description",
]
PREVIEW_TIMEOUT = 60.0
RESERVED_VLANS = range(1002, 1006)  # IOS's FDDI/Token Ring VLANs: not usable as access or voice VLANs


async def load_ports(app: CatcApp, device: dict[str, Any]) -> list[dict[str, Any]]:
    """The device's interfaces as Catalyst Center's inventory has them."""
    rows = ensure_list(await app.get_response(f"{IFACE}/network-device/{safe_id(str(device['id']))}"))
    return [r for r in rows if isinstance(r, dict)]


def _split(name: str) -> tuple[str, str]:
    m = re.match(r"\s*([A-Za-z-]+)\s*(.*?)\s*$", name)
    return (m.group(1).lower(), m.group(2)) if m else ("", name.strip())


def find_port(ports: list[dict[str, Any]], ref: str) -> dict[str, Any]:
    """A port by id, exact name (any case) or an abbreviation ('Gi1/0/3', 'gig 1/0/3')."""
    ref = ref.strip()
    if not ref:
        raise InvalidRequest("Give an interface name (e.g. GigabitEthernet1/0/3 or Gi1/0/3) or id.")
    for p in ports:
        if ref in (p.get("id"), p.get("instanceUuid")) or ref.lower() == str(p.get("portName", "")).lower():
            return p
    kind, num = _split(ref)
    hits = [
        p
        for p in ports
        if kind
        and _split(str(p.get("portName", "")))[1] == num
        and _split(str(p.get("portName", "")))[0].startswith(kind)
    ]
    if len(hits) == 1:
        return hits[0]
    if hits:
        names = ", ".join(str(p.get("portName")) for p in hits)
        raise InvalidRequest(f"{ref!r} matches {len(hits)} interfaces: {names}. Give the full name.")
    raise NotFound(f"No interface {ref!r} on the device. List them with catc_list_device_interfaces.")


async def uplink_ports(app: CatcApp, device_id: str) -> dict[str, str]:
    """{port name: neighbour} for the device's ports that face another network device in the physical
    (CDP/LLDP) topology. End hosts are left out of the topology read, so client ports never show up."""
    topo = await app.get_response(TOPOLOGY, {"nodeType": "device"})
    topo = topo if isinstance(topo, dict) else {}
    labels = {
        n.get("id"): str(n.get("label") or n.get("ip") or n.get("id"))
        for n in ensure_list(topo.get("nodes"))
        if isinstance(n, dict)
    }
    out: dict[str, str] = {}
    for link in ensure_list(topo.get("links")):
        if not isinstance(link, dict):
            continue
        for me, port, other, other_port in (
            ("source", "startPortName", "target", "endPortName"),
            ("target", "endPortName", "source", "startPortName"),
        ):
            if link.get(me) == device_id and link.get(port) and link.get(other) != device_id:
                peer = labels.get(link.get(other), str(link.get(other)))
                out[str(link[port]).lower()] = f"{peer} {link.get(other_port) or ''}".strip()
    return out


async def legit_properties(app: CatcApp, port_id: str) -> dict[str, dict[str, Any]] | None:
    """{property: {"applicable", "failureReason"}} from legit-operation; None when it can't be read."""
    try:
        data = await app.get_response(f"{IFACE}/{safe_id(port_id)}/legit-operation")
    except UpstreamError:
        return None
    if not isinstance(data, dict):
        return None
    return {
        str(p.get("name")): p
        for p in ensure_list(data.get("properties"))
        if isinstance(p, dict) and p.get("name")
    }


def _applicable(value: Any) -> bool:
    return value is True or str(value).lower() == "true"


def current_value(port: dict[str, Any], prop: str) -> Any:
    """The port's current value of a PUT property, in the PUT's own form (int VLANs, 'UP'/'DOWN')."""
    raw = port.get({"vlanId": "vlanId", "voiceVlanId": "voiceVlan"}.get(prop, prop))
    if prop in ("vlanId", "voiceVlanId"):
        try:
            return int(str(raw))
        except (TypeError, ValueError):
            return None
    if prop == "adminStatus":
        return str(raw or "").upper() or None
    return raw if raw is not None else ""


def wanted_value(action: str, vlan: int | None, description: str | None) -> Any:
    if action == "shut":
        return "DOWN"
    if action == "no_shut":
        return "UP"
    if action in ("access_vlan", "voice_vlan"):
        return vlan
    return description


def argument_blockers(action: str, vlan: int | None, description: str | None) -> list[str]:
    if action in ("access_vlan", "voice_vlan"):
        out = [] if vlan is not None else [f"action={action} needs `vlan` (1-4094)."]
        if vlan in RESERVED_VLANS:
            out.append(f"VLAN {vlan} is reserved on IOS XE (1002-1005); pick another.")
        if description is not None:
            out.append(f"action={action} takes `vlan`, not `description`.")
        return out
    if action == "description":
        out = [] if description is not None else ["action=description needs `description` ('' clears it)."]
        return out + (["action=description takes `description`, not `vlan`."] if vlan is not None else [])
    if vlan is not None or description is not None:
        return [f"action={action} takes neither `vlan` nor `description`."]
    return []


def undo_of(port: dict[str, Any], device_ref: str, prop: str) -> dict[str, Any]:
    """The pre-change row as a ready catc_set_interface call (and the raw PUT body)."""
    before = current_value(port, prop)
    name = str(port.get("portName") or port.get("id"))
    args: dict[str, Any] = {"device": device_ref, "interface": name}
    note = None
    if prop == "adminStatus":
        args["action"] = "shut" if before == "DOWN" else "no_shut"
    elif prop == "description":
        args |= {"action": "description", "description": before or ""}
    elif before is None:
        args = {}
        note = (
            "The port had no voice VLAN before; this API can't remove one. Undo with a template "
            "('interface <port>' / 'no switchport voice vlan')."
            if prop == "voiceVlanId"
            else "The port had no access VLAN before; set the one it should have."
        )
    else:
        args |= {"action": "access_vlan" if prop == "vlanId" else "voice_vlan", "vlan": before}
    out: dict[str, Any] = {"before": {prop: before}}
    if args:
        out["call"] = {"tool": "catc_set_interface", "args": args}
    if note:
        out["note"] = note
    return out


def plan_port_change(
    device: dict[str, Any],
    port: dict[str, Any],
    uplinks: dict[str, str],
    legit: dict[str, dict[str, Any]] | None,
    action: str,
    vlan: int | None = None,
    description: str | None = None,
    allow_uplink: bool = False,
) -> dict[str, Any]:
    """One port's change: {"port", "property", "from", "to", "body", "blockers", "warnings", "undo"}."""
    prop = PROPERTY[action]
    blockers = argument_blockers(action, vlan, description)
    warnings: list[str] = []
    name = str(port.get("portName") or port.get("id"))
    mode = str(port.get("portMode") or "").lower()
    guarded = action != "description"  # a description never changes forwarding
    reasons: list[str] = []
    if name.lower() in uplinks:
        reasons.append(f"it is an uplink to {uplinks[name.lower()]} (physical topology)")
    if mode in TRUNK_MODES:
        reasons.append(f"it is a {mode} port")
    if _split(name)[0] == "port-channel":
        reasons.append("it is a port channel")
    elif str(port.get("interfaceType") or "").lower() not in ("", "physical"):
        reasons.append(f"it is a {str(port.get('interfaceType')).lower()} interface, not a switch port")
    if guarded and reasons:
        if allow_uplink:
            warnings.append(f"{name}: {'; '.join(reasons)}. allow_uplink=true, so it is not refused.")
        else:
            blockers.append(
                f"{name} is refused because {'; '.join(reasons)}. Changing it can cut off the devices "
                "behind it; pass allow_uplink=true only if that is the intent."
            )
    mgmt = device.get("managementIpAddress")
    if action == "shut" and mgmt and port.get("ipv4Address") == mgmt:
        blockers.append(
            f"{name} carries the device's management address {mgmt}: shutting it cuts Catalyst Center off "
            "from the device. Not allowed, even with allow_uplink."
        )
    if action in ("access_vlan", "voice_vlan") and mode == "routed":
        blockers.append(f"{name} is a routed port (no switchport): it has no access or voice VLAN.")
    if legit is None:
        warnings.append(
            "Catalyst Center's legit-operation check could not be read; the PUT may still refuse."
        )
    elif prop in legit and not _applicable(legit[prop].get("applicable")):
        blockers.append(
            f"Catalyst Center can't change {prop} on {name}: "
            f"{legit[prop].get('failureReason') or 'not applicable'}."
        )
    before, after = current_value(port, prop), wanted_value(action, vlan, description)
    if after is not None and before == after:
        blockers.append(f"Nothing to change: {name} already has {prop} {after!r}.")
    reach = device.get("reachabilityStatus")
    if reach and reach != "Reachable":
        warnings.append(f"The device is {reach} in Catalyst Center; the change can't reach it until it is.")
    return {
        "port": name,
        "port_id": str(port.get("id") or port.get("instanceUuid")),
        "property": prop,
        "from": before,
        "to": after,
        "current": {k: port.get(k) for k in PORT_FIELDS if k in port},
        "body": {prop: after},
        "blockers": blockers,
        "warnings": warnings,
        "undo": undo_of(port, str(device.get("hostname") or device.get("id")), prop),
    }


async def cc_preview(app: CatcApp, port_id: str, body: dict[str, Any]) -> Any:
    """Ask Catalyst Center for the change with deploymentMode=Preview (nothing is pushed to the device)."""
    try:
        started = await app.api.request(
            "PUT", f"{IFACE}/{safe_id(port_id)}", params={"deploymentMode": "Preview"}, json=body
        )
        job = await app.wait_job(started, timeout=PREVIEW_TIMEOUT, what="interface preview")
    except UpstreamError as e:
        return {"unavailable": redact_config(str(e))[:300]}
    return {k: redact_config(v) if isinstance(v, str) else v for k, v in job.items()}


async def apply_port_change(
    app: CatcApp, change: dict[str, Any], ctx: Context | None = None
) -> dict[str, Any]:
    """Push one planned change (deploymentMode=Deploy), wait for its task and read the port back."""
    pid = safe_id(change["port_id"])
    job = await app.run_job(
        "PUT",
        f"{IFACE}/{pid}",
        change["body"],
        ctx=ctx,
        what="interface update",
        params={"deploymentMode": "Deploy"},
    )
    now = await app.get_response(f"{IFACE}/{pid}")
    now = now if isinstance(now, dict) else {}
    out: dict[str, Any] = {
        "port": change["port"],
        "task": job,
        "interface": {k: now.get(k) for k in PORT_FIELDS if k in now},
        "undo": change["undo"],
    }
    if now and current_value(now, change["property"]) != change["to"]:
        out["note"] = (
            f"The inventory still reads {change['property']} as {current_value(now, change['property'])!r}; "
            "it updates after Catalyst Center's next collection (catc_resync_devices to force one)."
        )
    return out


def register(reg: ToolRegistrar) -> None:
    @reg.dangerous(title="Set interface")
    async def catc_set_interface(
        ctx: Context,
        device: Annotated[str, Field(description="Switch (hostname, management IP, serial or id)")],
        interface: Annotated[
            str, Field(description="Port name (GigabitEthernet1/0/3, Gi1/0/3) or interface id")
        ],
        action: Annotated[
            Action,
            Field(
                description="shut, no_shut, access_vlan (needs vlan), voice_vlan (needs vlan) or "
                "description (needs description)"
            ),
        ],
        vlan: Annotated[
            int | None, Field(ge=1, le=4094, description="VLAN id for access_vlan / voice_vlan")
        ] = None,
        description: Annotated[
            str | None,
            Field(max_length=230, description="Port description for action=description ('' clears)"),
        ] = None,
        allow_uplink: Annotated[
            bool,
            Field(
                description="Allow uplinks, trunks, port channels and virtual interfaces (default refused)"
            ),
        ] = False,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Change one switch port through Catalyst Center: shut / no shut, the access VLAN, the voice VLAN
        or the description (containment or remediation without writing a template). Refuses uplinks (a port
        facing another network device in the physical topology), trunk and dynamic ports, port channels and
        virtual interfaces unless allow_uplink; never shuts the port carrying the management address; refuses
        what Catalyst Center's legit-operation check says the port can't take (3.2.2: no VLAN changes on
        fabric devices; use catc_assign_fabric_port there). Preview-first: the current port row, the change,
        Catalyst Center's own dry run (deploymentMode=Preview, nothing pushed) and the undo call (the
        pre-change value). Counts as one device for CATC_MAX_DEVICES_PER_CHANGE and honours MCP_CHANGE_WINDOW.
        Shutting a client port drops the client; the change is not saved to the startup config."""
        app: CatcApp = get_client(ctx)
        dev = await resolve_device(app, device)
        port = find_port(await load_ports(app, dev), interface)
        pid = str(port.get("id") or port.get("instanceUuid"))
        uplinks = await uplink_ports(app, str(dev["id"]))
        legit = await legit_properties(app, pid)
        change = plan_port_change(dev, port, uplinks, legit, action, vlan, description, allow_uplink)
        blockers = [*change["blockers"], *device_limit_blockers(app, 1)]
        details: dict[str, Any] = {
            "device": brief([dev])[0],
            "interface": change["current"],
            "change": {change["property"]: {"from": change["from"], "to": change["to"]}},
            "method": "PUT",
            "path": f"{IFACE}/{pid}?deploymentMode=Deploy",
            "body": change["body"],
            "undo": change["undo"],
        }
        if change["warnings"]:
            details["warnings"] = change["warnings"]
        if confirm is None and not blockers:
            details["catalyst_center_preview"] = await cc_preview(app, pid, change["body"])
        side_effects = ["Changes the device's running configuration (not saved to startup)."]
        if action == "shut":
            side_effects.append("Clients on the port lose their link; 802.1X/MAB sessions on it end.")
        elif action == "access_vlan":
            side_effects.append(
                "A client on the port moves VLAN: it needs a new DHCP lease (bounce the port)."
            )
        plan = Plan(
            f"{action} on {change['port']} of {brief([dev])[0]}",
            details=details,
            side_effects=side_effects,
            fingerprint={"port": change["current"], "uplinks": sorted(uplinks)},
            blockers=blockers,
            blast_radius=1,
        )

        async def apply() -> Any:
            return await apply_port_change(app, change, ctx)

        return await preview_or_apply(
            ctx,
            tool="catc_set_interface",
            args={
                "device": device,
                "interface": interface,
                "action": action,
                "vlan": vlan,
                "description": description,
                "allow_uplink": allow_uplink,
            },
            confirm=confirm,
            plan=plan,
            apply=apply,
        )
