"""SD-Access authentication templates (roadmap D90): the host onboarding posture of a fabric site.

A fabric site has one default template (`sda/fabricSites` authenticationProfileName: Closed Authentication,
Open Authentication, Low Impact or No Authentication) that every edge port assigned without a template of its
own uses, and one editable profile per template at that site (`sda/authenticationProfiles`: 802.1X/MAB order,
the 802.1X-to-MAB fallback timer, wake on LAN, single or unlimited hosts, BPDU guard for Closed, voice VLAN,
and the pre-authentication ACL for Low Impact). New fabric sites copy the global profiles. ISE's policy only
works when the template matches it: Closed lets nothing but EAPoL through until ISE answers, Low Impact lets
the pre-auth ACL (DHCP, DNS by default) through, Open lets everything through. catc_assign_fabric_port keeps
its per-port template.
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
from typing import Annotated, Any, Literal

from fastmcp import Context
from pydantic import BaseModel, Field

from catc_mcp._core import (
    Confirm,
    Plan,
    ToolRegistrar,
    UpstreamError,
    get_client,
    preview_or_apply,
)
from catc_mcp.client import CatcApp
from catc_mcp.common import pick
from catc_mcp.safety import device_limit_blockers
from catc_mcp.tools.sda import SDA, AuthProfile, FabricRef, edge_labels, resolve_fabric, sda_job, sda_list

PROFILE_FIELDS = [
    "authenticationProfileName",
    "authenticationOrder",
    "dot1xToMabFallbackTimeout",
    "numberOfHosts",
    "wakeOnLan",
    "isBpduGuardEnabled",
    "isVoiceVlanEnabled",
    "preAuthAcl",
    "preAuthAclIpV6",
    "id",
]
NO_AUTH = "No Authentication"


class AclRule(BaseModel):
    """One pre-authentication ACL entry (Low Impact): what a port lets through before ISE answers."""

    action: Literal["PERMIT", "DENY"]
    protocol: Literal["UDP", "TCP", "TCP_UDP"]
    port: Literal["DOMAIN", "BOOTPC", "BOOTPS"]


def port_template(p: dict[str, Any]) -> str | None:
    t = p.get("authenticateTemplateName")
    return str(t) if t else None


async def auth_state(app: CatcApp, fabric: dict[str, Any]) -> dict[str, Any]:
    """The fabric's default template, its profiles, its edges and the ports that override the default."""
    fid = str(fabric["id"])
    profiles = await sda_list(app, "authenticationProfiles", {"fabricId": fid})
    devices = await sda_list(app, "fabricDevices", {"fabricId": fid})
    ports = await sda_list(app, "portAssignments", {"fabricId": fid})
    default = fabric.get("authenticationProfileName")
    user_ports = [p for p in ports if p.get("connectedDeviceType") in (None, "USER_DEVICE")]
    return {
        "default": default,
        "profiles": profiles,
        "edges": [d for d in devices if "EDGE_NODE" in (d.get("deviceRoles") or [])],
        "ports_on_default": [p for p in user_ports if port_template(p) in (None, default)],
        "ports_overriding": [p for p in user_ports if port_template(p) not in (None, default)],
    }


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="Fabric authentication profile")
    async def catc_get_fabric_authentication_profile(
        ctx: Context,
        fabric_site: FabricRef,
        include_global: Annotated[
            bool, Field(description="Also return the global profiles new fabric sites start from")
        ] = False,
    ) -> dict[str, Any]:
        """The host onboarding (authentication template) posture of an SD-Access fabric site. Returns the
        default template its edge ports use (Closed Authentication, Open Authentication, Low Impact or No
        Authentication), the settings of each template profile at the site (802.1X/MAB order, 802.1X-to-MAB
        fallback timeout, single/unlimited hosts, wake on LAN, BPDU guard, voice VLAN, the Low Impact pre-auth
        ACL), the edge count, and the edge ports that use the default vs override it with their own template.
        Change it with catc_set_fabric_authentication_profile."""
        app: CatcApp = get_client(ctx)
        fabric, fsite = await resolve_fabric(app, fabric_site)
        st = await auth_state(app, fabric)
        out: dict[str, Any] = {
            "fabric_site": fsite.get("nameHierarchy"),
            "fabric_id": fabric.get("id"),
            "default_template": st["default"],
            "profiles": [pick(p, PROFILE_FIELDS) for p in st["profiles"]],
            "edges": len(st["edges"]),
            "ports_on_default": len(st["ports_on_default"]),
            "ports_overriding": [
                {
                    "networkDeviceId": p.get("networkDeviceId"),
                    "interface": p.get("interfaceName"),
                    "template": port_template(p),
                }
                for p in st["ports_overriding"]
            ],
        }
        if st["default"] == NO_AUTH:
            out["note"] = (
                "No Authentication: edge ports on the default template send nothing to ISE (open ports)."
            )
        if include_global:
            out["global_profiles"] = [
                pick(p, PROFILE_FIELDS)
                for p in await sda_list(
                    app, "authenticationProfiles", {"isGlobalAuthenticationProfile": True}
                )
            ]
        return out

    @reg.dangerous(title="Set fabric authentication profile", task=True)
    async def catc_set_fabric_authentication_profile(
        ctx: Context,
        fabric_site: FabricRef,
        template: Annotated[AuthProfile, Field(description="The authentication template to set or edit")],
        make_default: Annotated[
            bool,
            Field(
                description="Make it the fabric site's default template (edge ports without their own "
                "template follow it); false: only edit that template's settings"
            ),
        ] = True,
        authentication_order: Annotated[
            Literal["dot1x", "mac"] | None, Field(description="Try 802.1X first (dot1x) or MAB first (mac)")
        ] = None,
        dot1x_to_mab_fallback_s: Annotated[
            int | None, Field(ge=3, le=120, description="Seconds of 802.1X before falling back to MAB")
        ] = None,
        number_of_hosts: Annotated[
            Literal["Single", "Unlimited"] | None, Field(description="Hosts allowed per port")
        ] = None,
        wake_on_lan: Annotated[bool | None, Field(description="Wake on LAN")] = None,
        bpdu_guard: Annotated[
            bool | None, Field(description="BPDU guard (Closed Authentication only)")
        ] = None,
        voice_vlan: Annotated[bool | None, Field(description="Voice VLAN on the template's ports")] = None,
        pre_auth_acl_enabled: Annotated[
            bool | None, Field(description="Low Impact: turn the pre-authentication ACL on or off")
        ] = None,
        pre_auth_acl_implicit_action: Annotated[
            Literal["PERMIT", "DENY"] | None,
            Field(description="Low Impact: what the pre-auth ACL does with everything its rules don't match"),
        ] = None,
        pre_auth_acl_rules: Annotated[
            list[AclRule] | None,
            Field(
                max_length=3, description="Low Impact: the IPv4 pre-auth ACL rules (up to 3; replaces them)"
            ),
        ] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Set an SD-Access fabric site's authentication template and/or edit that template's settings.
        make_default=true (default) makes `template` the site's default: every edge port without a template
        of its own moves to it. The settings (802.1X/MAB order, fallback timer, hosts, wake on LAN, BPDU
        guard for Closed, voice VLAN, pre-auth ACL for Low Impact) edit that template's profile at this site
        only; unset ones keep their value. Catalyst Center pushes the template to every edge of the fabric
        site, and clients on affected ports may re-authenticate. Preview-first: shows current -> new, the
        edges and the ports that follow the default."""
        app: CatcApp = get_client(ctx)
        fabric, fsite = await resolve_fabric(app, fabric_site)
        st = await auth_state(app, fabric)
        site_name = fsite.get("nameHierarchy")
        settings: dict[str, Any] = {
            k: v
            for k, v in {
                "authenticationOrder": authentication_order,
                "dot1xToMabFallbackTimeout": dot1x_to_mab_fallback_s,
                "numberOfHosts": number_of_hosts,
                "wakeOnLan": wake_on_lan,
                "isBpduGuardEnabled": bpdu_guard,
                "isVoiceVlanEnabled": voice_vlan,
            }.items()
            if v is not None
        }
        acl_change = {
            k: v
            for k, v in {
                "enabled": pre_auth_acl_enabled,
                "implicitAction": pre_auth_acl_implicit_action,
                "accessContracts": [r.model_dump() for r in pre_auth_acl_rules]
                if pre_auth_acl_rules is not None
                else None,
            }.items()
            if v is not None
        }
        blockers: list[str] = []
        if template == NO_AUTH and (settings or acl_change):
            blockers.append("No Authentication has no profile settings; set only the default template.")
        if bpdu_guard is not None and template != "Closed Authentication":
            blockers.append("bpdu_guard applies to Closed Authentication only.")
        if acl_change and template != "Low Impact":
            blockers.append("The pre-authentication ACL applies to Low Impact only.")
        profile = next((p for p in st["profiles"] if p.get("authenticationProfileName") == template), None)
        if (settings or acl_change) and template != NO_AUTH and profile is None:
            blockers.append(
                f"{site_name} has no {template} profile (catc_get_fabric_authentication_profile lists them)."
            )
        steps: list[tuple[str, str, Any]] = []
        changes: dict[str, Any] = {}
        if make_default and template != st["default"]:
            body = {
                k: v
                for k, v in {
                    "id": fabric.get("id"),
                    "siteId": fabric.get("siteId"),
                    "authenticationProfileName": template,
                    "isPubSubEnabled": fabric.get("isPubSubEnabled"),
                    "underlayTransport": fabric.get("underlayTransport"),
                }.items()
                if v is not None
            }
            steps.append(("default template", f"{SDA}/fabricSites", [body]))
            changes["default_template"] = {"from": st["default"], "to": template}
        if profile is not None and (settings or acl_change):
            new = {k: profile.get(k) for k in PROFILE_FIELDS if profile.get(k) is not None}
            new["fabricId"] = fabric.get("id")
            new.update(settings)
            if acl_change:
                new["preAuthAcl"] = {**(profile.get("preAuthAcl") or {}), **acl_change}
            if template != "Closed Authentication":
                new.pop("isBpduGuardEnabled", None)
            if template != "Low Impact":
                new.pop("preAuthAcl", None)
                new.pop("preAuthAclIpV6", None)
            diff = {
                k: {"from": profile.get(k), "to": new.get(k)} for k in new if profile.get(k) != new.get(k)
            }
            diff.pop("fabricId", None)
            if diff:
                steps.append((f"{template} profile", f"{SDA}/authenticationProfiles", [new]))
                changes[f"{template} profile"] = diff
        if not steps and not blockers:
            blockers.append(
                f"Nothing to change: {site_name} already uses {st['default']}"
                + (" with those settings." if settings or acl_change else ".")
            )
        edges = st["edges"]
        blockers += device_limit_blockers(app, len(edges), "edge devices")
        follow = len(st["ports_on_default"]) if "default_template" in changes else None
        parts = [
            f"default template {c['from']} -> {c['to']}" if k == "default_template" else f"edit the {k}"
            for k, c in changes.items()
        ]
        plan = Plan(
            f"Authentication at fabric site {site_name}: " + ("; ".join(parts) or "no change"),
            details={
                "changes": changes,
                "edges": await edge_labels(app, edges),
                "ports_following_the_default": follow,
                "ports_with_their_own_template": len(st["ports_overriding"]),
                "requests": [{"method": "PUT", "path": p, "body": b} for _, p, b in steps],
            },
            side_effects=[
                f"Catalyst Center pushes the authentication template to {len(edges)} edge device(s).",
                "Clients on ports that follow the changed template may re-authenticate (a short outage).",
            ],
            fingerprint={"fabric": fabric, "profile": profile, "default": st["default"]},
            blockers=blockers,
            blast_radius=len(edges) or None,
        )

        async def apply() -> Any:
            done: list[str] = []
            for label, path, body in steps:  # the API asks for one request at a time
                try:
                    await sda_job(app, "PUT", path, body, ctx, f"set {label}")
                except UpstreamError as e:
                    raise UpstreamError(f"Failed at '{label}' (done: {done or 'nothing'}): {e}") from e
                done.append(label)
            after = await auth_state(app, (await resolve_fabric(app, str(fabric["id"])))[0])
            now = next((p for p in after["profiles"] if p.get("authenticationProfileName") == template), None)
            return {
                "done": done,
                "default_template": after["default"],
                "profile": pick(now, PROFILE_FIELDS) if now else None,
            }

        return await preview_or_apply(
            ctx,
            tool="catc_set_fabric_authentication_profile",
            args={
                "fabric_site": fabric_site,
                "template": template,
                "make_default": make_default,
                "authentication_order": authentication_order,
                "dot1x_to_mab_fallback_s": dot1x_to_mab_fallback_s,
                "number_of_hosts": number_of_hosts,
                "wake_on_lan": wake_on_lan,
                "bpdu_guard": bpdu_guard,
                "voice_vlan": voice_vlan,
                "pre_auth_acl_enabled": pre_auth_acl_enabled,
                "pre_auth_acl_implicit_action": pre_auth_acl_implicit_action,
                "pre_auth_acl_rules": [r.model_dump() for r in pre_auth_acl_rules]
                if pre_auth_acl_rules is not None
                else None,
            },
            confirm=confirm,
            plan=plan,
            apply=apply,
        )
