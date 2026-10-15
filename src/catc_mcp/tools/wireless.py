"""Wireless (roadmap D14): SSIDs, wireless network profiles and Catalyst 9800 WLC provisioning.

SSIDs and wireless profiles are design objects (write tier: no device changes until a WLC is provisioned).
Provisioning a WLC pushes the WLANs, policy profiles and tags of the wireless profiles assigned to its
managed AP locations (dangerous tier). Workflow: catc_create_ssid -> catc_create_wireless_profile ->
catc_assign_profile_to_sites (the AP locations, e.g. a floor) -> assign the WLC to a building
(catc_assign_devices_to_site) -> catc_provision_wireless_controller -> catc_get_wireless_controller.
Access points, RF and wireless clients need real APs (CML has none) and are left to catc_api_call.
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import hashlib
import hmac
import os
from datetime import UTC, datetime
from typing import Annotated, Any, Literal

from fastmcp import Context
from pydantic import Field, SecretStr
from stutters_mcp_core import (
    Confirm,
    InvalidRequest,
    NotFound,
    Plan,
    ToolRegistrar,
    compact,
    get_client,
    object_result,
    preview_or_apply,
)
from stutters_mcp_core.http import fetch_all

from catc_mcp.client import CatcApp, safe_id
from catc_mcp.common import ensure_list, gather_sections, resolve_device, resolve_site
from catc_mcp.safety import device_limit_blockers
from catc_mcp.tools.ops_writes import brief, device_site
from catc_mcp.tools.profiles import profile_site_ids

MASK = "********"
# Per-process key: confirm tokens bind a keyed digest of the passphrase, never the value or a plain hash.
_DIGEST_KEY = os.urandom(32)
PROFILES = "/dna/intent/api/v1/wirelessProfiles"
WLC = "/dna/intent/api/v1/wirelessControllers"
Security = Literal[
    "OPEN", "WPA2_PERSONAL", "WPA2_ENTERPRISE", "WPA3_PERSONAL", "WPA2_WPA3_PERSONAL", "WPA3_ENTERPRISE"
]
Radio = Literal[
    "Triple band operation(2.4GHz, 5GHz and 6GHz)",
    "2.4 and 5 GHz",
    "5GHz only",
    "2.4GHz only",
    "6GHz only",
]
# AKM + cipher per security type (Catalyst Center refuses a non-open SSID without both).
AKM = {
    "WPA2_PERSONAL": {"isAuthKeyPSK": True},
    "WPA2_ENTERPRISE": {"isAuthKey8021x": True},
    "WPA3_PERSONAL": {"isAuthKeySae": True},
    "WPA2_WPA3_PERSONAL": {"isAuthKeyPSK": True, "isAuthKeySae": True},
    "WPA3_ENTERPRISE": {"isAuthKey8021x_SHA256": True},
}


def ssids_path(site_id: str) -> str:
    return f"/dna/intent/api/v1/sites/{safe_id(site_id, 'site id')}/wirelessSettings/ssids"


async def site_ssids(app: CatcApp, site_id: str) -> list[dict[str, Any]]:
    page = await fetch_all(app.pager, app.api, ssids_path(site_id), cap=2000)
    return [s for s in page.items if isinstance(s, dict)]


async def wireless_profiles(app: CatcApp) -> list[dict[str, Any]]:
    page = await fetch_all(app.pager, app.api, PROFILES, cap=2000)
    return [p for p in page.items if isinstance(p, dict)]


def profile_ssids(profile: dict[str, Any]) -> list[str]:
    return [str(s.get("ssidName")) for s in ensure_list(profile.get("ssidDetails")) if isinstance(s, dict)]


def provision_status(st: Any) -> Any:
    """The WLC provisioning status without ids, with a readable time."""
    if not isinstance(st, dict):
        return st
    out = {k: v for k, v in st.items() if k not in ("networkDeviceId", "siteId", "deviceName")}
    ts = out.pop("lastProvisionedTimeStamp", None)
    try:
        out["lastProvisioned"] = datetime.fromtimestamp(int(ts) / 1000, tz=UTC).strftime("%Y-%m-%d %H:%M UTC")
    except (TypeError, ValueError, OverflowError, OSError):
        if ts:
            out["lastProvisioned"] = ts
    return out


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="Wireless controller")
    async def catc_get_wireless_controller(
        ctx: Context,
        device: Annotated[str, Field(description="WLC hostname, management IP, serial or id")],
    ) -> Any:
        """A Catalyst 9800 WLC as Catalyst Center sees it: provisioning status, primary managed AP locations
        and the SSIDs deployed on it (admin status, managed by Catalyst Center or not)."""
        app: CatcApp = get_client(ctx)
        dev = await resolve_device(app, device)
        did = safe_id(str(dev["id"]), "device id")
        sec, errors = await gather_sections(
            {
                "provision_status": app.get_response(f"{WLC}/{did}/provisionStatus"),
                "managed_ap_locations": app.get_response(f"{WLC}/{did}/primaryManagedApLocations"),
                "ssids": app.get_response(f"{WLC}/{did}/ssidDetails"),
            }
        )
        locs = sec.get("managed_ap_locations")
        if isinstance(locs, dict):
            locs = locs.get("managedApLocations", locs)
        out: dict[str, Any] = {
            "device": brief([dev])[0],
            "family": dev.get("family"),
            "site": await device_site(app, did),
            "provision_status": provision_status(sec.get("provision_status")),
            "managed_ap_locations": [loc.get("siteNameHierarchy") or loc for loc in ensure_list(locs) if loc],
            "ssids": [
                compact(
                    {k: s.get(k) for k in ("ssidName", "wlanId", "wlanProfileName", "adminStatus", "managed")}
                )
                for s in ensure_list(sec.get("ssids"))
                if isinstance(s, dict)
            ],
        }
        if errors:
            out["unavailable"] = errors
        return object_result(out)

    @reg.write(title="Create SSID")
    async def catc_create_ssid(
        ctx: Context,
        ssid: Annotated[str, Field(min_length=1, max_length=32, description="SSID (network name)")],
        security: Annotated[Security, Field(description="Security type")],
        passphrase: Annotated[
            SecretStr | None,
            Field(description="PERSONAL security: the pre-shared key, 8-63 characters (never echoed)"),
        ] = None,
        site: Annotated[str, Field(description="Site the SSID is defined at (default Global)")] = "Global",
        wlan_profile_name: Annotated[
            str | None,
            Field(max_length=32, description="WLAN profile name on the WLC (default '<ssid>_profile')"),
        ] = None,
        radio: Annotated[
            Radio, Field(description="Radio policy")
        ] = "Triple band operation(2.4GHz, 5GHz and 6GHz)",
        guest: Annotated[bool, Field(description="Guest WLAN type instead of Enterprise")] = False,
        broadcast: Annotated[bool, Field(description="Broadcast the SSID")] = True,
        enabled: Annotated[bool, Field(description="Admin state on the WLC")] = True,
        auth_servers: Annotated[
            list[str] | None,
            Field(description="ENTERPRISE: AAA server IPs (default: the site's AAA settings, e.g. ISE)"),
        ] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Define an SSID (WLAN) in network design. Nothing reaches a WLC until a wireless profile with this
        SSID is assigned to AP locations and the WLC is provisioned. Preview-first; passphrases are masked."""
        app: CatcApp = get_client(ctx)
        s = await resolve_site(app, site)
        personal = security.endswith("PERSONAL")
        if personal and (passphrase is None or not 8 <= len(passphrase.get_secret_value()) <= 63):
            raise InvalidRequest("PERSONAL security needs a passphrase of 8-63 characters.")
        if not personal and passphrase is not None:
            raise InvalidRequest("A passphrase only applies to PERSONAL security.")
        existing = [x for x in await site_ssids(app, str(s["id"])) if x.get("ssid") == ssid]
        blockers = [f"SSID {ssid} already exists at {s.get('nameHierarchy')}."] if existing else []
        body: dict[str, Any] = {
            "ssid": ssid,
            "authType": security,
            "wlanType": "Guest" if guest else "Enterprise",
            "profileName": wlan_profile_name or f"{ssid}_profile",
            "ssidRadioType": radio,
            "isBroadcastSSID": broadcast,
            "isEnabled": enabled,
        }
        if security != "OPEN":
            body |= AKM[security] | {"rsnCipherSuiteCcmp128": True}
        if auth_servers:
            body["authServers"] = auth_servers
        shown = dict(body)
        if passphrase is not None:
            shown["passphrase"] = MASK
        path = ssids_path(str(s["id"]))
        plan = Plan(
            f"Create {security} SSID {ssid} at {s.get('nameHierarchy')}",
            details={"method": "POST", "path": path, "body": shown},
            fingerprint={"site": s["id"], "existing": existing},
            blockers=blockers,
        )

        async def apply() -> Any:
            send = dict(body)
            if passphrase is not None:
                send["passphrase"] = passphrase.get_secret_value()
            job = await app.run_job("POST", path, send, ctx=ctx, what="create SSID")
            made = [x for x in await site_ssids(app, str(s["id"])) if x.get("ssid") == ssid]
            return {**job, "ssid_id": made[0].get("id") if made else None}

        return await preview_or_apply(
            ctx,
            tool="catc_create_ssid",
            args={
                "ssid": ssid,
                "security": security,
                # bound by digest, so a different passphrase needs a new preview; never the value itself
                "passphrase": (
                    hmac.new(_DIGEST_KEY, passphrase.get_secret_value().encode(), hashlib.sha256).hexdigest()[
                        :16
                    ]
                    if passphrase
                    else None
                ),
                "site": site,
                "wlan_profile_name": wlan_profile_name,
                "radio": radio,
                "guest": guest,
                "broadcast": broadcast,
                "enabled": enabled,
                "auth_servers": auth_servers,
            },
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.write(title="Delete SSID")
    async def catc_delete_ssid(
        ctx: Context,
        ssid: Annotated[str, Field(description="SSID name")],
        site: Annotated[str, Field(description="Site it is defined at (default Global)")] = "Global",
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Delete an SSID from network design. Refused while a wireless profile still lists it (remove it
        from the profile or delete the profile first). Preview-first."""
        app: CatcApp = get_client(ctx)
        s = await resolve_site(app, site)
        found = [x for x in await site_ssids(app, str(s["id"])) if x.get("ssid") == ssid]
        if not found:
            raise NotFound(f"No SSID {ssid} at {s.get('nameHierarchy')} (catc_list_ssids).")
        users = [
            str(p.get("wirelessProfileName"))
            for p in await wireless_profiles(app)
            if ssid in profile_ssids(p)
        ]
        blockers = [f"Wireless profile(s) {', '.join(users)} still use {ssid}."] if users else []
        path = f"{ssids_path(str(s['id']))}/{safe_id(str(found[0]['id']), 'ssid id')}"
        plan = Plan(
            f"Delete SSID {ssid} at {s.get('nameHierarchy')}",
            details={
                "method": "DELETE",
                "path": path,
                "ssid": compact({k: found[0].get(k) for k in ("ssid", "authType", "profileName")}),
            },
            fingerprint={"ssid": found[0].get("id"), "users": users},
            blockers=blockers,
        )

        async def apply() -> Any:
            return await app.run_job("DELETE", path, ctx=ctx, what="delete SSID")

        return await preview_or_apply(
            ctx,
            tool="catc_delete_ssid",
            args={"ssid": ssid, "site": site},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.write(title="Create wireless profile")
    async def catc_create_wireless_profile(
        ctx: Context,
        name: Annotated[
            str, Field(min_length=1, max_length=100, description="Wireless network profile name")
        ],
        ssids: Annotated[
            list[str], Field(min_length=1, max_length=16, description="SSIDs (defined at Global)")
        ],
        interface: Annotated[
            str, Field(description="WLC interface the SSIDs' clients use (default 'management')")
        ] = "management",
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Create a wireless network profile that carries SSIDs. Assign it to the AP locations (sites) with
        catc_assign_profile_to_sites; WLC provisioning then pushes the SSIDs. Preview-first."""
        app: CatcApp = get_client(ctx)
        g = await resolve_site(app, "Global")
        defined = {str(x.get("ssid")) for x in await site_ssids(app, str(g["id"]))}
        blockers = [f"SSID {x} is not defined (catc_create_ssid)." for x in ssids if x not in defined]
        profiles = await wireless_profiles(app)
        if any(p.get("wirelessProfileName") == name for p in profiles):
            blockers.append(f"Wireless profile {name} already exists.")
        body = {
            "wirelessProfileName": name,
            "ssidDetails": [
                {"ssidName": x, "enableFabric": False, "interfaceName": interface} for x in ssids
            ],
        }
        plan = Plan(
            f"Create wireless profile {name} with {', '.join(ssids)}",
            details={"method": "POST", "path": PROFILES, "body": body},
            fingerprint={
                "defined": sorted(defined & set(ssids)),
                "names": sorted(str(p.get("wirelessProfileName")) for p in profiles),
            },
            blockers=blockers,
        )

        async def apply() -> Any:
            job = await app.run_job("POST", PROFILES, body, ctx=ctx, what="create wireless profile")
            made = [p for p in await wireless_profiles(app) if p.get("wirelessProfileName") == name]
            return {**job, "profile_id": made[0].get("id") if made else None}

        return await preview_or_apply(
            ctx,
            tool="catc_create_wireless_profile",
            args={"name": name, "ssids": ssids, "interface": interface},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.write(title="Delete wireless profile")
    async def catc_delete_wireless_profile(
        ctx: Context,
        name: Annotated[str, Field(description="Wireless profile name or id")],
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Delete a wireless network profile. Refused while it is assigned to sites (unassign with
        catc_unassign_profile_from_sites first). Preview-first."""
        app: CatcApp = get_client(ctx)
        found = [
            p for p in await wireless_profiles(app) if name in (p.get("wirelessProfileName"), p.get("id"))
        ]
        if not found:
            raise NotFound(f"No wireless profile {name} (catc_list_network_profiles).")
        prof = found[0]
        pid = safe_id(str(prof["id"]), "profile id")
        sites = await profile_site_ids(app, pid)  # a failed lookup must not hide an assignment
        blockers = [f"Assigned to {len(sites)} site(s); unassign it first."] if sites else []
        plan = Plan(
            f"Delete wireless profile {prof.get('wirelessProfileName')}",
            details={"method": "DELETE", "path": f"{PROFILES}/{pid}", "ssids": profile_ssids(prof)},
            fingerprint={"profile": prof, "sites": sites},
            blockers=blockers,
        )

        async def apply() -> Any:
            return await app.run_job("DELETE", f"{PROFILES}/{pid}", ctx=ctx, what="delete wireless profile")

        return await preview_or_apply(
            ctx,
            tool="catc_delete_wireless_profile",
            args={"name": name},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.dangerous(title="Provision wireless controller", task=True)
    async def catc_provision_wireless_controller(
        ctx: Context,
        device: Annotated[str, Field(description="Catalyst 9800 WLC (hostname, IP, serial or id)")],
        managed_ap_locations: Annotated[
            list[str],
            Field(
                min_length=1, max_length=50, description="Sites (floors/buildings) whose APs this WLC manages"
            ),
        ],
        skip_ap_provision: Annotated[
            bool, Field(description="Don't reprovision the APs joined to it (default true)")
        ] = True,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Provision a Catalyst 9800 WLC: set its primary managed AP locations, then push the WLANs, policy
        profiles and tags of the wireless profiles assigned to those sites (plus the site's AAA, DNS, NTP and
        telemetry settings). The WLC must be assigned to a building first (catc_assign_devices_to_site).
        Changes the WLC's configuration. Preview-first: lists the SSIDs that will be pushed."""
        app: CatcApp = get_client(ctx)
        dev = await resolve_device(app, device)
        did = safe_id(str(dev["id"]), "device id")
        blockers = device_limit_blockers(app, 1)
        if "Wireless Controller" not in str(dev.get("family")):
            blockers.append(f"{brief([dev])[0]} is a {dev.get('family')}, not a wireless controller.")
        at = await device_site(app, did)
        if not at:
            blockers.append("The WLC isn't assigned to a site; assign it to a building first.")
        locs = [await resolve_site(app, x) for x in managed_ap_locations]
        loc_ids = sorted({str(x["id"]) for x in locs})
        profiles = await wireless_profiles(app)
        pushed: dict[str, list[str]] = {}
        for p in profiles:
            # siteAssignments lists the sites a profile reaches, inherited child sites included, so an
            # exact id match also catches a profile assigned to the floor's building or area. A failed lookup
            # raises: the preview must not understate what gets pushed.
            sites = set(await profile_site_ids(app, str(p["id"])))
            if sites & set(loc_ids):
                pushed[str(p.get("wirelessProfileName"))] = profile_ssids(p)
        if not pushed:
            # Catalyst Center refuses the managed AP locations otherwise ("These sites are not associated to
            # any wireless profile").
            blockers.append(
                "No wireless profile is assigned to those AP locations (catc_create_wireless_profile, "
                "catc_assign_profile_to_sites); Catalyst Center refuses AP locations without one."
            )
        cur = await app.get_response(f"{WLC}/{did}/primaryManagedApLocations")
        cur_locs = cur.get("managedApLocations", []) if isinstance(cur, dict) else ensure_list(cur)
        current_ids = sorted(
            str(x.get("siteId")) for x in cur_locs if isinstance(x, dict) and x.get("siteId")
        )
        reassign = current_ids != loc_ids
        g = await resolve_site(app, "Global")
        wanted = {x for names in pushed.values() for x in names}
        ssid_defs = sorted(
            (
                {k: v for k, v in x.items() if k != "passphrase"}
                for x in await site_ssids(app, str(g["id"]))
                if x.get("ssid") in wanted
            ),
            key=lambda x: str(x.get("ssid")),
        )
        body = {"skipApProvision": skip_ap_provision}
        plan = Plan(
            f"Provision WLC {brief([dev])[0]} for {len(locs)} AP location(s)",
            details={
                "site": at,
                "managed_ap_locations": [x.get("nameHierarchy") for x in locs],
                "wireless_profiles_pushed": pushed,
                "current_ap_locations": current_ids,
                "current_ap_locations_kept": not reassign,
                "requests": [
                    f"POST {WLC}/{did}/assignManagedApLocations {{primaryManagedAPLocationsSiteIds}}",
                    f"POST {WLC}/{did}/provision {body}",
                ],
            },
            side_effects=["Pushes WLANs, policy profiles/tags and site settings to the WLC."],
            fingerprint={
                "device": did,
                "site": at,
                "locations": loc_ids,
                "current": current_ids,
                "pushed": pushed,
                "ssid_definitions": ssid_defs,
                "reachability": dev.get("reachabilityStatus"),
            },
            blockers=blockers,
            blast_radius=1,
        )

        async def apply() -> Any:
            assigned: Any = "unchanged"
            if reassign:
                assigned = await app.run_job(
                    "POST",
                    f"{WLC}/{did}/assignManagedApLocations",
                    {"primaryManagedAPLocationsSiteIds": loc_ids},
                    ctx=ctx,
                    what="assign managed AP locations",
                )
            provisioned = await app.run_job(
                "POST", f"{WLC}/{did}/provision", body, ctx=ctx, what="WLC provisioning"
            )
            return {"managed_ap_locations": assigned, "provisioned": provisioned}

        return await preview_or_apply(
            ctx,
            tool="catc_provision_wireless_controller",
            args={
                "device": device,
                "managed_ap_locations": managed_ap_locations,
                "skip_ap_provision": skip_ap_provision,
            },
            confirm=confirm,
            plan=plan,
            apply=apply,
        )
