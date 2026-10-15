"""Network profiles for sites (D3): attach Day-N templates to profiles and assign profiles to sites.

Templates attached to a network profile are what provisioning applies to devices at the profile's
sites. The 3.2.2 API can create switching profiles (`/sda/switchNetworkProfiles`) but not routing
or wireless ones; those are created once in the UI (Design > Network Profiles)."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import asyncio
from typing import Annotated, Any

from fastmcp import Context
from pydantic import Field
from stutters_mcp_core import (
    Confirm,
    InvalidRequest,
    NotFound,
    Plan,
    ToolRegistrar,
    get_client,
    preview_or_apply,
)
from stutters_mcp_core.http import fetch_all

from catc_mcp.client import CatcApp, safe_id
from catc_mcp.common import ensure_list, is_uuid, pick, resolve_site, resolve_template

NP = "/dna/intent/api/v1/networkProfilesForSites"
TPL = "/dna/intent/api/v1/templates"
SWITCH_PROFILES = "/dna/intent/api/v1/sda/switchNetworkProfiles"

ProfileRef = Annotated[str, Field(description="Network profile name or id (catc_list_network_profiles)")]


async def list_profiles(app: CatcApp) -> list[dict[str, Any]]:
    page = await fetch_all(app.pager, app.api, NP, cap=2000)
    return [p for p in page.items if isinstance(p, dict)]


async def resolve_profile(app: CatcApp, ref: str) -> dict[str, Any]:
    ref = ref.strip()
    if not ref:
        raise InvalidRequest("Give a network profile name or id.")
    profiles = await list_profiles(app)
    if is_uuid(ref):
        found = [p for p in profiles if p.get("id") == ref]
    else:
        found = [p for p in profiles if str(p.get("name", "")).lower() == ref.lower()]
    if len(found) == 1:
        return found[0]
    if len(found) > 1:
        raise InvalidRequest(f"Profile name {ref!r} is ambiguous; use its id.")
    names = ", ".join(str(p.get("name")) for p in profiles[:20]) or "none"
    raise NotFound(f"No network profile {ref!r}. Profiles: {names}.")


async def profile_template_ids(app: CatcApp, profile_id: str) -> dict[str, str]:
    """{template id: name} attached to a profile."""
    data = await app.get_response(f"{NP}/{safe_id(profile_id, 'profile id')}/templates")
    return {str(t.get("id")): str(t.get("name")) for t in ensure_list(data) if isinstance(t, dict)}


async def template_profile_ids(app: CatcApp, template_id: str) -> dict[str, str]:
    """{profile id: name} a template is attached to."""
    data = await app.get_response(f"{TPL}/{safe_id(template_id, 'template id')}/networkProfilesForSites")
    return {str(p.get("id")): str(p.get("name")) for p in ensure_list(data) if isinstance(p, dict)}


async def profile_site_ids(app: CatcApp, profile_id: str) -> list[str]:
    page = await fetch_all(
        app.pager, app.api, f"{NP}/{safe_id(profile_id, 'profile id')}/siteAssignments", cap=5000
    )
    return [str(s.get("id")) for s in page.items if isinstance(s, dict) and s.get("id")]


async def site_names(app: CatcApp, ids: list[str]) -> list[str]:
    if not ids:
        return []
    page = await fetch_all(app.pager, app.api, "/dna/intent/api/v1/sites", cap=20_000)
    by_id = {s.get("id"): s.get("nameHierarchy") for s in page.items if isinstance(s, dict)}
    return sorted(str(by_id.get(i, i)) for i in ids)


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="Get network profile")
    async def catc_get_network_profile(ctx: Context, profile: ProfileRef) -> dict[str, Any]:
        """One network profile: its type, the Day-N CLI templates attached to it and the sites it is
        assigned to (by name). Provisioning a device at one of those sites applies the templates."""
        app: CatcApp = get_client(ctx)
        p = await resolve_profile(app, profile)
        pid = str(p["id"])
        tpls, sites = await asyncio.gather(profile_template_ids(app, pid), profile_site_ids(app, pid))
        return {
            **pick(p, ["name", "type", "id"]),
            "templates": [{"name": n, "id": i} for i, n in tpls.items()],
            "sites": await site_names(app, sites),
        }

    @reg.write(title="Create switching profile")
    async def catc_create_switching_profile(
        ctx: Context,
        name: Annotated[str, Field(min_length=1, max_length=128, description="Profile name")],
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Create an empty switching network profile, to attach Day-N templates to and assign to
        sites. Routing and wireless profiles can't be created through the 3.2.2 API (use the UI:
        Design > Network Profiles). Preview-first; refuses a duplicate name."""
        app: CatcApp = get_client(ctx)
        body = [{"profileName": name}]
        dup = [p for p in await list_profiles(app) if str(p.get("name", "")).lower() == name.lower()]
        plan = Plan(
            f"Create switching profile {name}",
            details={"method": "POST", "path": SWITCH_PROFILES, "body": body},
            blockers=[f"A network profile named {name!r} already exists."] if dup else [],
        )

        async def apply() -> Any:
            job = await app.run_job("POST", SWITCH_PROFILES, body, ctx=ctx, what="create profile")
            created = [p for p in await list_profiles(app) if p.get("name") == name]
            return {"name": name, "profile_id": created[0].get("id") if created else None, **job}

        return await preview_or_apply(
            ctx,
            tool="catc_create_switching_profile",
            args={"name": name},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    async def _attach(
        ctx: Context, template: str, profiles: list[str], confirm: str | None, detach: bool
    ) -> Any:
        app: CatcApp = get_client(ctx)
        tool = "catc_detach_template_from_profile" if detach else "catc_attach_template_to_profile"
        t = await resolve_template(app, template)
        tid = str(t.get("templateId") or t.get("id"))
        targets = [await resolve_profile(app, p) for p in profiles]
        current = await template_profile_ids(app, tid)
        todo = [p for p in targets if (str(p["id"]) in current) == detach]
        skipped = [str(p["name"]) for p in targets if p not in todo]
        verb = "Detach" if detach else "Attach"
        blockers = []
        if not todo:
            blockers.append(
                f"Nothing to do: {template!r} is {'not ' if detach else 'already '}attached to "
                f"{', '.join(skipped)}."
            )
        plan = Plan(
            f"{verb} template {t.get('projectName', '')}/{t.get('name')} {'from' if detach else 'to'} "
            f"{', '.join(str(p['name']) for p in todo) or 'nothing'}",
            details={
                "template_id": tid,
                "currently_attached_to": sorted(current.values()),
                "profiles": [str(p["name"]) for p in todo],
                "unchanged": skipped,
            },
            fingerprint=sorted(current),
            blockers=blockers,
            side_effects=[]
            if detach
            else ["Devices provisioned or re-provisioned at the profiles' sites get this template."],
        )

        async def apply() -> Any:
            ids = [str(p["id"]) for p in todo]
            if detach:
                for pid in ids:
                    await app.run_job(
                        "DELETE", f"{TPL}/{tid}/networkProfilesForSites/{pid}", ctx=ctx, what="detach"
                    )
            else:
                body = {"items": [{"profileId": i} for i in ids]}
                await app.run_job(
                    "POST", f"{TPL}/{tid}/networkProfilesForSites/bulk", body, ctx=ctx, what="attach"
                )
            after = await template_profile_ids(app, tid)
            return {"template": t.get("name"), "attached_to": sorted(after.values())}

        return await preview_or_apply(
            ctx,
            tool=tool,
            args={"template": template, "profiles": profiles},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.write(title="Attach template to network profiles")
    async def catc_attach_template_to_profile(
        ctx: Context,
        template: Annotated[str, Field(description="Day-N template 'Project/Name', name or id")],
        profiles: Annotated[
            list[str], Field(min_length=1, max_length=20, description="Profile names or ids")
        ],
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Attach a Day-N CLI template to network profiles. When devices at the profiles' sites are
        provisioned (catc_provision_devices), Catalyst Center applies the template's committed
        version. Preview-first; shows where the template is attached now and skips profiles it is
        already on."""
        result: dict[str, Any] = await _attach(ctx, template, profiles, confirm, detach=False)
        return result

    @reg.write(title="Detach template from network profiles")
    async def catc_detach_template_from_profile(
        ctx: Context,
        template: Annotated[str, Field(description="Day-N template 'Project/Name', name or id")],
        profiles: Annotated[
            list[str], Field(min_length=1, max_length=20, description="Profile names or ids")
        ],
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Detach a Day-N CLI template from network profiles. Configuration already pushed to devices
        stays; later provisioning no longer applies the template. Preview-first."""
        result: dict[str, Any] = await _attach(ctx, template, profiles, confirm, detach=True)
        return result

    async def _assign(
        ctx: Context, profile: str, sites: list[str], confirm: str | None, unassign: bool
    ) -> Any:
        app: CatcApp = get_client(ctx)
        tool = "catc_unassign_profile_from_sites" if unassign else "catc_assign_profile_to_sites"
        p = await resolve_profile(app, profile)
        pid = str(p["id"])
        targets = [await resolve_site(app, s) for s in sites]
        current = await profile_site_ids(app, pid)
        todo = [s for s in targets if (str(s["id"]) in current) == unassign]
        skipped = [str(s.get("nameHierarchy")) for s in targets if s not in todo]
        blockers = []
        if not todo:
            blockers.append(
                f"Nothing to do: {p.get('name')} is {'not ' if unassign else 'already '}assigned to "
                f"{', '.join(skipped)}."
            )
        verb = "Unassign" if unassign else "Assign"
        plan = Plan(
            f"{verb} profile {p.get('name')} {'from' if unassign else 'to'} "
            f"{', '.join(str(s.get('nameHierarchy')) for s in todo) or 'nothing'}",
            details={
                "profile_id": pid,
                "currently_assigned": await site_names(app, current),
                "sites": [str(s.get("nameHierarchy")) for s in todo],
                "unchanged": skipped,
            },
            fingerprint=sorted(current),
            blockers=blockers,
        )

        async def apply() -> Any:
            ids = [str(s["id"]) for s in todo]
            if unassign:
                for sid in ids:
                    await app.run_job("DELETE", f"{NP}/{pid}/siteAssignments/{sid}", ctx=ctx, what="unassign")
            else:
                body = {"items": [{"id": i} for i in ids]}
                await app.run_job("POST", f"{NP}/{pid}/siteAssignments/bulk", body, ctx=ctx, what="assign")
            return {
                "profile": p.get("name"),
                "sites": await site_names(app, await profile_site_ids(app, pid)),
            }

        return await preview_or_apply(
            ctx, tool=tool, args={"profile": profile, "sites": sites}, confirm=confirm, plan=plan, apply=apply
        )

    @reg.write(title="Assign network profile to sites")
    async def catc_assign_profile_to_sites(
        ctx: Context,
        profile: ProfileRef,
        sites: Annotated[
            list[str], Field(min_length=1, max_length=50, description="Site hierarchies or ids")
        ],
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Assign a network profile to sites (areas, buildings or floors; child sites inherit it).
        Devices provisioned at those sites then get the profile's templates. Preview-first; skips
        sites already assigned."""
        result: dict[str, Any] = await _assign(ctx, profile, sites, confirm, unassign=False)
        return result

    @reg.write(title="Unassign network profile from sites")
    async def catc_unassign_profile_from_sites(
        ctx: Context,
        profile: ProfileRef,
        sites: Annotated[
            list[str], Field(min_length=1, max_length=50, description="Site hierarchies or ids")
        ],
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Remove a network profile's assignment from sites. Device configuration stays; later
        provisioning at those sites no longer uses the profile. Preview-first."""
        result: dict[str, Any] = await _assign(ctx, profile, sites, confirm, unassign=True)
        return result
