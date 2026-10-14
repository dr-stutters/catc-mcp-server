"""Dangerous tier: operations that change device configuration or software, or delete things that
devices depend on. Registered only with MCP_ENABLE_WRITES and MCP_ENABLE_DANGEROUS; all
preview-first."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import re
from typing import Annotated, Any

from fastmcp import Context
from pydantic import Field
from stutters_mcp_core import (
    Confirm,
    InvalidRequest,
    NotFound,
    Plan,
    ToolRegistrar,
    UpstreamError,
    compact,
    get_client,
    poll_until,
    preview_or_apply,
)
from stutters_mcp_core.http import fetch_all

from catc_mcp.client import CatcApp, job_ref
from catc_mcp.common import ensure_list, is_uuid, resolve_device, resolve_site, resolve_template
from catc_mcp.tools.discovery import resolve_discovery
from catc_mcp.tools.inventory import redact_config
from catc_mcp.tools.ops_writes import Devices, brief, resolve_devices
from catc_mcp.tools.sites import SITE_DETAIL_PATHS, all_sites
from catc_mcp.tools.templates import TemplateRef

TP = "/dna/intent/api/v1/template-programmer"
DeviceRef = Annotated[str, Field(description="Device hostname, management IP, serial number or id")]
ImageRef = Annotated[str, Field(description="Software image id or exact name (from catc_list_images)")]
Wait = Annotated[bool, Field(description="Wait for the operation to finish (default true)")]


async def resolve_image(app: CatcApp, ref: str) -> dict[str, Any]:
    ref = ref.strip()
    params = {"imported": "true"}
    found = ensure_list(await app.get_response("/dna/intent/api/v1/images", {**params, "name": ref}))
    for img in found:
        if isinstance(img, dict) and (
            img.get("id") == ref or str(img.get("name", "")).lower() == ref.lower()
        ):
            return img
    if is_uuid(ref):
        page = await fetch_all(app.pager, app.api, "/dna/intent/api/v1/images", params, cap=2000)
        for img in page.items:
            if isinstance(img, dict) and img.get("id") == ref:
                return img
    raise NotFound(f"No imported software image {ref!r}. Use catc_list_images(imported=true).")


def deploy_outcome(progress: Any) -> dict[str, Any]:
    """Interpret a template deploy task's progress text: deployment id and non-applicable targets."""
    text = str(progress or "")
    out: dict[str, Any] = {"progress": text}
    # Catalyst Center spells it "Deployemnt Id" in some releases.
    m = re.search(r"Deploy\w*\s+Id:\s*([0-9a-fA-F-]{36})", text, re.IGNORECASE)
    if m:
        out["deployment_id"] = m.group(1)
    if "None of the targets are applicable" in text:
        out["deployed"] = False
        na = re.search(r"nonApplicableTargets:\s*\{(.*?)\}", text)
        if na:
            out["not_applicable"] = na.group(1)
    return out


def register(reg: ToolRegistrar) -> None:
    @reg.dangerous(title="Deploy template")
    async def catc_deploy_template(
        ctx: Context,
        template: TemplateRef,
        devices: Devices,
        params: Annotated[
            dict[str, Any] | None,
            Field(description='Template variable values, applied to every device, e.g. {"vlan_id": 10}'),
        ] = None,
        force_push: Annotated[
            bool, Field(description="Push even if this version was already deployed to the device")
        ] = False,
        wait: Wait = True,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Deploy (push) a committed configuration template to devices. This changes the devices'
        running configuration. Preview-first: the preview renders the CLI for the first device and
        lists every target; nothing is pushed until you confirm. Uncommitted templates are refused
        (commit with catc_commit_template)."""
        app: CatcApp = get_client(ctx)
        ref = await resolve_template(app, template)
        tid = str(ref.get("templateId") or ref.get("id"))
        devs = await resolve_devices(app, devices)
        blockers = []
        if not ensure_list(ref.get("versionsInfo")):
            blockers.append(
                "The template has never been committed; commit it with catc_commit_template first."
            )
        rendered: Any = None
        try:
            prev = await app.api.put(
                f"{TP}/template/preview",
                {"templateId": tid, "params": params or {}, "deviceId": str(devs[0]["id"])},
            )
            if isinstance(prev, dict):
                rendered = redact_config(str(prev.get("cliPreview") or ""))
                if prev.get("validationErrors"):
                    blockers.append(
                        f"Template validation errors: {redact_config(str(prev['validationErrors']))}"
                    )
        except UpstreamError as e:
            rendered = f"(preview unavailable: {redact_config(str(e))[:200]})"
        body = {
            "templateId": tid,
            "forcePushTemplate": force_push,
            "targetInfo": [
                {"id": str(d["id"]), "type": "MANAGED_DEVICE_UUID", "params": params or {}} for d in devs
            ],
        }
        plan = Plan(
            f"Deploy template {ref.get('projectName')}/{ref.get('name')} to {len(devs)} device(s)",
            details={
                "devices": brief(devs),
                "rendered_cli_first_device": rendered,
                "note": "CLI rendered for the first device only; device-bound variables may differ.",
                "params": compact(params or {}),
            },
            side_effects=["Changes the running configuration of every listed device."],
            fingerprint={
                "template": tid,
                "devices": sorted(str(d["id"]) for d in devs),
                "versions": [
                    v.get("id") for v in ensure_list(ref.get("versionsInfo")) if isinstance(v, dict)
                ],
            },
            blockers=blockers,
        )

        async def apply() -> Any:
            started = await app.api.post("/dna/intent/api/v2/template-programmer/template/deploy", body)
            if not wait:
                return {"started": started, "check_with": "catc_get_task"}
            job = await app.wait_job(started, ctx=ctx, what="template deploy")
            out = {"task_id": job.get("task_id"), **deploy_outcome(job.get("progress"))}
            if dep := out.get("deployment_id"):
                status = await poll_until(
                    lambda: app.api.get(f"{TP}/template/deploy/status/{dep}"),
                    done=lambda s: (
                        str((s or {}).get("status", "")).upper() not in ("IN_PROGRESS", "INIT", "")
                    ),
                    timeout=app.settings.mcp_task_timeout,
                    ctx=ctx,
                    what="template deployment",
                )
                out["deployment"] = status
            return out

        return await preview_or_apply(
            ctx,
            tool="catc_deploy_template",
            args={
                "template": template,
                "devices": devices,
                "params": params,
                "force_push": force_push,
                "wait": wait,
            },
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.dangerous(title="Provision devices")
    async def catc_provision_devices(
        ctx: Context,
        devices: Devices,
        site: Annotated[str, Field(description="Building or floor to provision the devices to")],
        wait: Wait = True,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Provision wired network devices to a site: Catalyst Center pushes the site's network
        settings (AAA, DNS, NTP, syslog/SNMP/telemetry, etc.) to them. This changes device
        configuration. Preview-first."""
        app: CatcApp = get_client(ctx)
        s = await resolve_site(app, site)
        devs = await resolve_devices(app, devices)
        blockers = []
        if s.get("type") not in ("building", "floor"):
            blockers.append(f"Provision to a building or floor, not a {s.get('type')}.")
        body = [{"networkDeviceId": str(d["id"]), "siteId": s["id"]} for d in devs]
        plan = Plan(
            f"Provision {len(devs)} device(s) to {s.get('nameHierarchy')}",
            details={
                "devices": brief(devs),
                "site": {"nameHierarchy": s.get("nameHierarchy"), "id": s.get("id")},
                "method": "POST",
                "path": "/dna/intent/api/v1/sda/provisionDevices",
            },
            side_effects=["Pushes the site's network settings to each device."],
            fingerprint={"site": s["id"], "devices": sorted(str(d["id"]) for d in devs)},
            blockers=blockers,
        )

        async def apply() -> Any:
            started = await app.api.post("/dna/intent/api/v1/sda/provisionDevices", body)
            if not wait:
                return {"started": started, "check_with": "catc_get_task"}
            return await app.wait_job(started, ctx=ctx, what="provisioning")

        return await preview_or_apply(
            ctx,
            tool="catc_provision_devices",
            args={"devices": devices, "site": site, "wait": wait},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    async def _swim(
        ctx: Context, tool: str, device: str, image: str, wait: bool, confirm: str | None, activate: bool
    ) -> dict[str, Any]:
        app: CatcApp = get_client(ctx)
        dev = await resolve_device(app, device)
        img = await resolve_image(app, image)
        action = "activate" if activate else "distribute"
        path = f"/dna/intent/api/v1/networkDeviceImages/{dev['id']}/{action}"
        key = "installedImages" if activate else "distributedImages"
        body = {key: [{"id": img["id"]}]}
        effects = (
            ["Installs the image and RELOADS the device (outage)."]
            if activate
            else ["Copies the image to the device's flash (no reload)."]
        )
        plan = Plan(
            f"{action.title()} image {img.get('name')} ({img.get('version')}) on {dev.get('hostname')}",
            details={
                "device": brief([dev])[0],
                "current_version": dev.get("softwareVersion"),
                "image": {k: img.get(k) for k in ("name", "version", "id")},
                "method": "POST",
                "path": path,
            },
            side_effects=effects,
            fingerprint={"device": dev["id"], "image": img["id"], "action": action},
        )

        async def apply() -> Any:
            started = await app.api.post(path, body)
            if not wait or job_ref(started) is None:
                return {"started": started, "check_with": "catc_get_task"}
            return await app.wait_job(
                started, ctx=ctx, what=f"image {action}", timeout=max(app.settings.mcp_task_timeout, 1800)
            )

        return await preview_or_apply(
            ctx,
            tool=tool,
            args={"device": device, "image": image, "wait": wait},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.dangerous(title="Distribute software image")
    async def catc_distribute_image(
        ctx: Context, device: DeviceRef, image: ImageRef, wait: Wait = True, confirm: Confirm = None
    ) -> dict[str, Any]:
        """Copy an imported software image to a device's flash (SWIM distribution) without
        activating it. Preview-first. Activate it later with catc_activate_image."""
        return await _swim(ctx, "catc_distribute_image", device, image, wait, confirm, activate=False)

    @reg.dangerous(title="Activate software image")
    async def catc_activate_image(
        ctx: Context, device: DeviceRef, image: ImageRef, wait: Wait = True, confirm: Confirm = None
    ) -> dict[str, Any]:
        """Install and activate a software image on a device (distributing it first if needed). The
        device RELOADS: plan for an outage. Preview-first."""
        return await _swim(ctx, "catc_activate_image", device, image, wait, confirm, activate=True)

    @reg.dangerous(title="Delete site")
    async def catc_delete_site(
        ctx: Context,
        site: Annotated[str, Field(description="Area, building or floor to delete (id or name hierarchy)")],
        recursive: Annotated[
            bool, Field(description="Also delete every child site (deepest first); default false")
        ] = False,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Delete a site from the hierarchy. Without recursive, sites with children are refused;
        sites with assigned devices are always refused (move or delete the devices first).
        Preview-first: lists every site that would go."""
        app: CatcApp = get_client(ctx)
        s = await resolve_site(app, site)
        if s.get("type") == "global":
            raise InvalidRequest("The Global site can't be deleted.")
        sites, complete = await all_sites(app)
        prefix = str(s["nameHierarchy"]) + "/"
        children = [c for c in sites if str(c.get("nameHierarchy", "")).startswith(prefix)]
        doomed = sorted([*children, s], key=lambda c: -str(c.get("nameHierarchy", "")).count("/"))
        blockers = []
        if not complete:
            blockers.append("The site list was truncated, so children can't be enumerated safely.")
        if children and not recursive:
            blockers.append(f"{len(children)} child site(s) exist; pass recursive=true to delete them too.")
        devices = 0
        for c in doomed:
            if c.get("type") in ("building", "floor"):
                n = await app.get_response(
                    "/dna/intent/api/v1/networkDevices/assignedToSite/count", {"siteId": c["id"]}
                )
                devices += int(n.get("count", 0)) if isinstance(n, dict) else 0
        if devices:
            blockers.append(f"{devices} device(s) are assigned under this site; move or delete them first.")
        plan = Plan(
            f"Delete {s.get('type')} {s.get('nameHierarchy')}"
            + (f" and {len(children)} child site(s)" if children else ""),
            details={"sites": [c.get("nameHierarchy") for c in doomed]},
            fingerprint=sorted(str(c.get("id")) for c in doomed),
            blockers=blockers,
        )

        async def apply() -> Any:
            deleted: list[Any] = []
            for c in doomed:
                path = SITE_DETAIL_PATHS[str(c.get("type"))].format(id=c["id"])
                try:
                    await app.run_job("DELETE", path, ctx=ctx, what=f"delete {c.get('nameHierarchy')}")
                except UpstreamError as e:
                    return {"deleted": deleted, "failed": c.get("nameHierarchy"), "error": str(e)[:300]}
                deleted.append(c.get("nameHierarchy"))
            return {"deleted": deleted}

        return await preview_or_apply(
            ctx,
            tool="catc_delete_site",
            args={"site": site, "recursive": recursive},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.dangerous(title="Delete device")
    async def catc_delete_device(
        ctx: Context,
        device: DeviceRef,
        clean_config: Annotated[
            bool, Field(description="Also remove the configuration Catalyst Center pushed to the device")
        ] = False,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Remove a (non-provisioned) device from the Catalyst Center inventory; with clean_config
        also remove the settings Catalyst Center configured on it. Preview-first."""
        app: CatcApp = get_client(ctx)
        dev = await resolve_device(app, device)
        path = f"/dna/intent/api/v1/network-device/{dev['id']}"
        blockers = []
        try:
            prov = ensure_list(
                await app.get_response(
                    "/dna/intent/api/v1/sda/provisionDevices", {"networkDeviceId": dev["id"]}
                )
            )
        except UpstreamError:
            prov = []
        if prov:
            blockers.append(
                "The device is provisioned; un-provision it first (Catalyst Center refuses otherwise)."
            )
        plan = Plan(
            f"Delete device {dev.get('hostname')} ({dev.get('managementIpAddress')}) from inventory",
            details={
                "device": brief([dev])[0],
                "clean_config": clean_config,
                "method": "DELETE",
                "path": path,
            },
            side_effects=["Assurance history for the device is lost."]
            + (["Removes Catalyst Center-pushed config from the device."] if clean_config else []),
            fingerprint=dev.get("id"),
            blockers=blockers,
        )

        async def apply() -> Any:
            return await app.run_job(
                "DELETE",
                path,
                params={"cleanConfig": str(clean_config).lower()},
                ctx=ctx,
                what="delete device",
            )

        return await preview_or_apply(
            ctx,
            tool="catc_delete_device",
            args={"device": device, "clean_config": clean_config},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.dangerous(title="Delete discovery")
    async def catc_delete_discovery(
        ctx: Context,
        discovery: Annotated[str, Field(description="Discovery name or id (catc_list_discoveries)")],
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Delete a discovery job and its results (devices it added stay in the inventory).
        Preview-first."""
        app: CatcApp = get_client(ctx)
        d = await resolve_discovery(app, discovery)
        path = f"/dna/intent/api/v1/discovery/{d['id']}"
        plan = Plan(
            f"Delete discovery {d.get('name')}",
            details={
                "method": "DELETE",
                "path": path,
                "ip_ranges": d.get("ipAddressList"),
                "devices_found": d.get("numDevices"),
                "note": "Devices it added stay in the inventory.",
            },
            fingerprint=d.get("id"),
        )

        async def apply() -> Any:
            return await app.run_job("DELETE", path, ctx=ctx, what="delete discovery")

        return await preview_or_apply(
            ctx,
            tool="catc_delete_discovery",
            args={"discovery": discovery},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )
