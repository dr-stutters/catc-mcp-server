"""Dangerous tier: operations that change device configuration or software, or delete things that
devices depend on. Registered only with MCP_ENABLE_WRITES and MCP_ENABLE_DANGEROUS; all
preview-first."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import re
from datetime import UTC, datetime
from typing import Annotated, Any

from fastmcp import Context
from pydantic import Field

from catc_mcp._core import (
    Confirm,
    InvalidRequest,
    Plan,
    ToolRegistrar,
    UpstreamError,
    compact,
    get_client,
    poll_until,
    preview_or_apply,
)
from catc_mcp.client import CatcApp, job_ref, safe_id
from catc_mcp.common import ensure_list, resolve_device, resolve_site, resolve_template
from catc_mcp.safety import device_limit_blockers, resolve_targets
from catc_mcp.tools.archive import archive_files
from catc_mcp.tools.discovery import resolve_discovery
from catc_mcp.tools.inventory import redact_config
from catc_mcp.tools.ops_writes import Devices, brief, resolve_devices
from catc_mcp.tools.sites import SITE_DETAIL_PATHS, all_sites
from catc_mcp.tools.swim import resolve_image
from catc_mcp.tools.templates import TemplateRef, deployment_summary

TP = "/dna/intent/api/v1/template-programmer"
DeviceRef = Annotated[str, Field(description="Device hostname, management IP, serial number or id")]
ImageRef = Annotated[str, Field(description="Software image id or exact name (from catc_list_images)")]
Wait = Annotated[bool, Field(description="Wait for the operation to finish (default true)")]


async def provisioned_records(app: CatcApp, device_ids: list[str]) -> dict[str, dict[str, Any]]:
    """{device id: provisioning record ({"id", "siteId", "networkDeviceId"})} for provisioned devices."""
    out: dict[str, dict[str, Any]] = {}
    for did in device_ids:
        recs = ensure_list(
            await app.get_response("/dna/intent/api/v1/sda/provisionDevices", {"networkDeviceId": did})
        )
        for r in recs:
            if isinstance(r, dict) and r.get("networkDeviceId") == did:
                out[did] = r
    return out


def iso_ms(value: Any) -> str | None:
    """Catalyst Center epoch milliseconds -> ISO 8601 UTC."""
    try:
        return datetime.fromtimestamp(float(value) / 1000, tz=UTC).isoformat(timespec="seconds")
    except (TypeError, ValueError, OverflowError, OSError):
        return None


def _version_key(v: dict[str, Any]) -> float:
    try:
        return float(v.get("version") or 0)
    except (TypeError, ValueError):
        return 0.0


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


def template_families(ref: dict[str, Any]) -> set[str]:
    """The device families (lower case) a template targets; empty (no filtering) when it doesn't
    say, or when any device type entry has no family (series/type-only entries aren't checked here)."""
    types = [t for t in ensure_list(ref.get("deviceTypes")) if isinstance(t, dict)]
    if not types or any(not t.get("productFamily") for t in types):
        return set()
    return {str(t["productFamily"]).strip().lower() for t in types}


def split_applicable(
    devs: list[dict[str, Any]], families: set[str]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """(devices whose family the template targets, the others). Catalyst Center refuses the others
    as nonApplicableTargets ("mismatch of deviceType"), so they are left out of the deploy."""
    if not families:
        return devs, []
    ok = [str(d.get("family") or "").strip().lower() in families for d in devs]
    return [d for d, k in zip(devs, ok, strict=True) if k], [
        d for d, k in zip(devs, ok, strict=True) if not k
    ]


UNSAVED_NOTE = (
    "Catalyst Center does not save the configuration after a template deploy: the change is lost on "
    "reload, and RUNNING_CONFIG compliance shows it as drift. See the unsaved lines with "
    "catc_compare_device_configs(compare='startup'), and save it on the device (write memory) if it "
    "must persist."
)


def register(reg: ToolRegistrar) -> None:
    @reg.dangerous(title="Deploy template", task=True)
    async def catc_deploy_template(
        ctx: Context,
        template: TemplateRef,
        devices: Annotated[
            list[str] | None,
            Field(max_length=100, description="Devices (hostname, IP, serial or id); or give site / tag"),
        ] = None,
        site: Annotated[
            str | None,
            Field(description="Instead of devices: every device under this site (and its children)"),
        ] = None,
        tag: Annotated[
            str | None, Field(description="Instead of devices: every device with this tag")
        ] = None,
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
        """Deploy (push) a committed configuration template to devices: an explicit list, every device
        under a site, or every device with a tag. This changes the devices' running configuration.
        Preview-first: the preview renders the CLI for the first device and lists every target and the
        template version; nothing is pushed until you confirm. Uncommitted templates are refused (commit
        with catc_commit_template). Only devices in the template's device families are targeted (e.g.
        site= with a Routers template skips the switches and WLCs there; the preview lists them). More
        than CATC_MAX_DEVICES_PER_CHANGE targets (default 10) are refused."""
        app: CatcApp = get_client(ctx)
        ref = await resolve_template(app, template)
        tid = str(ref.get("templateId") or ref.get("id"))
        devs, targeting = await resolve_targets(app, devices, site, tag)
        if not devs:
            raise InvalidRequest(f"No devices to deploy to ({targeting}).")
        families = template_families(ref)
        devs, skipped = split_applicable(devs, families)
        if skipped:
            targeting["skipped_not_applicable"] = [
                f"{n} - {d.get('family') or 'unknown family'}"
                for n, d in zip(brief(skipped), skipped, strict=True)
            ]
            targeting["template_families"] = sorted(
                str(t.get("productFamily"))
                for t in ensure_list(ref.get("deviceTypes"))
                if isinstance(t, dict) and t.get("productFamily")
            )
        if not devs:
            raise InvalidRequest(
                "None of the target devices is in the template's device families "
                f"({', '.join(targeting['template_families'])}); "
                f"Catalyst Center would refuse them all: {', '.join(targeting['skipped_not_applicable'])}. "
                "Pick other devices, or change the template's device types."
            )
        blockers = device_limit_blockers(app, len(devs))
        versions = [v for v in ensure_list(ref.get("versionsInfo")) if isinstance(v, dict)]
        latest = max(versions, key=_version_key, default={})
        if not versions:
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
                "targets": targeting,
                "template_version": {
                    "version": latest.get("version"),
                    "committed": iso_ms(latest.get("versionTime")),
                    "comment": latest.get("versionComment") or latest.get("description"),
                },
                "rendered_cli_first_device": rendered,
                "note": "CLI rendered for the first device only; device-bound variables may differ.",
                "params": compact(params or {}),
            },
            side_effects=[
                "Changes the running configuration of every listed device.",
                "The change is not saved to the startup config (Catalyst Center doesn't write memory).",
            ],
            fingerprint={
                "template": tid,
                "devices": sorted(str(d["id"]) for d in devs),
                "versions": [v.get("id") for v in versions],
            },
            blockers=blockers,
            blast_radius=len(devs),
        )

        async def apply() -> Any:
            started = await app.api.post("/dna/intent/api/v2/template-programmer/template/deploy", body)
            if not wait:
                return {
                    "started": started,
                    "check_with": "catc_get_task (its progress names the deployment id), then "
                    "catc_get_template_deployment",
                }
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
                out["deployment"] = deployment_summary(status)
            if str((out.get("deployment") or {}).get("status", "")).upper() == "SUCCESS":
                out["note"] = UNSAVED_NOTE
            return out

        return await preview_or_apply(
            ctx,
            tool="catc_deploy_template",
            args={
                "template": template,
                "devices": devices,
                "site": site,
                "tag": tag,
                "params": params,
                "force_push": force_push,
                "wait": wait,
            },
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.dangerous(title="Provision devices", task=True)
    async def catc_provision_devices(
        ctx: Context,
        devices: Devices,
        site: Annotated[str, Field(description="Building or floor to provision the devices to")],
        wait: Wait = True,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Provision wired network devices to the site they are assigned to: Catalyst Center pushes
        the site's network settings (AAA, DNS, NTP, banner, syslog/SNMP trap/telemetry, etc.) to them.
        Devices already provisioned at that site are re-provisioned (pushes changed settings). This
        changes device configuration. Preview-first. Assign devices first with
        catc_assign_devices_to_site."""
        app: CatcApp = get_client(ctx)
        s = await resolve_site(app, site)
        devs = await resolve_devices(app, devices)
        blockers = device_limit_blockers(app, len(devs))
        if s.get("type") not in ("building", "floor"):
            blockers.append(f"Provision to a building or floor, not a {s.get('type')}.")
        existing = await provisioned_records(app, [str(d["id"]) for d in devs])
        new_devs = [d for d in devs if str(d["id"]) not in existing]
        again = [d for d in devs if str(d["id"]) in existing]
        moved = [d for d in again if existing[str(d["id"])].get("siteId") != s["id"]]
        if moved:
            blockers.append(
                "Already provisioned to another site: "
                + ", ".join(brief(moved))
                + ". Catalyst Center can't move a provisioned device: delete it (catc_delete_device), "
                "rediscover it, then assign and provision it."
            )
        path = "/dna/intent/api/v1/sda/provisionDevices"
        plan = Plan(
            f"Provision {len(new_devs)} and re-provision {len(again)} device(s) at {s.get('nameHierarchy')}",
            details={
                "provision": brief(new_devs),
                "re_provision": brief(again),
                "site": {"nameHierarchy": s.get("nameHierarchy"), "id": s.get("id")},
                "requests": ([f"POST {path}"] if new_devs else []) + ([f"PUT {path}"] if again else []),
            },
            side_effects=[
                "Pushes the site's network settings to each device (not the network profile's Day-N "
                "templates: deploy those with catc_deploy_template)."
            ],
            fingerprint={
                "site": s["id"],
                "devices": sorted(str(d["id"]) for d in devs),
                "existing": existing,
            },
            blockers=blockers,
            blast_radius=len(devs),
        )

        async def apply() -> Any:
            out: dict[str, Any] = {}
            for method, group, body in (
                ("POST", new_devs, [{"networkDeviceId": str(d["id"]), "siteId": s["id"]} for d in new_devs]),
                (
                    "PUT",
                    again,
                    [
                        {
                            "id": existing[str(d["id"])]["id"],
                            "networkDeviceId": str(d["id"]),
                            "siteId": s["id"],
                        }
                        for d in again
                    ],
                ),
            ):
                if not group:
                    continue
                key = "provisioned" if method == "POST" else "re_provisioned"
                started = await app.api.request(method, path, json=body)
                if not wait:
                    out[key] = {"started": started, "check_with": "catc_get_task"}
                else:
                    out[key] = await app.wait_job(started, ctx=ctx, what="provisioning")
            return out

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
            f"{action.title()} image {img.get('name')} ({img.get('version')}) on {brief([dev])[0]}",
            details={
                "device": brief([dev])[0],
                "current_version": dev.get("softwareVersion"),
                "image": {k: img.get(k) for k in ("name", "version", "id")},
                "method": "POST",
                "path": path,
            },
            side_effects=effects,
            fingerprint={"device": dev["id"], "image": img["id"], "action": action},
            blockers=device_limit_blockers(app, 1),
            blast_radius=1,
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

    @reg.dangerous(title="Distribute software image", task=True)
    async def catc_distribute_image(
        ctx: Context, device: DeviceRef, image: ImageRef, wait: Wait = True, confirm: Confirm = None
    ) -> dict[str, Any]:
        """Copy an imported software image to a device's flash (SWIM distribution) without
        activating it. Preview-first. Activate it later with catc_activate_image."""
        return await _swim(ctx, "catc_distribute_image", device, image, wait, confirm, activate=False)

    @reg.dangerous(title="Activate software image", task=True)
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

    @reg.dangerous(title="Delete device (un-provision)")
    async def catc_delete_device(
        ctx: Context,
        device: DeviceRef,
        clean_config: Annotated[
            bool,
            Field(
                description="Required, no default: true also removes the configuration Catalyst Center "
                "pushed to the device (AAA/RADIUS, syslog/SNMP/telemetry, banner, ...); false leaves the "
                "device's configuration as it is"
            ),
        ],
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Remove a device from Catalyst Center. This is also the only way to UN-PROVISION a device:
        Catalyst Center 3.x has no separate un-provision call, and un-provisioning DELETES the device from
        the inventory (the device is no longer managed, its assurance history and config archive go). To
        keep managing it, don't use this: re-provision it instead. Bring a deleted device back with a
        discovery, then assign and provision it (prompt catc_onboard_device). clean_config must be given
        explicitly. Preview-first: states every effect and the archived config versions that are lost."""
        app: CatcApp = get_client(ctx)
        dev = await resolve_device(app, device)
        did = str(dev["id"])
        prov = (await provisioned_records(app, [did])).get(did)
        if prov:
            path = f"/dna/intent/api/v1/sda/provisionDevices/{safe_id(str(prov['id']), 'provisioning id')}"
            params = {"cleanUpConfig": str(clean_config).lower()}
        else:
            path = f"/dna/intent/api/v1/network-device/{did}"
            params = {"cleanConfig": str(clean_config).lower()}
        try:
            files = await archive_files(app, did)
        except UpstreamError as e:
            files = None
            archive: dict[str, Any] = {"unavailable": str(e)[:200]}
        if files is not None:
            running = [f for f in files if f.get("fileType") == "RUNNINGCONFIG"]
            archive = {
                "versions": len({f.get("versionId") for f in files}),
                "latest_running_config": (
                    iso_ms(max(running, key=lambda f: f.get("createdTime") or 0).get("createdTime"))
                    if running
                    else None
                ),
                "keep_a_copy_with": "catc_get_device_config (running config) before confirming",
            }
        effects = [
            ("Un-provisions the device AND deletes it" if prov else "Deletes the device")
            + " from the Catalyst Center inventory: it is no longer managed (no assurance, compliance, "
            "templates or provisioning) until it is rediscovered, assigned and provisioned again.",
            "Its assurance history and archived configuration versions are deleted.",
            "Removes the configuration Catalyst Center pushed (AAA/RADIUS, syslog/SNMP/telemetry, banner, "
            "...) from the device."
            if clean_config
            else "Leaves the device's configuration as it is (clean_config=false), including AAA pointing at "
            "ISE; ISE keeps its network device entry either way.",
        ]
        plan = Plan(
            f"{'Un-provision and delete' if prov else 'Delete'} device {brief([dev])[0]} from inventory"
            + (" and clean its configuration" if clean_config else ""),
            details={
                "device": brief([dev])[0],
                "site": prov.get("siteId") if prov else None,
                "provisioned": bool(prov),
                "clean_config": clean_config,
                "config_archive_lost": archive,
                "method": "DELETE",
                "path": path,
                "params": params,
            },
            side_effects=effects,
            fingerprint={"id": did, "provisioning": prov, "clean_config": clean_config},
            blockers=device_limit_blockers(app, 1),
            blast_radius=1,
        )

        async def apply() -> Any:
            return await app.run_job("DELETE", path, params=params, ctx=ctx, what="delete device")

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
