"""Plug and Play (zero-touch day 0) and device replacement (RMA), D11.

PnP: a factory-fresh device finds Catalyst Center (DHCP option 43, DNS pnpserver.<domain>, or a
`pnp profile` on its CLI) and waits Unclaimed; claiming it to a site pushes a day-0 onboarding
template (and optionally an image), so claim/reset/delete are dangerous tier. RMA: mark the faulty
device (unreachable) for replacement, then replace it with a same-PID device that arrived in PnP:
Catalyst Center pushes the faulty device's archived config and licences to it and swaps the serial
in the inventory."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import hashlib
import re
from typing import Annotated, Any, Literal

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field
from stutters_mcp_core import (
    Confirm,
    NotFound,
    Plan,
    ResponseFormat,
    ToolRegistrar,
    get_client,
    list_result,
    poll_until,
    preview_or_apply,
)
from stutters_mcp_core.formatting import MASK, is_secret_key
from stutters_mcp_core.http import page_of

from catc_mcp.client import CatcApp, safe_id
from catc_mcp.common import ensure_list, is_uuid, resolve_device, resolve_site, resolve_template
from catc_mcp.safety import device_limit_blockers
from catc_mcp.tools.inventory import redact_config

PNP = "/dna/intent/api/v1/onboarding/pnp-device"
REPL = "/dna/intent/api/v1/networkDeviceReplacements"
MARK = "/dna/intent/api/v1/device-replacement"
ARCHIVE = "/dna/intent/api/v1/networkDeviceConfigFiles"

DeviceRef = Annotated[str, Field(description="PnP device serial number or PnP id (catc_list_pnp_devices)")]
REPL_FIELDS = [
    "id",
    "family",
    "faultyDeviceName",
    "faultyDeviceSerialNumber",
    "faultyDevicePlatform",
    "faultyDeviceId",
    "replacementDeviceSerialNumber",
    "replacementDevicePlatform",
    "replacementStatus",
    "outOfBand",
    "creationTime",
    "replacementTime",
]
RMA_POLL_SECONDS = 15.0
FAMILY_TYPE = {"Routers": "ROUTER", "Switches and Hubs": "SWITCH"}


def pnp_summary(d: dict[str, Any]) -> dict[str, Any]:
    info = d.get("deviceInfo") or {}
    return {
        "id": d.get("id"),
        "serial": info.get("serialNumber"),
        "pid": info.get("pid"),
        "hostname": info.get("hostname"),
        "state": info.get("state"),
        "onboarding": info.get("onbState"),
        "image": info.get("imageVersion"),
        "site": info.get("siteName") or info.get("siteId"),
        "last_contact": info.get("lastContact"),
        "error": info.get("errorDetails") and str(info.get("errorDetails"))[:300],
    }


def stable(dev: dict[str, Any]) -> dict[str, Any]:
    """A PnP device without the fields that change at every agent contact (for confirm tokens)."""
    return {k: v for k, v in dev.items() if k not in ("last_contact", "onboarding")}


def _secret_param(key: str) -> bool:
    k = key.lower()
    return is_secret_key(key) or any(w in k for w in ("password", "secret", "community", "snmp", "key"))


def shown_params(params: dict[str, str] | None) -> dict[str, str]:
    """Template variables for previews/results: values of password/secret/community/key-like names masked."""
    return {k: (MASK if _secret_param(k) else str(v)) for k, v in (params or {}).items()}


async def resolve_pnp_device(app: CatcApp, ref: str) -> dict[str, Any]:
    ref = ref.strip()
    if is_uuid(ref) or (len(ref) == 24 and all(c in "0123456789abcdef" for c in ref)):
        d = await app.get_response(f"{PNP}/{safe_id(ref, 'PnP device id')}")
        if isinstance(d, dict) and d.get("id"):
            return d
    found = [d for d in ensure_list(await app.api.get(PNP, {"serialNumber": ref})) if isinstance(d, dict)]
    if not found:
        raise NotFound(f"No PnP device {ref!r}; see catc_list_pnp_devices.")
    return found[0]


async def latest_archive(app: CatcApp, device_id: str) -> dict[str, Any] | None:
    files = ensure_list(
        await app.get_response(ARCHIVE, {"networkDeviceId": device_id, "fileType": "RUNNINGCONFIG"})
    )
    files = [f for f in files if isinstance(f, dict)]
    files.sort(key=lambda f: f.get("createdTime") or 0, reverse=True)
    if not files:
        return None
    return {k: files[0].get(k) for k in ("id", "createdTime", "versionId", "fileType")}


def _ver(v: str) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", v)[:3])


async def image_imported(app: CatcApp, version: str) -> bool:
    """Whether an image of this software version is imported (RMA needs the faulty device's image).
    Versions compare on their first three numbers: the inventory says 17.18.2, SWIM 17.18.02.0.4112."""
    want = _ver(version)
    if not want:
        return True
    rows = ensure_list(await app.get_response("/dna/intent/api/v1/images", {"imported": "true"}))
    return any(isinstance(r, dict) and _ver(str(r.get("version") or "")) == want for r in rows)


async def replacements(app: CatcApp, **params: Any) -> list[dict[str, Any]]:
    rows = ensure_list(await app.get_response(REPL, {k: v for k, v in params.items() if v} or None))
    return [r for r in rows if isinstance(r, dict)]


def register(reg: ToolRegistrar) -> None:
    @reg.dangerous(title="Claim a PnP device to a site")
    async def catc_claim_pnp_device(
        ctx: Context,
        device: DeviceRef,
        site: Annotated[str, Field(description="Building or floor to claim it to (id or name hierarchy)")],
        template: Annotated[
            str | None,
            Field(
                description="Day-0 onboarding template ('Onboarding Configuration/<name>' or id); it must "
                "give the device credentials and management reachability for Catalyst Center"
            ),
        ] = None,
        params: Annotated[
            dict[str, str] | None, Field(description='Template variable values, e.g. {"hostname": "br1"}')
        ] = None,
        hostname: Annotated[
            str | None,
            Field(description="Hostname to set on the device ('hostname' is a blocked command in templates)"),
        ] = None,
        image: Annotated[
            str | None, Field(description="Software image id to install first (default: keep the image)")
        ] = None,
        wait: Annotated[
            bool, Field(description="Wait until the device is Provisioned or in Error (default true)")
        ] = True,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Claim an Unclaimed Plug and Play device to a site: Catalyst Center pushes the day-0
        onboarding template (with its variables), optionally an image, then adds the device to the
        inventory at that site. Preview-first: shows the device (serial, PID, state), the site, the
        template body and which variables are missing. Takes a few minutes; with wait=true returns
        the final PnP state. Devices in Error need catc_reset_pnp_device first."""
        app: CatcApp = get_client(ctx)
        d = await resolve_pnp_device(app, device)
        dev = pnp_summary(d)
        s = await resolve_site(app, site)
        blockers: list[str] = []
        if str(dev.get("state")) != "Unclaimed":
            blockers.append(
                f"{dev['serial']} is {dev.get('state')}, not Unclaimed"
                + (" (reset it with catc_reset_pnp_device)" if dev.get("state") == "Error" else "")
                + "."
            )
        if str(s.get("type", "")).lower() not in ("building", "floor"):
            blockers.append(f"{s.get('nameHierarchy')} is a {s.get('type')}; claim to a building or floor.")
        body: dict[str, Any] = {
            "deviceId": d["id"],
            "siteId": s["id"],
            "type": "Default",
            "imageInfo": {"imageId": image or "", "skip": not image},
        }
        if hostname:
            body["hostname"] = hostname
        details: dict[str, Any] = {"device": dev, "site": s.get("nameHierarchy")}
        if template:
            t = await resolve_template(app, template)
            tid = str(t.get("templateId") or t.get("id") or "")
            if not tid:
                raise NotFound(f"Template {template!r} has no id.")
            full = await app.get_response(f"/dna/intent/api/v1/template-programmer/template/{tid}")
            full = full if isinstance(full, dict) else {}
            if not (t.get("versionsInfo") or full.get("versionsInfo")):
                blockers.append(f"Template {template} has never been committed (catc_commit_template).")
            names = [
                str(p.get("parameterName")) for p in full.get("templateParams") or [] if isinstance(p, dict)
            ]
            missing = [n for n in names if n not in (params or {})]
            if missing:
                blockers.append(f"Template variables without a value: {', '.join(missing)}.")
            body["configInfo"] = {
                "configId": tid,
                "configParameters": [{"key": k, "value": str(v)} for k, v in (params or {}).items()],
            }
            details["template"] = {
                "name": f"{t.get('projectName')}/{t.get('name')}",
                "content": redact_config(str(full.get("templateContent") or ""))[:4000],
                "params": shown_params(params),
                "versions": len(t.get("versionsInfo") or full.get("versionsInfo") or []),
            }
        else:
            details["note"] = (
                "No day-0 template: the device keeps its current config; Catalyst Center must be able "
                "to reach and log in to it afterwards."
            )
        plan = Plan(
            f"Claim PnP device {dev['serial']} ({dev.get('pid')}) to {s.get('nameHierarchy')}",
            details={
                **details,
                "method": "POST",
                "path": f"{PNP}/site-claim",
                "body": {
                    **body,
                    **(
                        {
                            "configInfo": {
                                **body["configInfo"],
                                "configParameters": [
                                    {"key": k, "value": v} for k, v in shown_params(params).items()
                                ],
                            }
                        }
                        if "configInfo" in body
                        else {}
                    ),
                },
            },
            fingerprint={
                "device": stable(dev),
                "site": s.get("id"),
                "template": details.get("template", {}).get("content"),
                "versions": details.get("template", {}).get("versions"),
            },
            blockers=blockers + device_limit_blockers(app, 1),
            blast_radius=1,
        )

        async def apply() -> Any:
            res = await app.api.request("POST", f"{PNP}/site-claim", json=body)
            out: dict[str, Any] = {"claimed": dev["serial"], "response": redact_config(str(res))[:300]}
            if wait:
                final = await poll_until(
                    lambda: resolve_pnp_device(app, str(d["id"])),
                    done=lambda x: pnp_summary(x).get("state") in ("Provisioned", "Error"),
                    describe=lambda x: f"{pnp_summary(x).get('state')}/{pnp_summary(x).get('onboarding')}",
                    timeout=max(app.settings.mcp_task_timeout, 900),
                    ctx=ctx,
                    what="PnP claim",
                    interval=10.0,
                )
                out["device"] = pnp_summary(final)
            return out

        return await preview_or_apply(
            ctx,
            tool="catc_claim_pnp_device",
            args={
                "device": device,
                "site": site,
                "template": template,
                # Secret values are bound by digest only, so audit logs never carry them.
                "params": {
                    k: (hashlib.sha256(str(v).encode()).hexdigest() if _secret_param(k) else v)
                    for k, v in (params or {}).items()
                },
                "hostname": hostname,
                "image": image,
                "wait": wait,
            },
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.dangerous(title="Reset a PnP device")
    async def catc_reset_pnp_device(
        ctx: Context, device: DeviceRef, confirm: Confirm = None
    ) -> dict[str, Any]:
        """Reset a PnP device that is in Error so it retries onboarding (it becomes Unclaimed again
        and can be claimed with catc_claim_pnp_device). Preview-first: shows the device and its error."""
        app: CatcApp = get_client(ctx)
        d = await resolve_pnp_device(app, device)
        dev = pnp_summary(d)
        blockers = (
            [] if dev.get("state") == "Error" else [f"{dev['serial']} is {dev.get('state')}, not Error."]
        )
        body = {"deviceResetList": [{"deviceId": d["id"]}]}
        plan = Plan(
            f"Reset PnP device {dev['serial']}",
            details={"device": dev, "method": "POST", "path": f"{PNP}/reset", "body": body},
            fingerprint=stable(dev),
            blockers=blockers,
        )

        async def apply() -> Any:
            res = await app.api.request("POST", f"{PNP}/reset", json=body)
            return {"reset": dev["serial"], "response": res}

        return await preview_or_apply(
            ctx,
            tool="catc_reset_pnp_device",
            args={"device": device},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.dangerous(title="Delete a PnP device")
    async def catc_delete_pnp_device(
        ctx: Context, device: DeviceRef, confirm: Confirm = None
    ) -> dict[str, Any]:
        """Remove a device from the Plug and Play list (not from the inventory). If it still runs the
        PnP agent it shows up again as Unclaimed at its next contact. Preview-first."""
        app: CatcApp = get_client(ctx)
        d = await resolve_pnp_device(app, device)
        dev = pnp_summary(d)
        pid = safe_id(str(d["id"]), "PnP device id")
        plan = Plan(
            f"Delete PnP device {dev['serial']} ({dev.get('state')})",
            details={"device": dev, "method": "DELETE", "path": f"{PNP}/{pid}"},
            fingerprint=stable(dev),
        )

        async def apply() -> Any:
            await app.api.request("DELETE", f"{PNP}/{pid}")
            return {"deleted": dev["serial"]}

        return await preview_or_apply(
            ctx,
            tool="catc_delete_pnp_device",
            args={"device": device},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.read(title="List device replacements (RMA)")
    async def catc_list_device_replacements(
        ctx: Context,
        status: Annotated[
            Literal[
                "MARKED_FOR_REPLACEMENT",
                "NETWORK_READINESS_REQUESTED",
                "NETWORK_READINESS_FAILED",
                "READY_FOR_REPLACEMENT",
                "REPLACEMENT_SCHEDULED",
                "REPLACEMENT_IN_PROGRESS",
                "REPLACED",
                "ERROR",
            ]
            | None,
            Field(description="Only this replacement status"),
        ] = None,
        faulty_serial: Annotated[str | None, Field(description="Faulty device serial number")] = None,
        limit: Annotated[int, Field(ge=1, le=500)] = 50,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """Devices marked for replacement (RMA) and replacement workflows: faulty device name, serial
        and platform, the replacement serial, status (MARKED_FOR_REPLACEMENT -> READY_FOR_REPLACEMENT
        -> REPLACEMENT_IN_PROGRESS -> REPLACED or ERROR) and times."""
        app: CatcApp = get_client(ctx)
        rows = [
            {k: r.get(k) for k in REPL_FIELDS if r.get(k) not in (None, "")}
            for r in await replacements(app, replacementStatus=status, faultyDeviceSerialNumber=faulty_serial)
        ]
        return list_result(page_of(rows, limit=limit, offset=offset), fmt=response_format)

    @reg.write(title="Mark a device for replacement", destructive=False)
    async def catc_mark_device_for_replacement(
        ctx: Context,
        device: Annotated[str, Field(description="Faulty device (hostname, IP, serial or id)")],
        unmark: Annotated[bool, Field(description="Undo: mark the device as not faulty again")] = False,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Mark a faulty device for replacement (RMA), the first step before catc_replace_device; or
        unmark it. Catalyst Center only accepts devices that are unreachable. Preview-first: shows the
        device, its reachability and the newest archived running config (what a replacement will get)."""
        app: CatcApp = get_client(ctx)
        dev = await resolve_device(app, device)
        did = str(dev["id"])
        current = [r for r in await replacements(app, faultyDeviceSerialNumber=dev.get("serialNumber"))]
        open_rec = [r for r in current if r.get("replacementStatus") not in ("REPLACED",)]
        blockers: list[str] = []
        if unmark:
            if not open_rec:
                blockers.append(f"{dev.get('hostname')} is not marked for replacement.")
            busy = [
                r
                for r in open_rec
                if r.get("replacementStatus") in ("REPLACEMENT_IN_PROGRESS", "REPLACEMENT_SCHEDULED")
            ]
            if busy:
                blockers.append(
                    f"Replacement of {dev.get('hostname')} is {busy[0].get('replacementStatus')}."
                )
            body: list[dict[str, Any]] = [
                {"id": r.get("id"), "faultyDeviceId": did, "replacementStatus": "NON-FAULTY"}
                for r in open_rec
            ]
            method = "PUT"
        else:
            if open_rec:
                blockers.append(f"{dev.get('hostname')} is already {open_rec[0].get('replacementStatus')}.")
            if dev.get("reachabilityStatus") == "Reachable":
                blockers.append(
                    f"{dev.get('hostname')} is Reachable; Catalyst Center only marks unreachable devices."
                )
            body = [{"faultyDeviceId": did, "replacementStatus": "MARKED-FOR-REPLACEMENT"}]
            method = "POST"
        if not unmark and not await image_imported(app, str(dev.get("softwareVersion") or "")):
            blockers.append(
                f"{dev.get('platformId')} {dev.get('softwareVersion')} (running on {dev.get('hostname')}) "
                "isn't imported into the image repository; Catalyst Center refuses RMA without it "
                "(NCRM11042). Import it with SWIM first (catc_list_images imported=true)."
            )
        archive = None if unmark else await latest_archive(app, did)
        if not unmark and archive is None:
            blockers.append(
                f"No archived running config for {dev.get('hostname')}: a replacement would get none."
            )
        info = {
            k: dev.get(k)
            for k in ("hostname", "managementIpAddress", "serialNumber", "platformId", "reachabilityStatus")
        }
        plan = Plan(
            f"{'Unmark' if unmark else 'Mark'} {dev.get('hostname')} ({dev.get('serialNumber')}) "
            f"{'as not faulty' if unmark else 'for replacement'}",
            details={"device": info, "config_archive": archive, "method": method, "path": MARK, "body": body},
            fingerprint={"device": info, "replacements": current},
            blockers=blockers,
        )

        async def apply() -> Any:
            job = await app.run_job(method, MARK, body, ctx=ctx, what="device replacement mark")
            return {"device": dev.get("hostname"), "marked": not unmark, "task": job.get("status")}

        return await preview_or_apply(
            ctx,
            tool="catc_mark_device_for_replacement",
            args={"device": device, "unmark": unmark},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.dangerous(title="Replace a faulty device (RMA)")
    async def catc_replace_device(
        ctx: Context,
        faulty: Annotated[str, Field(description="The faulty device, marked for replacement")],
        replacement_serial: Annotated[
            str, Field(description="Serial of the replacement device (Unclaimed in PnP, same PID)")
        ],
        wait: Annotated[bool, Field(description="Wait until REPLACED or ERROR (default true)")] = True,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Replace a faulty device with a new one of the same model (RMA): Catalyst Center pushes the
        faulty device's archived running config (and licences) to the replacement through PnP and
        moves the inventory entry, site and history to the new serial. Preview-first: shows both
        serials and PIDs, the replacement status and the config archive version that will be
        restored. The replacement must have contacted PnP (Unclaimed); takes 10+ minutes."""
        app: CatcApp = get_client(ctx)
        dev = await resolve_device(app, faulty)
        did = str(dev["id"])
        serial = str(dev.get("serialNumber"))
        recs = [
            r
            for r in await replacements(app, faultyDeviceSerialNumber=serial)
            if r.get("replacementStatus") != "REPLACED"
        ]
        blockers: list[str] = []
        if not recs:
            blockers.append(
                f"{dev.get('hostname')} isn't marked for replacement (catc_mark_device_for_replacement)."
            )
        elif recs[0].get("replacementStatus") not in (
            "MARKED_FOR_REPLACEMENT",
            "READY_FOR_REPLACEMENT",
            "ERROR",
        ):
            blockers.append(f"Replacement of {dev.get('hostname')} is {recs[0].get('replacementStatus')}.")
        try:
            new = pnp_summary(await resolve_pnp_device(app, replacement_serial))
        except NotFound:
            new = {"serial": replacement_serial}
            blockers.append(f"{replacement_serial} hasn't contacted PnP yet (catc_list_pnp_devices).")
        if new.get("state") not in (None, "Unclaimed"):
            blockers.append(f"{replacement_serial} is {new.get('state')} in PnP, not Unclaimed.")
        if new.get("pid") and new.get("pid") != dev.get("platformId"):
            blockers.append(f"PID differs: faulty {dev.get('platformId')}, replacement {new.get('pid')}.")
        kind = FAMILY_TYPE.get(str(dev.get("family")))
        if kind is None:
            blockers.append(f"Replacement of {dev.get('family')} devices isn't supported by this tool.")
        archive = await latest_archive(app, did)
        body = {
            "type": kind,
            "faultyDeviceSerialNumber": serial,
            # The resolved serial: replacement_serial may also be a PnP id.
            "replacementDeviceSerialNumber": str(new.get("serial") or replacement_serial),
        }
        plan = Plan(
            f"Replace {dev.get('hostname')} ({serial}) with {replacement_serial}",
            details={
                "faulty": {
                    k: dev.get(k)
                    for k in ("hostname", "managementIpAddress", "platformId", "reachabilityStatus")
                },
                "replacement": new,
                "replacement_record": recs[0] if recs else None,
                "config_archive_restored": archive,
                "method": "POST",
                "path": f"{REPL}/workflow/deploy",
                "body": body,
            },
            fingerprint={"recs": recs, "new": stable(new)},
            blockers=blockers + device_limit_blockers(app, 1),
            blast_radius=1,
        )

        async def apply() -> Any:
            # Earlier records (e.g. a previous ERROR) must not end the wait: only a changed one counts.
            before = {
                str(r.get("id")): (r.get("replacementStatus"), r.get("replacementTime"))
                for r in await replacements(app, faultyDeviceSerialNumber=serial)
            }

            def settled(rs: list[dict[str, Any]]) -> bool:
                return any(
                    r.get("replacementStatus") in ("REPLACED", "ERROR")
                    and before.get(str(r.get("id"))) != (r.get("replacementStatus"), r.get("replacementTime"))
                    for r in rs
                )

            job = await app.run_job(
                "POST", f"{REPL}/workflow/deploy", body, ctx=ctx, what="device replacement"
            )
            out: dict[str, Any] = {"task": job.get("status"), "progress": job.get("progress")}
            if wait:
                final = await poll_until(
                    lambda: replacements(app, faultyDeviceSerialNumber=serial),
                    done=settled,
                    describe=lambda rs: ",".join(str(r.get("replacementStatus")) for r in rs),
                    timeout=max(app.settings.mcp_task_timeout, 1800),
                    ctx=ctx,
                    what="device replacement",
                    interval=RMA_POLL_SECONDS,
                )
                out["replacement"] = [{k: r.get(k) for k in REPL_FIELDS if r.get(k)} for r in final]
            return out

        return await preview_or_apply(
            ctx,
            tool="catc_replace_device",
            args={"faulty": faulty, "replacement_serial": replacement_serial, "wait": wait},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )
