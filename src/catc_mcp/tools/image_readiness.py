"""Image readiness and update history (roadmap D66, #113): de-risk an upgrade before the .bin exists.

- `GET /dna/intent/api/v1/networkDeviceImages/validationResults` (+ `/count`): the results of the system
  pre-checks (READINESS_CHECK) and of the pre/post validations that ran around a distribution or an
  activation, one row per check, grouped by `parentId` (one run). Each row: name, status (SUCCESS, FAILED,
  STARTED, PARTIAL_SUCCESS, PENDING, WARNING, SKIPPED, ABORTED), type (PRE/POST_VALIDATION), start/end and
  `resultDetails` (EXPECTED / ACTUAL / ACTION / STATUS / DESCRIPTION).
- `POST /dna/intent/api/v1/networkDeviceImages/{device id}/readinessChecks`: run the system pre-checks on
  demand (a task; the device gets show commands, no configuration). Write tier, preview-first.
- `GET /dna/intent/api/v1/networkDeviceImages/validations`: the custom validations (show commands mapped to
  product series) that run as part of distribution/activation.
- `GET /dna/intent/api/v1/networkDeviceImageUpdates` (+ `/count`): every distribution and activation per
  device, with status, image version and times.
- `GET /dna/intent/api/v1/images/{id}/addonImages` and
  `GET /dna/intent/api/v1/images/distributionServerSettings`.

Checked live on the 3.2.2 lab appliance (2026-10-29, read-only): validationResults, validations and
networkDeviceImageUpdates answer `{"response": [], "version": "1.0"}` on a lab with no upgrade done;
networkDeviceImageUpdates/count answers `{"response": {"count": 0}}`; `networkDeviceImages/{id}` takes the
network device id and returns the same record as the list; distributionServerSettings lists a remote SFTP
server (id, serverAddress, portNumber, rootLocation, username; no password). The spec types `resultDetails`
as one {key, value} object; a list of them is accepted too.
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import contextlib
from typing import Annotated, Any, Literal
from urllib.parse import parse_qs, urlparse

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field

from catc_mcp._core import (
    Confirm,
    Plan,
    ResponseFormat,
    ToolRegistrar,
    UpstreamError,
    get_client,
    list_result,
    object_result,
    preview_or_apply,
)
from catc_mcp._core.http import Page, fetch_all
from catc_mcp.client import CatcApp, safe_id
from catc_mcp.common import ensure_list, pick, resolve_device
from catc_mcp.tools.maintenance import to_iso
from catc_mcp.tools.swim import IMAGE_FIELDS, resolve_image

NDI = "/dna/intent/api/v1/networkDeviceImages"
RESULTS = f"{NDI}/validationResults"
VALIDATIONS = f"{NDI}/validations"
UPDATES = "/dna/intent/api/v1/networkDeviceImageUpdates"
IMAGES = "/dna/intent/api/v1/images"
DIST_SERVERS = f"{IMAGES}/distributionServerSettings"
CAP = 2000

FAILED = {"FAILED", "ABORTED"}
WARN = {"WARNING", "PARTIAL_SUCCESS"}
RUNNING = {"STARTED", "PENDING", "IN_PROGRESS", "IN-PROGRESS"}
OPERATIONS = ("READINESS_CHECK", "DISTRIBUTION", "ACTIVATION")


async def _count(app: CatcApp, path: str, params: dict[str, Any] | None = None) -> int | None:
    with contextlib.suppress(UpstreamError):
        data = await app.get_response(path, params)
        if isinstance(data, dict) and isinstance(data.get("count"), int | float):
            return int(data["count"])
    return None


def details(raw: Any) -> dict[str, Any] | None:
    """resultDetails as {EXPECTED: ..., ACTUAL: ..., ACTION: ...}: the spec's {key, value} object, a list
    of them, or a plain mapping."""
    items = raw if isinstance(raw, list) else [raw]
    out: dict[str, Any] = {}
    for it in items:
        if not isinstance(it, dict):
            continue
        if "key" in it and set(it) <= {"key", "value"}:
            out[str(it["key"])] = it.get("value")
        else:
            out.update(it)
    return out or None


def _duration(start: Any, end: Any) -> float | None:
    if isinstance(start, int | float) and isinstance(end, int | float) and end >= start > 0:
        return round((end - start) / 1000, 1)
    return None


def result_row(r: dict[str, Any]) -> dict[str, Any]:
    row: dict[str, Any] = {
        "name": r.get("name"),
        "status": r.get("status"),
        "type": r.get("type"),
        "operation": r.get("operationType"),
        "start": to_iso(r.get("startTime")) if r.get("startTime") else None,
        "end": to_iso(r.get("endTime")) if r.get("endTime") else None,
    }
    d = details(r.get("resultDetails"))
    if d:
        row["details"] = d
    row["id"] = r.get("id")
    return {k: v for k, v in row.items() if v is not None}


def verdict_of(statuses: list[str]) -> str:
    s = {x.upper() for x in statuses}
    if s & FAILED:
        return "NOT_READY"
    if s & RUNNING:
        return "IN_PROGRESS"
    if s & WARN:
        return "READY_WITH_WARNINGS"
    return "READY" if s else "NO_CHECKS"


def group_runs(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """One entry per run (parentId), newest first: operation, verdict, counts and the checks, failed first."""
    runs: dict[str, list[dict[str, Any]]] = {}
    for r in rows:
        runs.setdefault(str(r.get("parentId") or r.get("id") or "?"), []).append(r)
    out: list[dict[str, Any]] = []
    for parent, items in runs.items():
        starts = [r["startTime"] for r in items if isinstance(r.get("startTime"), int | float)]
        ends = [r["endTime"] for r in items if isinstance(r.get("endTime"), int | float)]
        statuses = [str(r.get("status") or "") for r in items]
        rank = {"FAILED": 0, "ABORTED": 0, "WARNING": 1, "PARTIAL_SUCCESS": 1}
        ordered = sorted(
            items, key=lambda r: (rank.get(str(r.get("status") or "").upper(), 2), str(r.get("name")))
        )
        counts: dict[str, int] = {}
        for st in statuses:
            counts[st or "UNKNOWN"] = counts.get(st or "UNKNOWN", 0) + 1
        out.append(
            {
                "run_id": parent,
                "operation": next((r.get("operationType") for r in items if r.get("operationType")), None),
                "verdict": verdict_of([s for s in statuses if s]),
                "start": to_iso(min(starts)) if starts else None,
                "end": to_iso(max(ends)) if ends else None,
                "counts": counts,
                "checks": [result_row(r) for r in ordered],
                "_start": min(starts) if starts else 0,
            }
        )
    out.sort(key=lambda g: float(g["_start"]), reverse=True)
    for g in out:
        g.pop("_start")
    return out


def summarize_results(rows: list[dict[str, Any]], device_name: str) -> dict[str, Any]:
    """{verdict, latest_readiness_check, latest_by_operation, runs} for one device's validation results."""
    runs = group_runs(rows)
    latest: dict[str, Any] = {}
    for g in runs:
        op = str(g.get("operation") or "UNKNOWN")
        latest.setdefault(op, g)
    out: dict[str, Any] = {}
    check = latest.get("READINESS_CHECK")
    if check:
        failed = [c["name"] for c in check["checks"] if str(c.get("status", "")).upper() in FAILED]
        warned = [c["name"] for c in check["checks"] if str(c.get("status", "")).upper() in WARN]
        out["verdict"] = check["verdict"]
        line = f"{device_name}: readiness check of {check.get('start') or 'unknown time'}: {check['verdict']}"
        if failed:
            line += f"; failed: {', '.join(str(f) for f in failed)}"
        if warned:
            line += f"; warnings: {', '.join(str(w) for w in warned)}"
        out["summary"] = line
    else:
        out["verdict"] = "NO_READINESS_CHECK"
        out["summary"] = (
            f"{device_name}: no readiness check has run. Run one with catc_run_image_readiness_check "
            "(write tier; show commands only)."
        )
    out["latest_by_operation"] = {
        op: {k: g[k] for k in ("run_id", "verdict", "start", "end", "counts")} for op, g in latest.items()
    }
    out["runs"] = runs
    return out


def _run_id_from(task: dict[str, Any]) -> str | None:
    """The validation run id from a finished task's resultLocation ('...validationResults?id=<id>')."""
    loc = task.get("resultLocation")
    if not isinstance(loc, str) or not loc:
        return None
    q = parse_qs(urlparse(loc).query)
    for key in ("id", "parentId"):
        if q.get(key):
            return q[key][0]
    return None


def image_applicability(img: dict[str, Any], record: dict[str, Any] | None) -> dict[str, Any]:
    """Does the image name the device's product, is it imported, golden, verified?"""
    product = (record or {}).get("networkDevice") or {}
    ordinal = product.get("productNameOrdinal")
    names = [p for p in ensure_list(img.get("productNames")) if isinstance(p, dict)]
    ords = {str(p.get("productNameOrdinal")) for p in names if p.get("productNameOrdinal") is not None}
    out: dict[str, Any] = {"image": pick(img, IMAGE_FIELDS) or img}
    if ordinal is None or not names:
        out["applies_to_device"] = None
        out["applies_note"] = (
            "unknown: the image lists no products" if not names else "unknown: no product for the device"
        )
    else:
        out["applies_to_device"] = str(ordinal) in ords
    installed = [
        str(i.get("version") or "")
        for i in ensure_list((record or {}).get("installedImages"))
        if isinstance(i, dict)
    ]
    issues = []
    if out["applies_to_device"] is False:
        issues.append(f"the image is not for {product.get('productName') or 'this product'}")
    if img.get("imported") is False:
        issues.append("not imported into the repository (cisco.com suggestion only)")
    if str(img.get("integrityStatus") or "").upper() not in ("", "VERIFIED"):
        issues.append(f"integrity {img.get('integrityStatus')}")
    if img.get("version") and str(img.get("version")) in installed:
        issues.append("the device already runs this version")
    out["issues"] = issues
    return out


async def addon_images(app: CatcApp, image_id: str) -> list[dict[str, Any]]:
    iid = safe_id(image_id, "image id")
    # No paging on this path (the spec gives it no offset/limit).
    data = ensure_list(await app.get_response(f"{IMAGES}/{iid}/addonImages"))
    return [pick(a, IMAGE_FIELDS) or a for a in data if isinstance(a, dict)]


def update_row(u: dict[str, Any]) -> dict[str, Any]:
    row = {
        "hostname": u.get("hostName"),
        "managementAddress": u.get("managementAddress"),
        "type": u.get("type"),
        "status": u.get("status"),
        "version": u.get("updateImageVersion"),
        "start": to_iso(u.get("startTime")) if u.get("startTime") else None,
        "end": to_iso(u.get("endTime")) if u.get("endTime") else None,
        "duration_s": _duration(u.get("startTime"), u.get("endTime")),
        "parentId": u.get("parentId"),
        "id": u.get("id"),
    }
    return {k: v for k, v in row.items() if v is not None}


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="Image readiness for a device")
    async def catc_image_readiness(
        ctx: Context,
        device: Annotated[str, Field(description="Device hostname, management IP, serial or id")],
        image: Annotated[
            str | None,
            Field(description="Target image name or id: is it for this device, and its add-on images"),
        ] = None,
        include_custom_validations: Annotated[
            bool, Field(description="Also list the custom validations that run around an update")
        ] = True,
    ) -> ToolResult:
        """Is this device ready for a software upgrade? The device's image status (running image, golden
        compliance, compatibility, last update status), the latest readiness check (the system pre-checks:
        flash space, config register, startup config, service entitlement...) with a verdict
        (READY / READY_WITH_WARNINGS / NOT_READY / IN_PROGRESS / NO_READINESS_CHECK) and each check's
        expected/actual/action, the pre/post validations of past distributions and activations, the
        custom validations, and with `image` whether that image is for the device's product, imported and
        verified, and its add-on images (SMUs, subpackages). Needs no image file. To run the check now:
        catc_run_image_readiness_check; past upgrades: catc_image_update_history."""
        app: CatcApp = get_client(ctx)
        dev = await resolve_device(app, device)
        did = safe_id(str(dev["id"]), "device id")
        name = str(dev.get("hostname") or dev.get("managementIpAddress") or did)
        notes: list[str] = []
        record: dict[str, Any] | None = None
        try:
            rec = await app.get_response(f"{NDI}/{did}")
            record = rec if isinstance(rec, dict) else None
        except UpstreamError as e:
            notes.append(f"Image status unavailable: {str(e)[:160]}")
        page = await fetch_all(app.pager, app.api, RESULTS, {"networkDeviceId": did}, cap=CAP)
        rows = [r for r in page.items if isinstance(r, dict)]
        out: dict[str, Any] = {"device": name, "device_id": did}
        if record:
            out["image_status"] = {
                "running": ", ".join(
                    str(i.get("name"))
                    for i in ensure_list(record.get("installedImages"))
                    if isinstance(i, dict)
                ),
                "product": (record.get("networkDevice") or {}).get("productName"),
                "golden_status": record.get("networkDeviceImageStatus"),
                "update_status": record.get("networkDeviceUpdateStatus"),
                "compatibility": record.get("networkDeviceImageCompatibilityStatus"),
            }
        out.update(summarize_results(rows, name))
        if not page.complete:
            notes.append(f"More than {CAP} validation results; only the first {CAP} were read.")
        if include_custom_validations:
            try:
                vpage = await fetch_all(app.pager, app.api, VALIDATIONS, cap=500)
                out["custom_validations"] = [
                    pick(v, ["name", "operationType", "type", "cli", "productSeriesOrdinals", "id"]) or v
                    for v in vpage.items
                    if isinstance(v, dict)
                ]
            except UpstreamError as e:
                notes.append(f"Custom validations unavailable: {str(e)[:160]}")
        if image:
            img = await resolve_image(app, image)
            target = image_applicability(img, record)
            try:
                target["addon_images"] = await addon_images(app, str(img["id"]))
            except UpstreamError as e:
                notes.append(f"Add-on images unavailable: {str(e)[:160]}")
            out["target_image"] = target
            if target["issues"]:
                notes.append(f"Target image: {'; '.join(target['issues'])}.")
        if notes:
            out["notes"] = notes
        return object_result(out, shape=False)

    @reg.write(title="Run image readiness check", destructive=False, idempotent=False)
    async def catc_run_image_readiness_check(
        ctx: Context,
        device: Annotated[str, Field(description="Device hostname, management IP, serial or id")],
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Run Catalyst Center's software-update readiness check on one device now (the system pre-checks
        it runs before a distribution or activation) and return the verdict and each check's result.
        Catalyst Center logs in and runs show commands; no configuration changes and no image is needed.
        Preview-first. Read the results later with catc_image_readiness."""
        app: CatcApp = get_client(ctx)
        dev = await resolve_device(app, device)
        did = safe_id(str(dev["id"]), "device id")
        name = str(dev.get("hostname") or dev.get("managementIpAddress") or did)
        path = f"{NDI}/{did}/readinessChecks"
        blockers = []
        reach = str(dev.get("reachabilityStatus") or "")
        if reach and reach.lower() != "reachable":
            blockers.append(f"{name} is {reach}: the pre-checks need a CLI session to it.")
        plan = Plan(
            f"Run the image update readiness check on {name} ({dev.get('managementIpAddress')})",
            details={
                "method": "POST",
                "path": path,
                "device": pick(
                    dev, ["hostname", "managementIpAddress", "platformId", "softwareVersion", "id"]
                ),
                "effect": "show commands on the device; no configuration change",
            },
            fingerprint={"device": did, "reachability": reach},
            blockers=blockers,
        )

        async def apply() -> Any:
            job = await app.run_job("POST", path, None, ctx=ctx, what="readiness check")
            run_id = _run_id_from(job)
            params: dict[str, Any] = {"networkDeviceId": did, "operationType": "READINESS_CHECK"}
            page = await fetch_all(app.pager, app.api, RESULTS, params, cap=CAP)
            rows = [r for r in page.items if isinstance(r, dict)]
            if run_id and any(str(r.get("parentId")) == run_id for r in rows):
                rows = [r for r in rows if str(r.get("parentId")) == run_id]
            summary = summarize_results(rows, name)
            runs = summary.pop("runs")
            summary.pop("latest_by_operation", None)
            return {
                "task": {k: job.get(k) for k in ("task_id", "status", "resultLocation") if job.get(k)},
                **summary,
                "checks": runs[0]["checks"] if runs else [],
            }

        return await preview_or_apply(
            ctx,
            tool="catc_run_image_readiness_check",
            args={"device": device},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.read(title="Image update history")
    async def catc_image_update_history(
        ctx: Context,
        device: Annotated[
            str | None, Field(description="Only this device (hostname, management IP, serial or id)")
        ] = None,
        status: Annotated[
            Literal["FAILURE", "SUCCESS", "IN_PROGRESS", "PENDING"] | None,
            Field(description="Only updates with this status"),
        ] = None,
        image_name: Annotated[str | None, Field(description="Only updates to this image name")] = None,
        limit: Annotated[int, Field(ge=1, le=500)] = 50,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """Software image distributions and activations Catalyst Center ran, newest first: device,
        type (DISTRIBUTION / ACTIVATE), status, image version, start/end and duration, and the parent id
        that groups one upgrade job. Explains past upgrade failures; the checks that ran around each one
        are in catc_image_readiness."""
        app: CatcApp = get_client(ctx)
        params: dict[str, Any] = {"sortBy": "startTime", "order": "desc"}
        if device:
            params["networkDeviceId"] = (await resolve_device(app, device))["id"]
        if status:
            params["status"] = status
        if image_name:
            params["imageName"] = image_name
        page = await app.pager.fetch_page(app.api, UPDATES, params, limit=limit, offset=offset)
        count_params = {k: v for k, v in params.items() if k not in ("sortBy", "order")}
        total = await _count(app, f"{UPDATES}/count", count_params)
        if total is not None:
            page.total = total
        page.items = [update_row(u) for u in page.items if isinstance(u, dict)]
        return list_result(page, fmt=response_format)

    @reg.read(title="List add-on images")
    async def catc_list_addon_images(
        ctx: Context,
        image: Annotated[str, Field(description="Software image name or id (catc_list_images)")],
        limit: Annotated[int, Field(ge=1, le=500)] = 50,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """Add-on images (SMUs, subpackages, APSP/APDP, ROMMON) that apply to one software image, with
        their type, golden tag, imported flag and integrity status."""
        app: CatcApp = get_client(ctx)
        img = await resolve_image(app, image)
        rows = await addon_images(app, str(img["id"]))
        # The API answers the whole list (no offset/limit): page it here.
        page = Page(items=rows[offset : offset + limit], offset=offset, total=len(rows))
        return list_result(page, fmt=response_format)

    @reg.read(title="Image distribution servers")
    async def catc_get_image_distribution_servers(ctx: Context) -> ToolResult:
        """Remote image distribution servers (SFTP; up to two) that devices copy images from: address,
        port, root location, user and id. Catalyst Center itself is always the local distribution server
        and isn't listed. Passwords are never returned."""
        app: CatcApp = get_client(ctx)
        data = ensure_list(await app.get_response(DIST_SERVERS))
        rows = [
            pick(s, ["serverAddress", "portNumber", "rootLocation", "username", "id"]) or s
            for s in data
            if isinstance(s, dict)
        ]
        out: dict[str, Any] = {
            "servers": rows,
            "note": "Catalyst Center is always the local distribution server (not listed).",
        }
        return object_result(out, shape=False)
