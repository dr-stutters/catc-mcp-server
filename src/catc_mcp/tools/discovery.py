"""Discovery reads (D58: the v2 `discoverys/*` API, paged on the server) and catc_stop_discovery.

The v1 helpers (all_discoveries, resolve_discovery) stay for catc_create_discovery's name check and
catc_delete_discovery: v1 and v2 share the discovery ids (3.2.2: id "94" is the same discovery on both).
Live shapes (3.2.2, 2026-10-29): counts are {"response": {"count": n}}; a device's validationStatuses
use "NOT-PROVIDED" (hyphen) where the spec says NOT_PROVIDED."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
from datetime import UTC, datetime
from typing import Annotated, Any, Literal

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field

from catc_mcp._core import (
    Confirm,
    NotFound,
    Plan,
    ResponseFormat,
    ToolRegistrar,
    UpstreamError,
    get_client,
    list_result,
    preview_or_apply,
)
from catc_mcp._core.http import Page
from catc_mcp.client import CatcApp, safe_id
from catc_mcp.common import ensure_list, is_uuid

V2 = "/dna/intent/api/v1/discoverys"
PAGE = 500  # the v2 API's largest page
# Job states (3.2.2 spec): only a RUNNING job can be stopped.
STOPPABLE = {"RUNNING"}

# v1 network-device fields (catc_create_discovery wait=true lists what it found with these).
DEVICE_FIELDS = [
    "hostname",
    "managementIpAddress",
    "platformId",
    "reachabilityStatus",
    "reachabilityFailureReason",
    "inventoryCollectionStatus",
    "cliStatus",
    "snmpStatus",
    "netconfStatus",
    "id",
]


async def all_discoveries(app: CatcApp) -> list[dict[str, Any]]:
    total = await app.get_response("/dna/intent/api/v1/discovery/count")
    total = total if isinstance(total, int) else 500
    out: list[dict[str, Any]] = []
    start = 1
    while start <= total:
        chunk = ensure_list(await app.get_response(f"/dna/intent/api/v1/discovery/{start}/500"))
        out += [d for d in chunk if isinstance(d, dict)]
        if len(chunk) < 500:
            break
        start += 500
    return out


async def resolve_discovery(app: CatcApp, ref: str) -> dict[str, Any]:
    ref = ref.strip()
    if ref.isdigit() or is_uuid(ref):
        d = await app.get_response(f"/dna/intent/api/v1/discovery/{ref}")
        if isinstance(d, dict) and d.get("id"):
            return d
    for d in await all_discoveries(app):
        if str(d.get("name", "")).lower() == ref.lower() or str(d.get("id")) == ref:
            return d
    raise NotFound(f"No discovery {ref!r}. Use catc_list_discoveries.")


def to_iso(ms: Any) -> str | None:
    """Epoch milliseconds -> ISO 8601 UTC; None for a missing or bad value."""
    if isinstance(ms, bool) or not isinstance(ms, int | float) or ms <= 0:
        return None
    try:
        when = datetime.fromtimestamp(float(ms) / 1000, tz=UTC)
    except (ValueError, OverflowError, OSError):
        return None
    return when.isoformat(timespec="seconds").replace("+00:00", "Z")


def count_of(value: Any) -> int | None:
    """A v2 count: {"count": n} (3.2.2) or a bare integer."""
    if isinstance(value, dict):
        value = value.get("count")
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _addr(a: Any) -> str | None:
    if isinstance(a, dict) and a.get("cidrPrefix") is not None:
        return (
            f"{a.get('cidrPrefix')}/{a.get('cidrSuffix')}"
            if a.get("cidrSuffix") is not None
            else str(a["cidrPrefix"])
        )
    return str(a) if isinstance(a, str) and a else None


def targets_text(details: Any) -> str | None:
    """What a v2 discovery scans, as one line: '198.51.100.1-198.51.100.9', a CIDR, or a seed + hops."""
    if not isinstance(details, dict):
        return None
    ranges = [
        f"{r.get('ipAddressStart')}-{r.get('ipAddressEnd')}"
        for r in ensure_list(details.get("range"))
        if isinstance(r, dict)
    ]
    if ranges:
        return ",".join(ranges)
    seed = _addr(details.get("cidrAddress")) or _addr(details.get("ipAddress"))
    if seed and details.get("hopCount") is not None:
        return f"{seed} (seed, {details['hopCount']} hop(s))"
    return seed


def job_row(j: dict[str, Any]) -> dict[str, Any]:
    """One discovery with its latest (or a given) job, from a v2 summary or job record."""
    details = j.get("discoveryTypeDetails")
    row: dict[str, Any] = {
        "name": j.get("name"),
        "type": details.get("type") if isinstance(details, dict) else None,
        "targets": targets_text(details),
        "status": j.get("status"),
        "reachable_devices": j.get("reachableDevices"),
        "started": to_iso(j.get("startTime")),
        "ended": to_iso(j.get("endTime")),
        "job_id": j.get("jobId"),
        "id": j.get("id"),
    }
    return {k: v for k, v in row.items() if v is not None}


def device_row(d: dict[str, Any]) -> dict[str, Any]:
    raw = d.get("validationStatuses")
    v: dict[str, Any] = raw if isinstance(raw, dict) else {}
    row: dict[str, Any] = {
        "hostname": d.get("hostname"),
        "managementIpAddress": d.get("managementIpAddress"),
        "discoveryStatus": d.get("discoveryStatus"),
        "reachabilityStatus": d.get("reachabilityStatus"),
        "reachabilityFailureReason": d.get("reachabilityFailureReason"),
        "inventoryStatus": d.get("status"),
        **{p: str(v[p]).replace("-", "_") for p in ("ping", "cli", "snmp", "netconf", "http") if v.get(p)},
        "id": d.get("id"),
    }
    return {k: x for k, x in row.items() if x is not None}


async def find_discovery(app: CatcApp, ref: str) -> dict[str, Any]:
    """A discovery (v2 summary: settings + latest job) by id or exact name."""
    ref = ref.strip()
    if ref.isdigit() or is_uuid(ref):
        hit = ensure_list(await app.get_response(f"{V2}/jobs/summarys", {"id": ref}))
        if hit and isinstance(hit[0], dict):
            return dict(hit[0])
    matches: list[dict[str, Any]] = []
    offset = 1
    while True:
        chunk = ensure_list(
            await app.get_response(f"{V2}/jobs/summarys", {"name": ref, "limit": PAGE, "offset": offset})
        )
        matches += [d for d in chunk if isinstance(d, dict)]
        if len(chunk) < PAGE:
            break
        offset += PAGE
    exact = [d for d in matches if str(d.get("name", "")).lower() == ref.lower()]
    if exact:
        return exact[0]
    near = ", ".join(sorted(str(d.get("name")) for d in matches)[:10])
    raise NotFound(
        f"No discovery {ref!r}" + (f" (similar: {near})" if near else "") + ". Use catc_list_discoveries."
    )


async def discovery_job(app: CatcApp, d: dict[str, Any], job: str | None) -> dict[str, Any]:
    """The job to act on: the one named, else the discovery's latest job."""
    did = safe_id(str(d.get("id")), "discovery id")
    if job:
        j = await app.get_response(f"{V2}/{did}/jobs/{safe_id(job.strip(), 'job id')}")
        if not isinstance(j, dict) or not j.get("jobId"):
            raise NotFound(f"Discovery {d.get('name')!r} has no job {job!r}.")
        return {**d, **j}
    if not d.get("jobId"):
        raise NotFound(f"Discovery {d.get('name')!r} has not run a job yet.")
    return d


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="List discoveries")
    async def catc_list_discoveries(
        ctx: Context,
        name: Annotated[
            str | None, Field(description="Discovery name contains (partial match, done by Catalyst Center)")
        ] = None,
        limit: Annotated[int, Field(ge=1, le=PAGE)] = 50,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """Discoveries, newest first, each with its type (RANGE/CIDR/CDP/LLDP/SINGLE), the addresses it
        scans, the status of its latest job (RUNNING/QUEUED/COMPLETED/TERMINATED/SCHEDULED), the number of
        reachable devices it found, start/end times and the job id. Paged on the server (any offset).
        Use catc_list_discovery_devices to see what one found; catc_stop_discovery stops a running job."""
        app: CatcApp = get_client(ctx)
        filt = {"name": name} if name else {}
        items = ensure_list(
            await app.get_response(f"{V2}/jobs/summarys", {**filt, "limit": limit, "offset": offset + 1})
        )
        rows = [job_row(d) for d in items if isinstance(d, dict)]
        total = count_of(await app.get_response(f"{V2}/count", filt or None))
        page = Page(rows, offset, total, more=total is None and len(rows) >= limit)
        return list_result(page, fmt=response_format)

    @reg.read(title="List discovered devices")
    async def catc_list_discovery_devices(
        ctx: Context,
        discovery: Annotated[str, Field(description="Discovery name or id (from catc_list_discoveries)")],
        job: Annotated[
            str | None, Field(description="Job id (catc_list_discoveries job_id); default: the latest job")
        ] = None,
        reachability: Annotated[
            Literal["REACHABLE", "ONLY_PING_REACHABLE", "UNREACHABLE", "UNKNOWN"] | None,
            Field(description="Only devices with this reachability"),
        ] = None,
        limit: Annotated[int, Field(ge=1, le=PAGE)] = 100,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """Devices one discovery job found (the latest job unless `job` is given), with discovery status
        (SUCCESS/UNREACHABLE/DISCARDED), reachability and the failure reason, the inventory status, and
        per protocol whether ping/CLI/SNMP/NETCONF/HTTP credentials worked (SUCCESS, FAILURE,
        NOT_PROVIDED, NOT_VALIDATED): the place to look when a discovery 'found nothing'. Paged on the
        server, with the total from Catalyst Center's count."""
        app: CatcApp = get_client(ctx)
        j = await discovery_job(app, await find_discovery(app, discovery), job)
        path = f"{V2}/{safe_id(str(j['id']), 'discovery id')}/jobs/{safe_id(str(j['jobId']), 'job id')}"
        filt = {"reachabilityStatus": reachability} if reachability else {}
        items = ensure_list(
            await app.get_response(
                f"{path}/discoveredNetworkDevices", {**filt, "limit": limit, "offset": offset + 1}
            )
        )
        rows = [device_row(x) for x in items if isinstance(x, dict)]
        total = count_of(await app.get_response(f"{path}/discoveredNetworkDevices/count", filt or None))
        page = Page(rows, offset, total, more=total is None and len(rows) >= limit)
        extra = {"discovery": j.get("name"), "job_id": j.get("jobId"), "job_status": j.get("status")}
        return list_result(page, fmt=response_format, extra=extra)

    @reg.write(title="Stop discovery")
    async def catc_stop_discovery(
        ctx: Context,
        discovery: Annotated[str, Field(description="Discovery name or id (from catc_list_discoveries)")],
        job: Annotated[
            str | None, Field(description="Job id to stop; default: the discovery's latest job")
        ] = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Stop a running discovery job (e.g. one started on the wrong range). Preview-first: the preview
        names the discovery, the job, its state, start time and the addresses it scans, and is refused
        when the job is not RUNNING (completed, terminated, queued or scheduled). Devices it has already
        added stay in the inventory (remove them with catc_delete_device); the discovery itself stays and
        can be deleted with catc_delete_discovery."""
        app: CatcApp = get_client(ctx)
        j = await discovery_job(app, await find_discovery(app, discovery), job)
        did = safe_id(str(j["id"]), "discovery id")
        jid = safe_id(str(j["jobId"]), "job id")
        path = f"{V2}/{did}/jobs/{jid}/stop"
        status = str(j.get("status") or "UNKNOWN")
        blockers = []
        if status not in STOPPABLE:
            blockers.append(
                f"Job {jid} of discovery {j.get('name')!r} is {status}, not RUNNING: "
                "there is nothing to stop."
            )
        plan = Plan(
            f"Stop discovery {j.get('name')} (job {jid})",
            details={"job": job_row(j), "method": "POST", "path": path},
            side_effects=[
                "The rest of the addresses are not scanned; devices already found stay in the inventory.",
            ],
            fingerprint={"id": did, "job": jid, "status": status},
            blockers=blockers,
        )

        async def apply() -> Any:
            task = await app.run_job("POST", path, ctx=ctx, what="stop discovery")
            out: dict[str, Any] = {"discovery": j.get("name"), "job_id": jid, "task": task}
            try:
                after = await app.get_response(f"{V2}/{did}/jobs/{jid}")
                out["job_status"] = after.get("status") if isinstance(after, dict) else None
            except UpstreamError as err:
                out["job_status"] = {"unavailable": str(err)[:200]}
            return out

        return await preview_or_apply(
            ctx,
            tool="catc_stop_discovery",
            args={"discovery": discovery, "job": job},
            confirm=confirm,
            plan=plan,
            apply=apply,
        )
