"""Discovery reads."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
from typing import Annotated, Any

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field

from catc_mcp._core import NotFound, ResponseFormat, ToolRegistrar, get_client, list_result
from catc_mcp._core.http import Page
from catc_mcp.client import CatcApp
from catc_mcp.common import ensure_list, is_uuid, pick

DISCOVERY_FIELDS = [
    "name",
    "discoveryType",
    "ipAddressList",
    "discoveryStatus",
    "discoveryCondition",
    "numDevices",
    "deviceIds",
    "protocolOrder",
    "timeOut",
    "retryCount",
    "id",
]
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


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="List discoveries")
    async def catc_list_discoveries(
        ctx: Context,
        name: Annotated[str | None, Field(description="Discovery name contains (case-insensitive)")] = None,
        limit: Annotated[int, Field(ge=1, le=500)] = 50,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """Discovery jobs with their type (range/CDP/LLDP/single), IP ranges, status, condition and
        number of devices found. Use catc_list_discovery_devices to see what one found."""
        app: CatcApp = get_client(ctx)
        rows = [pick(d, DISCOVERY_FIELDS) for d in await all_discoveries(app)]
        if name:
            rows = [r for r in rows if name.lower() in str(r.get("name", "")).lower()]
        for r in rows:
            if isinstance(r.get("deviceIds"), str):
                r["deviceIds"] = len([x for x in r["deviceIds"].split(",") if x])
        return list_result(Page(rows[offset : offset + limit], offset, len(rows)), fmt=response_format)

    @reg.read(title="List discovered devices")
    async def catc_list_discovery_devices(
        ctx: Context,
        discovery: Annotated[str, Field(description="Discovery name or id (from catc_list_discoveries)")],
        limit: Annotated[int, Field(ge=1, le=500)] = 100,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """Devices found by one discovery with reachability, the failure reason when unreachable, and
        CLI/SNMP/NETCONF credential status: the place to look when a discovery 'found nothing'."""
        app: CatcApp = get_client(ctx)
        d = await resolve_discovery(app, discovery)
        total = await app.get_response(f"/dna/intent/api/v1/discovery/{d['id']}/network-device/count")
        items = ensure_list(
            await app.get_response(
                f"/dna/intent/api/v1/discovery/{d['id']}/network-device/{offset + 1}/{limit}"
            )
        )
        rows = [pick(x, DEVICE_FIELDS) for x in items if isinstance(x, dict)]
        page = Page(rows, offset, total if isinstance(total, int) else None, more=len(rows) >= limit)
        return list_result(page, fmt=response_format, extra={"discovery": d.get("name")})
