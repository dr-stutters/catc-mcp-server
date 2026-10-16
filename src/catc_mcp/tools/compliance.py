"""Compliance reads (and, with writes enabled, running a compliance check)."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import asyncio
from datetime import UTC, datetime
from typing import Annotated, Any, Literal

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field

from catc_mcp._core import ToolRegistrar, get_client, object_result
from catc_mcp.client import CatcApp
from catc_mcp.common import ensure_list, pick, resolve_device

STATUSES = ["COMPLIANT", "NON_COMPLIANT", "IN_PROGRESS", "NOT_AVAILABLE", "NOT_APPLICABLE", "ERROR"]
CATEGORIES = Literal["INTENT", "RUNNING_CONFIG", "IMAGE", "PSIRT", "DESIGN_OOD", "EOX", "NETWORK_SETTINGS"]


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="Compliance summary")
    async def catc_get_compliance_summary(
        ctx: Context,
        max_devices: Annotated[
            int, Field(ge=0, le=500, description="How many non-compliant devices to list (default 50)")
        ] = 50,
    ) -> ToolResult:
        """Fleet compliance at a glance: how many devices are compliant, non-compliant, in progress,
        not available or in error, and which devices are non-compliant (with hostname). Drill into one
        with catc_get_compliance_detail."""
        app: CatcApp = get_client(ctx)
        counts = await asyncio.gather(
            *(
                app.get_response("/dna/intent/api/v1/compliance/count", {"complianceStatus": s})
                for s in STATUSES
            )
        )
        out: dict[str, Any] = {"counts": dict(zip(STATUSES, counts, strict=True))}
        if max_devices:
            bad = ensure_list(
                await app.get_response(
                    "/dna/intent/api/v1/compliance",
                    {"complianceStatus": "NON_COMPLIANT,ERROR", "limit": max_devices, "offset": 1},
                )
            )
            names: dict[str, str] = {}
            ids = [str(b.get("deviceUuid")) for b in bad if isinstance(b, dict) and b.get("deviceUuid")]
            if ids:
                devs = ensure_list(
                    await app.get_response("/dna/intent/api/v1/network-device", {"id": ",".join(ids[:100])})
                )
                names = {d["id"]: d.get("hostname", "") for d in devs if isinstance(d, dict) and d.get("id")}
            out["non_compliant"] = [
                {
                    "device": names.get(str(b.get("deviceUuid")), b.get("deviceUuid")),
                    "status": b.get("complianceStatus"),
                    "lastUpdateTime": b.get("lastUpdateTime"),
                    "deviceUuid": b.get("deviceUuid"),
                }
                for b in bad
                if isinstance(b, dict)
            ]
        return object_result(out)

    @reg.read(title="Device compliance detail")
    async def catc_get_compliance_detail(
        ctx: Context,
        device: Annotated[str, Field(description="Device hostname, management IP, serial number or id")],
        category: Annotated[CATEGORIES | None, Field(description="Only this compliance category")] = None,
        include_diff: Annotated[
            bool, Field(description="Include the config/intent difference list for non-compliant items")
        ] = False,
    ) -> ToolResult:
        """Compliance report for one device per category (startup vs running config, image, PSIRT,
        EoX, network settings, network profile, fabric): status, message, last check time, whether
        Catalyst Center can remediate it and, with include_diff, what differs. Non-compliant items come
        first. For RUNNING_CONFIG (unsaved changes) see the actual lines with
        catc_compare_device_configs(compare='startup'). Re-check with catc_run_compliance."""
        app: CatcApp = get_client(ctx)
        dev = await resolve_device(app, device)
        params: dict[str, Any] = {}
        if category:
            params["category"] = category
        if include_diff:
            params["diffList"] = "true"
        detail = await app.get_response(f"/dna/intent/api/v1/compliance/{dev['id']}/detail", params)
        rows = []
        for d in ensure_list(detail):
            if not isinstance(d, dict):
                continue
            row = pick(
                d, ["complianceType", "status", "state", "message", "severity", "remediationSupported"]
            )
            if isinstance(d.get("lastUpdateTime"), int | float):
                row["checked"] = datetime.fromtimestamp(d["lastUpdateTime"] / 1000, tz=UTC).strftime(
                    "%Y-%m-%d %H:%M UTC"
                )
            if d.get("sourceInfoList"):
                row["differences"] = d["sourceInfoList"]
            rows.append(row)
        rows.sort(key=lambda r: (r.get("status") == "COMPLIANT", str(r.get("complianceType"))))
        return object_result({"device": dev.get("hostname"), "deviceUuid": dev["id"], "compliance": rows})
