"""System tools: asynchronous task / execution status, audit log."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
from typing import Annotated, Any, Literal

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field

from catc_mcp._core import (
    NotFound,
    ResponseFormat,
    ToolRegistrar,
    ValidationFailed,
    get_client,
    list_result,
    object_result,
)
from catc_mcp._core.http import fetch_all, page_of
from catc_mcp.client import CatcApp, exec_summary, safe_id, task_summary
from catc_mcp.common import PAGE_AUDIT, resolve_device, resolve_site, window
from catc_mcp.tools.activity import AUDIT_SCAN_CAP, audit_kind, audit_rows, fetch_audit


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="Get task status")
    async def catc_get_task(
        ctx: Context,
        task_id: Annotated[
            str, Field(description="Task id (or business-API execution id) returned by a write tool")
        ],
        kind: Annotated[
            Literal["auto", "task", "execution"],
            Field(description="'task' (Intent API task), 'execution' (business API), or 'auto' to try both"),
        ] = "auto",
        include_children: Annotated[
            bool, Field(description="Also list the child tasks (useful when a parent task failed)")
        ] = False,
    ) -> ToolResult:
        """Status of an asynchronous Catalyst Center operation: progress, whether it finished or failed,
        the failure reason and any result data. Use it for task ids that write tools return when they
        did not wait, or that time out. Accepts Intent API task ids and business-API execution ids."""
        app: CatcApp = get_client(ctx)
        out: dict[str, Any]
        if kind in ("auto", "task"):
            try:
                t = await app.get_task(task_id)
                status = "FAILURE" if t.get("isError") else ("SUCCESS" if t.get("endTime") else "RUNNING")
                out = {"task_id": task_id, "status": status, **task_summary(t)}
                if t.get("failureReason"):
                    out["failureReason"] = t["failureReason"]
                if include_children:
                    kids = await app.get_response(f"/dna/intent/api/v1/task/{safe_id(task_id)}/tree")
                    out["tree"] = kids
                return object_result(out)
            except (NotFound, ValidationFailed):
                if kind == "task":
                    raise
        e = await app.get_execution(task_id)
        out = {"execution_id": task_id, "status": e.get("status"), **exec_summary(e)}
        return object_result(out)

    @reg.read(title="List audit logs")
    async def catc_list_audit_logs(
        ctx: Context,
        user: Annotated[str | None, Field(description="Only actions by this user id")] = None,
        category: Annotated[
            Literal[
                "INFO",
                "WARN",
                "ERROR",
                "ALERT",
                "TASK_PROGRESS",
                "TASK_FAILURE",
                "TASK_COMPLETE",
                "COMMAND",
                "QUERY",
                "CONVERSATION",
            ]
            | None,
            Field(description="Only this event category"),
        ] = None,
        text: Annotated[
            str | None, Field(description="Description contains this text (case-insensitive)")
        ] = None,
        device: Annotated[
            str | None, Field(description="Only records about this device (hostname, IP, serial or id)")
        ] = None,
        site: Annotated[
            str | None, Field(description="Only records about this site (hierarchy or id)")
        ] = None,
        device_id: Annotated[
            str | None, Field(description="Deprecated: same as `device` with a device id")
        ] = None,
        hours: Annotated[
            float, Field(gt=0, le=720, description="Look-back window in hours (default 24)")
        ] = 24,
        include_system: Annotated[bool, Field(description="Include system-generated records")] = False,
        changes_only: Annotated[
            bool,
            Field(
                description="Only changes: leave out logins, reads (retrievals, downloads, show commands) "
                "and Catalyst Center's internal provisioning steps. Use it for 'who changed what'."
            ),
        ] = False,
        limit: Annotated[int, Field(ge=1, le=500)] = 50,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """Catalyst Center audit log, newest first: who did what and when (logins, provisioning,
        template deploys, configuration changes, API calls) with the device it concerns. For "who
        changed what" pass changes_only=true: one provisioning alone writes dozens of internal records.
        A device or site filter keeps the records Catalyst Center tagged with it plus those whose text
        names it (most records carry no device/site tag). Times are UTC."""
        app: CatcApp = get_client(ctx)
        params: dict[str, Any] = {**window(hours), "isSystemEvents": str(include_system).lower()}
        if user:
            params["userId"] = user
        if category:
            params["category"] = category
        if text:
            params["description"] = text
        dev = await resolve_device(app, device) if device else None
        if device_id and not device:
            # Deprecated: passed through as before (works for devices no longer in inventory).
            params["deviceId"] = safe_id(device_id, "device id")
        st = await resolve_site(app, site) if site else None
        extra: dict[str, Any] | None = None
        if changes_only and dev is None and st is None:
            scan = await fetch_all(
                app.audit_pager,
                app.api,
                "/dna/data/api/v1/event/event-series/audit-logs",
                params,
                cap=AUDIT_SCAN_CAP,
                max_page=PAGE_AUDIT,
            )
            rows = [r for r in scan.items if isinstance(r, dict) and audit_kind(r) == "change"]
            page = page_of(rows, limit=limit, offset=offset)
            extra = {
                "left_out": f"{len(scan.items) - len(rows)} logins, reads and internal steps in the window"
            }
            if not scan.complete:
                extra["scan"] = (
                    f"Read the newest {AUDIT_SCAN_CAP} records of the window only; "
                    "narrow `hours` for older ones."
                )
        elif dev is None and st is None:
            page = await app.audit_pager.fetch_page(
                app.api,
                "/dna/data/api/v1/event/event-series/audit-logs",
                params,
                limit=limit,
                offset=offset,
                max_page=PAGE_AUDIT,
            )
        else:
            cap = AUDIT_SCAN_CAP if changes_only else offset + limit
            rows, more, truncated = await fetch_audit(app, params, device=dev, site=st, cap=cap)
            if changes_only:
                kept = [r for r in rows if audit_kind(r) == "change"]
                extra = {"left_out": f"{len(rows) - len(kept)} logins, reads and internal steps"}
                rows = kept
            page = page_of(rows, limit=limit, offset=offset)
            if (more or truncated) and not changes_only:
                page.total = None
                page.more = True
            if truncated:
                extra = {
                    **(extra or {}),
                    "scan": f"Device/site text matching scanned the newest {AUDIT_SCAN_CAP} records "
                    "only; narrow `hours` for older ones.",
                }
        page.items = await audit_rows(app, [r for r in page.items if isinstance(r, dict)])
        return list_result(
            page,
            fmt=response_format,
            columns=["time", "user", "device", "what", "category", "severity", "source", "id"],
            extra=extra,
        )
