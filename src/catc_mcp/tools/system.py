"""System tools: asynchronous task / execution status, audit log."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
from typing import Annotated, Any, Literal

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field
from stutters_mcp_core import (
    NotFound,
    ResponseFormat,
    ToolRegistrar,
    ValidationFailed,
    get_client,
    list_result,
    object_result,
)
from stutters_mcp_core.http import OffsetLimit

from catc_mcp.client import CatcApp, exec_summary, safe_id, task_summary
from catc_mcp.common import pick, window

# Audit log: bare JSON list, 0-based offset, at most 25 records per request.
AUDIT_PAGER = OffsetLimit(items=None, max_page=25)
AUDIT_FIELDS = [
    "timestamp",
    "userId",
    "category",
    "severity",
    "domain",
    "name",
    "description",
    "source",
    "instanceId",
]


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
        device_id: Annotated[str | None, Field(description="Only records about this device id")] = None,
        hours: Annotated[
            float, Field(gt=0, le=720, description="Look-back window in hours (default 24)")
        ] = 24,
        include_system: Annotated[bool, Field(description="Include system-generated records")] = False,
        limit: Annotated[int, Field(ge=1, le=500)] = 50,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """Catalyst Center audit log, newest first: who did what and when (logins, provisioning,
        template deploys, configuration changes, API calls), with category and severity. Useful for
        "what changed recently" questions."""
        app: CatcApp = get_client(ctx)
        params: dict[str, Any] = {**window(hours), "isSystemEvents": str(include_system).lower()}
        if user:
            params["userId"] = user
        if category:
            params["category"] = category
        if text:
            params["description"] = text
        if device_id:
            params["deviceId"] = safe_id(device_id, "device id")
        page = await AUDIT_PAGER.fetch_page(
            app.api, "/dna/data/api/v1/event/event-series/audit-logs", params, limit=limit, offset=offset
        )
        page.items = [pick(r, AUDIT_FIELDS) for r in page.items if isinstance(r, dict)]
        return list_result(page, fmt=response_format)
