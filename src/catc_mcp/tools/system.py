"""System tools: asynchronous task / execution status."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
from typing import Annotated, Any, Literal

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field
from stutters_mcp_core import NotFound, ToolRegistrar, ValidationFailed, get_client, object_result

from catc_mcp.client import CatcApp, exec_summary, safe_id, task_summary


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
