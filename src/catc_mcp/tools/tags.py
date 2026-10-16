"""Tag reads."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
from typing import Annotated, Any, Literal

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field

from catc_mcp._core import ResponseFormat, ToolRegistrar, get_client, list_result
from catc_mcp.client import CatcApp
from catc_mcp.common import pick, resolve_tag

TAG_FIELDS = ["name", "description", "systemTag", "dynamicRules", "id"]


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="List tags")
    async def catc_list_tags(
        ctx: Context,
        name: Annotated[
            str | None, Field(description="Tag name filter ('*' wildcard ok, e.g. 'mcp-*')")
        ] = None,
        include_system: Annotated[bool, Field(description="Include built-in system tags")] = True,
        limit: Annotated[int, Field(ge=1, le=500)] = 50,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """Tags used to group devices and interfaces (for templates, provisioning and filtering): name,
        description, whether it is a system tag, dynamic membership rules and id."""
        app: CatcApp = get_client(ctx)
        params: dict[str, Any] = {"sortBy": "name", "order": "asc"}
        if name:
            params["name"] = name
        if not include_system:
            params["systemTag"] = "false"
        page = await app.pager.fetch_page(
            app.api, "/dna/intent/api/v1/tag", params, limit=limit, offset=offset
        )
        page.items = [pick(t, TAG_FIELDS) for t in page.items if isinstance(t, dict)]
        return list_result(page, fmt=response_format)

    @reg.read(title="List tag members")
    async def catc_list_tag_members(
        ctx: Context,
        tag: Annotated[str, Field(description="Tag name or id (from catc_list_tags)")],
        member_type: Annotated[
            Literal["networkdevice", "interface"], Field(description="Kind of member to list")
        ] = "networkdevice",
        limit: Annotated[int, Field(ge=1, le=500)] = 100,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """Members of one tag: network devices (hostname, IP, platform) or interfaces, whether added
        statically or by a dynamic rule."""
        app: CatcApp = get_client(ctx)
        t = await resolve_tag(app, tag)
        page = await app.pager.fetch_page(
            app.api,
            f"/dna/intent/api/v1/tag/{t['id']}/member",
            {"memberType": member_type},
            limit=limit,
            offset=offset,
        )
        fields = ["hostname", "managementIpAddress", "platformId", "portName", "deviceId", "id"]
        page.items = [pick(m, fields) or m for m in page.items if isinstance(m, dict)]
        return list_result(page, fmt=response_format, extra={"tag": t.get("name")})
