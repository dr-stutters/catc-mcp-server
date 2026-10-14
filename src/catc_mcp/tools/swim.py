"""Software image management (SWIM) reads."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
from typing import Annotated, Any

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field
from stutters_mcp_core import ResponseFormat, ToolRegistrar, get_client, list_result

from catc_mcp.client import CatcApp
from catc_mcp.common import pick, resolve_site

IMAGE_FIELDS = [
    "name",
    "version",
    "productNames",
    "imported",
    "golden",
    "recommended",
    "integrityStatus",
    "isAddonImage",
    "imageType",
    "id",
]


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="List software images")
    async def catc_list_images(
        ctx: Context,
        name: Annotated[str | None, Field(description="Image name contains (min 3 characters)")] = None,
        version: Annotated[
            str | None, Field(description="Version contains (min 3 characters), e.g. '17.9'")
        ] = None,
        golden: Annotated[
            bool | None, Field(description="true: only golden-tagged images; false: only untagged")
        ] = None,
        imported: Annotated[
            bool | None, Field(description="true: only images imported into the repository")
        ] = None,
        site: Annotated[
            str | None, Field(description="Site whose golden tagging to evaluate (default Global)")
        ] = None,
        limit: Annotated[int, Field(ge=1, le=500)] = 50,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """Software images known to Catalyst Center (imported into the repository, or suggested from
        cisco.com): name, version, product families, golden tag, integrity status and id. Use
        golden=true to see the golden images per site."""
        app: CatcApp = get_client(ctx)
        params: dict[str, Any] = {}
        if name:
            params["name"] = name
        if version:
            params["version"] = version
        if golden is not None:
            params["golden"] = str(golden).lower()
        if imported is not None:
            params["imported"] = str(imported).lower()
        if site:
            params["siteId"] = (await resolve_site(app, site))["id"]
        page = await app.pager.fetch_page(
            app.api, "/dna/intent/api/v1/images", params, limit=limit, offset=offset
        )
        page.items = [pick(i, IMAGE_FIELDS) or i for i in page.items if isinstance(i, dict)]
        return list_result(page, fmt=response_format)
