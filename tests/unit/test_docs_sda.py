"""D109: every catc_ tool or prompt docs/sd-access.md names exists on the server."""

import re
from pathlib import Path

from fastmcp import Client

from catc_mcp.server import create_server

from .conftest import make_settings

DOC = Path(__file__).resolve().parents[2] / "docs" / "sd-access.md"


async def test_sd_access_guide_names_real_tools() -> None:
    names = set(re.findall(r"\bcatc_[a-z0-9_]+\b", DOC.read_text()))
    assert names, "the guide names no tools"
    async with Client(create_server(make_settings(mcp_enable_writes=True, mcp_enable_dangerous=True))) as c:
        known = {t.name for t in await c.list_tools()} | {p.name for p in await c.list_prompts()}
    assert not names - known, f"docs/sd-access.md names unknown tools: {sorted(names - known)}"
