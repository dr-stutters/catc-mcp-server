"""Print the tool list as a Markdown table, grouped by tier (used for the README)."""

import asyncio
import re

from fastmcp import Client

from catc_mcp.config import Settings
from catc_mcp.server import create_server


async def main() -> None:
    settings = Settings(
        _env_file=None,
        url="https://catc.invalid",
        mcp_enable_writes=True,
        mcp_enable_dangerous=True,
        mcp_cache_dir="",
    )  # type: ignore[call-arg]
    server = create_server(settings)
    tiers = server._stutters_tiers  # type: ignore[attr-defined]
    async with Client(server) as c:
        tools = await c.list_tools()
    for tier in ("read", "write", "dangerous"):
        rows = [t for t in tools if tiers[t.name].value == tier]
        print(f"\n### {tier.title()} ({len(rows)})\n")
        print("| Tool | What it does |\n|---|---|")
        for t in sorted(rows, key=lambda t: t.name):
            desc = " ".join((t.description or "").split())
            first = re.split(r"(?<!e\.g)\. ", desc)[0].replace("|", "\\|")
            print(f"| `{t.name}` | {first.rstrip('.')}. |")


asyncio.run(main())
