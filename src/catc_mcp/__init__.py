"""MCP server for Cisco Catalyst Center, built on stutters-mcp-core."""

from stutters_mcp_core import run_cli

from catc_mcp.config import Settings
from catc_mcp.server import SPEC, create_server


def main() -> None:
    run_cli(SPEC, Settings, create_server)


__all__ = ["SPEC", "Settings", "create_server", "main"]
