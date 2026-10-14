"""Settings: CATC_* for the appliance, MCP_* for this server (see stutters_mcp_core.settings)."""

from pydantic import Field
from stutters_mcp_core import BaseServerSettings, server_config


class Settings(BaseServerSettings):
    model_config = server_config("CATC_")

    # CATC_COMMAND_RUNNER_TIMEOUT: how long catc_run_show_commands waits for the command-runner task.
    command_runner_timeout: float = Field(default=120.0, gt=0)
