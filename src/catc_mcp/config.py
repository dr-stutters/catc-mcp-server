"""Settings: CATC_* for the appliance, MCP_* for this server (see catc_mcp._core.settings)."""

from pydantic import Field

from catc_mcp._core import BaseServerSettings, server_config


class Settings(BaseServerSettings):
    model_config = server_config("CATC_")

    # CATC_COMMAND_RUNNER_TIMEOUT: how long catc_run_show_commands waits for the command-runner task.
    command_runner_timeout: float = Field(default=120.0, gt=0)

    # CATC_MAX_DEVICES_PER_CHANGE: the most devices one template deploy, provisioning, SWIM, PnP or device
    # change may touch (D19); 0 turns the limit off. Core's MCP_MAX_BLAST_RADIUS applies on top.
    max_devices_per_change: int = Field(default=10, ge=0)
