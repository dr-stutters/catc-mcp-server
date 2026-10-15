"""Workflow prompts: core prompt contract, rendering and tier gating (D6)."""

from fastmcp import Client
from stutters_mcp_core.testing import assert_prompt_contract

from catc_mcp.server import create_server

from .conftest import make_settings

SAMPLES = {
    "catc_onboard_device": {
        "ip_or_range": "198.18.128.170",
        "site_path": "Global/mcp-test-lab/mcp-test-bldg",
        "cli_credential": "mcp-test-cli",
        "snmp_credential": "mcp-test-snmp-ro",
        "provision": "true",
    }
}


async def test_prompt_contract_all_tiers() -> None:
    server = create_server(make_settings(mcp_enable_writes=True, mcp_enable_dangerous=True))
    await assert_prompt_contract(
        server, "catc", samples=SAMPLES, known_prefixes={"cml", "ise", "fmc", "catc"}
    )


async def test_onboard_prompt_renders() -> None:
    async with Client(create_server(make_settings(mcp_enable_writes=True))) as c:
        prompts = {p.name: p for p in await c.list_prompts()}
        assert "catc_onboard_device" in prompts
        res = await c.get_prompt("catc_onboard_device", SAMPLES["catc_onboard_device"])
        text = res.messages[0].content.text  # type: ignore[union-attr]
        assert "`catc_create_discovery`" in text and "198.18.128.170" in text
        assert "`catc_provision_devices`" in text and "Global/mcp-test-lab/mcp-test-bldg" in text
        no_prov = await c.get_prompt(
            "catc_onboard_device", {**SAMPLES["catc_onboard_device"], "provision": "false"}
        )
        assert "`catc_provision_devices`" not in no_prov.messages[0].content.text  # type: ignore[union-attr]


async def test_onboard_prompt_hidden_read_only() -> None:
    async with Client(create_server(make_settings())) as c:
        assert "catc_onboard_device" not in {p.name for p in await c.list_prompts()}


async def test_onboard_prompt_range_acts_on_all_devices() -> None:
    args = {**SAMPLES["catc_onboard_device"], "ip_or_range": "10.0.0.1-10.0.0.2"}
    async with Client(create_server(make_settings(mcp_enable_writes=True))) as c:
        text = (await c.get_prompt("catc_onboard_device", args)).messages[0].content.text  # type: ignore[union-attr]
    assert "devices=DEVICES" in text and "not just the first" in text
