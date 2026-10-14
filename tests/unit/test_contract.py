from stutters_mcp_core.testing import assert_tool_contract, call_tool

from catc_mcp.server import create_server

from .conftest import make_settings


async def test_contract_all_tiers() -> None:
    await assert_tool_contract(
        create_server(make_settings(mcp_enable_writes=True, mcp_enable_dangerous=True)), "catc"
    )


async def test_contract_read_only() -> None:
    await assert_tool_contract(create_server(make_settings()), "catc")


async def test_no_write_tools_when_read_only() -> None:
    from fastmcp import Client

    async with Client(create_server(make_settings())) as c:
        tools = await c.list_tools()
    for t in tools:
        assert t.annotations is not None and t.annotations.read_only_hint, t.name


async def test_status_does_not_leak_secrets(api) -> None:  # type: ignore[no-untyped-def]
    api.get("/dna/intent/api/v1/dnac-release").respond(json={"response": {"installedVersion": "3.2.2-75131"}})
    api.get("/dna/intent/api/v1/network-device/count").respond(json={"response": 0})
    api.get("/dna/intent/api/v1/sites/count").respond(json={"response": {"count": 1}})
    out = await call_tool(create_server(make_settings()), "catc_status")
    text = str(out)
    assert "3.2.2-75131" in text
    assert "pw" not in text.replace("password", "") and "tok-123" not in text
    assert out["catc"]["devices"] == 0
