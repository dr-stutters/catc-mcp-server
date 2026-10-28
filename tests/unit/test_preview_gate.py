"""#286 (D128): the previews of the gated tools (template deploy, provisioning, SWIM) say when Catalyst
Center's Visibility and Control of Configurations (requirePreview / requireItsmApproval) holds the change,
on the 3.2.2 payload shape (tests/fixtures/provisioning_settings_322.json); a failed read leaves the preview
working."""

from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client

from catc_mcp.server import create_server
from catc_mcp.tools.provisioning_settings import gate_effect

from .conftest import make_settings
from .test_dangerous_tools import TID
from .test_read_tools import AREA, BLDG, GLOBAL, fixture, mock_device_lookup
from .test_write_tools import mock_sites, run

PATH = "/dna/intent/api/v1/provisioningSettings"
IMG = {"id": "dddddddd-1111-2222-3333-444444444444", "name": "img.bin", "version": "17.12.4"}


def settings(api: respx.MockRouter, preview: bool, itsm: bool = False) -> respx.Route:
    return api.get(PATH).respond(
        json={"response": {"requirePreview": preview, "requireItsmApproval": itsm}, "version": "1.0"}
    )


def mock_tool(api: respx.MockRouter, tool: str) -> dict[str, Any]:
    """The reads one gated tool's preview needs, and its arguments."""
    mock_device_lookup(api)
    if tool == "catc_deploy_template":
        tpl = {**fixture("templates.json")[0], "versionsInfo": [{"version": "1"}]}
        api.get("/dna/intent/api/v1/template-programmer/template").respond(json=[tpl])
        api.put("/dna/intent/api/v1/template-programmer/template/preview").respond(
            json={"cliPreview": "aaa new-model", "validationErrors": []}
        )
        return {"template": TID, "devices": ["edge-sw1"]}
    if tool == "catc_provision_devices":
        mock_sites(api, [GLOBAL, AREA, BLDG])
        api.get("/dna/intent/api/v1/sda/provisionDevices").respond(json={"response": []})
        return {"devices": ["edge-sw1"], "site": "Global/AU/SYD-1"}
    api.get("/dna/intent/api/v1/images").respond(json={"response": [IMG]})
    return {"device": "edge-sw1", "image": "img.bin"}


async def preview(tool: str, args: dict[str, Any]) -> dict[str, Any]:
    settings_ = make_settings(mcp_enable_writes=True, mcp_enable_dangerous=True)
    async with Client(create_server(settings_)) as c:
        out: dict[str, Any] = await run(c, tool, args)
    return out


TOOLS = ["catc_deploy_template", "catc_provision_devices", "catc_distribute_image", "catc_activate_image"]


@pytest.mark.parametrize("tool", TOOLS)
async def test_preview_says_require_preview_is_on(api: respx.MockRouter, tool: str) -> None:
    route = settings(api, preview=True)
    out = await preview(tool, mock_tool(api, tool))
    assert out["status"] == "preview"
    gate = [e for e in out["side_effects"] if "Visibility and Control" in e]
    assert len(gate) == 1 and "config preview mandated" in gate[0] and "Work Item" in gate[0]
    assert out["preview"]["provisioning_settings"]["require_preview"] is True
    assert route.call_count == 1  # one read per call


@pytest.mark.parametrize("tool", TOOLS)
async def test_preview_quiet_when_off(api: respx.MockRouter, tool: str) -> None:
    settings(api, preview=False)
    out = await preview(tool, mock_tool(api, tool))
    assert out["status"] == "preview"
    assert not [e for e in out["side_effects"] if "Visibility and Control" in e]
    assert out["preview"]["provisioning_settings"] == {
        "require_preview": False,
        "require_itsm_approval": False,
    }


@pytest.mark.parametrize("tool", TOOLS)
async def test_preview_survives_unreadable_settings(api: respx.MockRouter, tool: str) -> None:
    api.get(PATH).respond(500, json={"message": "boom"})
    out = await preview(tool, mock_tool(api, tool))
    assert out["status"] == "preview"
    assert not [e for e in out["side_effects"] if "Visibility and Control" in e]
    assert "unavailable" in out["preview"]["provisioning_settings"]


async def test_itsm_line(api: respx.MockRouter) -> None:
    settings(api, preview=True, itsm=True)
    out = await preview("catc_deploy_template", mock_tool(api, "catc_deploy_template"))
    gate = [e for e in out["side_effects"] if "Visibility and Control" in e]
    assert len(gate) == 1 and "ITSM (ServiceNow)" in gate[0] and "template deploy" in gate[0]


async def test_provision_site_preview(api: respx.MockRouter) -> None:
    from .test_provision_site import mock_site

    settings(api, preview=True)
    mock_site(api, [])
    out = await preview("catc_provision_site", {"site": "Global/AU/SYD-1"})
    gate = [e for e in out["side_effects"] if "Visibility and Control" in e]
    assert len(gate) == 1 and "provisioning creates a preview" in gate[0]


async def test_confirm_refused_when_setting_flips(api: respx.MockRouter) -> None:
    """The setting is in the fingerprint: turning it on after the preview invalidates the token."""
    state = {"requirePreview": False, "requireItsmApproval": False}
    api.get(PATH).mock(side_effect=lambda r: httpx.Response(200, json={"response": dict(state)}))
    args = mock_tool(api, "catc_distribute_image")
    settings_ = make_settings(mcp_enable_writes=True, mcp_enable_dangerous=True)
    async with Client(create_server(settings_)) as c:
        first = await run(c, "catc_distribute_image", args)
        state["requirePreview"] = True
        again = await c.call_tool(
            "catc_distribute_image", {**args, "confirm": first["confirm"]}, raise_on_error=False
        )
    assert again.is_error and "changed since the preview" in str(again.content)


def test_gate_effect_unknown_is_silent() -> None:
    assert gate_effect({"require_preview": None, "require_itsm_approval": None}, "x") is None
