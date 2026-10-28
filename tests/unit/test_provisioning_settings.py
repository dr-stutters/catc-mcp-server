"""D128: Visibility and Control of Configurations (provisioningSettings) read and dangerous-tier set, on the
payloads recorded from the 3.2.2 lab (tests/fixtures/provisioning_settings_322.json), plus the client hint on
Catalyst Center's 'config preview mandated' refusal."""

import json
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client
from fastmcp.exceptions import ToolError

from catc_mcp._core import ValidationFailed
from catc_mcp.client import CatcApp
from catc_mcp.server import create_server

from .conftest import make_settings
from .test_write_tools import run, task_ok

FIX = json.loads((Path(__file__).parent.parent / "fixtures" / "provisioning_settings_322.json").read_text())
PATH = "/dna/intent/api/v1/provisioningSettings"
ITSM = "/dna/intent/api/v1/integration-settings/itsm/instances"
ONE_ITSM = {
    "page": 1,
    "data": [{"name": "snow-prod", "id": "itsm-1", "typeId": "ServiceNow"}],
    "totalRecords": 1,
}


def rw() -> Any:
    return create_server(make_settings(mcp_enable_writes=True, mcp_enable_dangerous=True))


def mock_settings(api: respx.MockRouter, preview: bool = True, itsm: bool = False) -> dict[str, bool]:
    state = {"requirePreview": preview, "requireItsmApproval": itsm}
    api.get(PATH).mock(
        side_effect=lambda r: httpx.Response(200, json={"response": dict(state), "version": "1.0"})
    )
    return state


async def test_get_recorded(api: respx.MockRouter) -> None:
    api.get(PATH).respond(json=FIX["settings"])
    api.get(ITSM).respond(json=FIX["itsm_instances_none"])
    async with Client(create_server(make_settings())) as c:
        out = await run(c, "catc_get_provisioning_settings", {})
    assert out["require_preview"] is True and out["require_itsm_approval"] is False
    assert "reviewed" in out["meaning"] and "catc_deploy_template" in out["affected_tools"]
    assert out["itsm_instances"] == []


async def test_get_off_has_no_affected_tools(api: respx.MockRouter) -> None:
    mock_settings(api, preview=False)
    api.get(ITSM).respond(500, json={"message": "boom"})
    async with Client(create_server(make_settings())) as c:
        out = await run(c, "catc_get_provisioning_settings", {})
    assert out["require_preview"] is False and "affected_tools" not in out
    assert str(out["itsm_instances"]).startswith("unavailable")


async def test_set_is_dangerous_tier(api: respx.MockRouter) -> None:
    async with Client(create_server(make_settings(mcp_enable_writes=True))) as c:
        names = {t.name for t in await c.list_tools()}
    assert "catc_set_provisioning_settings" not in names and "catc_get_provisioning_settings" in names


async def test_preview_then_apply_turn_preview_off(api: respx.MockRouter) -> None:
    state = mock_settings(api)

    def put(request: httpx.Request) -> httpx.Response:
        state.update(json.loads(request.content))
        return httpx.Response(
            202, json={"response": {"taskId": "t-ps", "url": "/api/v1/task/t-ps"}, "version": "1.0"}
        )

    route = api.put(PATH).mock(side_effect=put)
    task_ok(api, "t-ps")
    async with Client(rw()) as c:
        preview = await run(c, "catc_set_provisioning_settings", {"require_preview": False})
        assert preview["status"] == "preview" and route.call_count == 0
        p = preview["preview"]
        assert p["request"]["body"] == {"requirePreview": False, "requireItsmApproval": False}
        assert p["current"] == {"require_preview": True, "require_itsm_approval": False}
        assert {
            "catc_provision_devices",
            "catc_deploy_template",
            "catc_deploy_wlc_config",
            "catc_activate_image",
        } <= set(p["affected_tools"])
        assert any("straight away" in e for e in p["effects"]) and any("Global" in e for e in p["effects"])
        done = await run(
            c, "catc_set_provisioning_settings", {"require_preview": False, "confirm": preview["confirm"]}
        )
    assert json.loads(route.calls.last.request.content) == {
        "requirePreview": False,
        "requireItsmApproval": False,
    }
    assert done["result"]["require_preview"] is False and done["result"]["task_id"] == "t-ps"
    assert "warning" not in done["result"]


async def test_turn_back_on_preview(api: respx.MockRouter) -> None:
    mock_settings(api, preview=False)
    async with Client(rw()) as c:
        preview = await run(c, "catc_set_provisioning_settings", {"require_preview": True})
    assert preview["status"] == "preview"
    assert any("config preview" in e and "mandated" in e for e in preview["preview"]["effects"])


async def test_itsm_refused_without_instance(api: respx.MockRouter) -> None:
    mock_settings(api)
    api.get(ITSM).respond(json=FIX["itsm_instances_none"])
    put = api.put(PATH)
    async with Client(rw()) as c:
        out = await run(c, "catc_set_provisioning_settings", {"require_itsm_approval": True})
    assert out["status"] == "blocked" and "No ITSM integration" in json.dumps(out["blockers"])
    assert put.call_count == 0


async def test_itsm_needs_preview(api: respx.MockRouter) -> None:
    mock_settings(api)
    api.get(ITSM).respond(json=ONE_ITSM)
    async with Client(rw()) as c:
        out = await run(
            c, "catc_set_provisioning_settings", {"require_itsm_approval": True, "require_preview": False}
        )
    assert out["status"] == "blocked" and "needs require_preview=true" in json.dumps(out["blockers"])


async def test_itsm_allowed_with_instance_implies_preview(api: respx.MockRouter) -> None:
    mock_settings(api, preview=False)
    api.get(ITSM).respond(json=ONE_ITSM)
    async with Client(rw()) as c:
        out = await run(c, "catc_set_provisioning_settings", {"require_itsm_approval": True})
    assert out["status"] == "preview"
    assert out["preview"]["request"]["body"] == {"requirePreview": True, "requireItsmApproval": True}
    assert any("snow-prod" in e for e in out["preview"]["effects"])


async def test_noop_and_empty_call(api: respx.MockRouter) -> None:
    mock_settings(api)
    put = api.put(PATH)
    async with Client(rw()) as c:
        out = await run(c, "catc_set_provisioning_settings", {"require_preview": True})
        with pytest.raises(ToolError, match="require_preview and/or"):
            await c.call_tool("catc_set_provisioning_settings", {})
    assert out["status"] == "no_change" and put.call_count == 0


async def test_preview_mandated_error_points_to_setting(api: respx.MockRouter) -> None:
    """D85/D128: a write refused because the provisioning settings mandate a preview names the setting; an
    unrelated 422 does not."""
    path = "/dna/intent/api/v1/sda/provisionDevices"
    api.post(path).mock(
        side_effect=[
            httpx.Response(
                422, json={"response": {"errorCode": "NCSP10250", "message": "Config preview mandated"}}
            ),
            httpx.Response(422, json={"response": {"message": "siteId is invalid"}}),
        ]
    )
    app = CatcApp(make_settings())
    try:
        with pytest.raises(ValidationFailed) as e:
            await app.api.post(path, [{}])
        assert "mandated" in str(e.value) and "catc_get_provisioning_settings" in str(e.value)
        assert e.value.status_code == 422
        with pytest.raises(ValidationFailed) as e2:
            await app.api.post(path, [{}])
        assert "provisioning_settings" not in str(e2.value)
    finally:
        await app.aclose()
