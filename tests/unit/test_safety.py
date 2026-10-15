"""D19/D20: device-count limit, site/tag targets, blast radius and core's rails (window, dry run, two-person)
on the device-changing tools."""

from datetime import UTC, datetime
from typing import Any

import httpx
import pytest
import respx
import stutters_mcp_core.policy
from fastmcp import Client
from fastmcp.exceptions import ToolError
from stutters_mcp_core.testing import as_caller

from catc_mcp.server import create_server

from .conftest import make_settings
from .test_read_tools import AREA, BLDG, DEV_ID, DEVICE, GLOBAL, fixture
from .test_write_tools import mock_sites, run, task_ok

TID = "72a0afc4-0b5c-4c69-b47f-f647eb34d71b"
DEV2 = {
    **DEVICE,
    "id": "22222222-2222-3333-4444-555555555555",
    "hostname": "edge-sw2",
    "managementIpAddress": "10.0.0.12",
}
TAG = {"id": "99999999-1111-2222-3333-444444444444", "name": "access"}


def mock_inventory(api: respx.MockRouter) -> None:
    devices = [DEVICE, DEV2]

    def by_query(request: httpx.Request) -> httpx.Response:
        q = request.url.params
        if q.get("id"):
            ids = q["id"].split(",")
            return httpx.Response(200, json={"response": [d for d in devices if d["id"] in ids]})
        for d in devices:
            host = str(q.get("hostname", "")).removesuffix(".*")
            if q.get("managementIpAddress") == d["managementIpAddress"] or host in (
                d["hostname"],
                d["hostname"].split(".")[0],
            ):
                return httpx.Response(200, json={"response": [d]})
        if not q.get("hostname") and not q.get("managementIpAddress") and not q.get("serialNumber"):
            return httpx.Response(200, json={"response": devices})
        return httpx.Response(200, json={"response": []})

    api.get("/dna/intent/api/v1/network-device").mock(side_effect=by_query)
    for d in devices:
        api.get(f"/dna/intent/api/v1/network-device/{d['id']}").respond(json={"response": d})


def mock_template(api: respx.MockRouter) -> None:
    tpl = {
        **fixture("templates.json")[0],
        "versionsInfo": [
            {"id": "v1", "version": "1", "versionTime": 1792060568267, "versionComment": "first"},
            {"id": "v2", "version": "2", "versionTime": 1792070568267, "versionComment": "second"},
        ],
    }
    api.get("/dna/intent/api/v1/template-programmer/template").respond(json=[tpl])
    api.put("/dna/intent/api/v1/template-programmer/template/preview").respond(json={"cliPreview": "x"})


async def preview(name: str, args: dict[str, Any], **settings: Any) -> dict[str, Any]:
    s = make_settings(mcp_enable_writes=True, mcp_enable_dangerous=True, **settings)
    async with Client(create_server(s)) as c:
        return await run(c, name, args)


async def test_deploy_limit_blocks_and_reports_blast_radius(api: respx.MockRouter) -> None:
    mock_inventory(api)
    mock_template(api)
    args = {"template": TID, "devices": ["edge-sw1", "edge-sw2"]}
    out = await preview("catc_deploy_template", args, max_devices_per_change=1)
    assert out["status"] == "blocked" and "CATC_MAX_DEVICES_PER_CHANGE=1" in out["blockers"][0]
    out = await preview("catc_deploy_template", args)
    assert out["status"] == "preview" and out["blast_radius"] == 2
    assert out["preview"]["template_version"]["version"] == "2"
    assert out["preview"]["template_version"]["committed"].startswith("2026-")
    out = await preview(
        "catc_deploy_template", {"template": TID, "devices": ["edge-sw1"]}, max_devices_per_change=1
    )
    assert out["status"] == "preview" and out["blast_radius"] == 1


async def test_deploy_core_blast_radius_limit(api: respx.MockRouter) -> None:
    mock_inventory(api)
    mock_template(api)
    out = await preview(
        "catc_deploy_template", {"template": TID, "devices": ["edge-sw1", "edge-sw2"]}, mcp_max_blast_radius=1
    )
    assert out["status"] == "blocked"


async def test_deploy_by_tag_and_site(api: respx.MockRouter) -> None:
    mock_inventory(api)
    mock_template(api)
    api.get("/dna/intent/api/v1/tag").respond(json={"response": [TAG]})
    api.get(f"/dna/intent/api/v1/tag/{TAG['id']}/member").respond(json={"response": [{"id": DEV_ID}]})
    out = await preview("catc_deploy_template", {"template": TID, "tag": "access"})
    assert out["preview"]["targets"] == {"by": "tag", "tag": "access"} and out["blast_radius"] == 1

    mock_sites(api, [GLOBAL, AREA, BLDG])
    api.get("/dna/intent/api/v1/networkDevices/assignedToSite").mock(
        side_effect=lambda r: httpx.Response(
            200,
            json={"response": [{"deviceId": DEV2["id"]}] if r.url.params["siteId"] == BLDG["id"] else []},
        )
    )
    out = await preview("catc_deploy_template", {"template": TID, "site": "Global/AU"})
    assert out["preview"]["targets"]["site"] == "Global/AU" and out["preview"]["devices"][0].startswith(
        "edge-sw2"
    )
    # Global = the whole inventory, refused past the limit
    out = await preview("catc_deploy_template", {"template": TID, "site": "Global"}, max_devices_per_change=1)
    assert out["status"] == "blocked" and "2 devices" in out["blockers"][0]


async def test_deploy_needs_exactly_one_target(api: respx.MockRouter) -> None:
    mock_template(api)
    for args in ({}, {"devices": ["edge-sw1"], "tag": "access"}):
        with pytest.raises(ToolError, match="exactly one target"):
            await preview("catc_deploy_template", {"template": TID, **args})


async def test_provision_limit(api: respx.MockRouter) -> None:
    mock_inventory(api)
    mock_sites(api, [GLOBAL, AREA, BLDG])
    api.get("/dna/intent/api/v1/sda/provisionDevices").respond(json={"response": []})
    args = {"devices": ["edge-sw1", "edge-sw2"], "site": "Global/AU/SYD-1"}
    out = await preview("catc_provision_devices", args, max_devices_per_change=1)
    assert out["status"] == "blocked"
    out = await preview("catc_provision_devices", args, max_devices_per_change=0)  # 0 = off
    assert out["status"] == "preview" and out["blast_radius"] == 2


async def test_change_window_refuses_confirm(api: respx.MockRouter, monkeypatch: pytest.MonkeyPatch) -> None:
    mock_inventory(api)
    api.get("/dna/intent/api/v1/sda/provisionDevices").respond(json={"response": []})
    delete = api.delete(f"/dna/intent/api/v1/network-device/{DEV_ID}").respond(
        202, json={"response": {"taskId": "t"}}
    )
    task_ok(api, "t")
    # Thursday 14:00 Sydney, outside a weekend window
    monkeypatch.setattr(stutters_mcp_core.policy, "_now", lambda: datetime(2026, 10, 15, 3, 0, tzinfo=UTC))
    s = make_settings(
        mcp_enable_writes=True,
        mcp_enable_dangerous=True,
        mcp_change_window="Sat-Sun 00:00-23:59 Australia/Sydney",
    )
    args = {"device": "edge-sw1", "clean_config": False}
    async with Client(create_server(s)) as c:
        out = await run(c, "catc_delete_device", args)
        assert out["policy"]["change_window"]["open"] is False
        with pytest.raises(ToolError, match="(?i)change window"):
            await run(c, "catc_delete_device", {**args, "confirm": out["confirm"]})
    assert delete.call_count == 0


async def test_dry_run_blocks_delete(api: respx.MockRouter) -> None:
    mock_inventory(api)
    api.get("/dna/intent/api/v1/sda/provisionDevices").respond(json={"response": []})
    out = await preview("catc_delete_device", {"device": "edge-sw1", "clean_config": True}, mcp_dry_run=True)
    assert out["policy"]["dry_run"] is True and "confirm" not in out


async def test_deploy_token_bound_to_resolved_devices(api: respx.MockRouter) -> None:
    """A tag whose members change between preview and confirm invalidates the token."""
    mock_inventory(api)
    mock_template(api)
    api.get("/dna/intent/api/v1/tag").respond(json={"response": [TAG]})
    api.get(f"/dna/intent/api/v1/tag/{TAG['id']}/member").mock(
        side_effect=[
            httpx.Response(200, json={"response": [{"id": DEV_ID}]}),
            httpx.Response(200, json={"response": [{"id": DEV_ID}, {"id": DEV2["id"]}]}),
        ]
    )
    deploy = api.post("/dna/intent/api/v2/template-programmer/template/deploy")
    s = make_settings(mcp_enable_writes=True, mcp_enable_dangerous=True)
    async with Client(create_server(s)) as c:
        out = await run(c, "catc_deploy_template", {"template": TID, "tag": "access"})
        with pytest.raises(ToolError, match="changed since the preview"):
            await run(
                c, "catc_deploy_template", {"template": TID, "tag": "access", "confirm": out["confirm"]}
            )
    assert deploy.call_count == 0


async def test_two_person_on_provision(api: respx.MockRouter) -> None:
    mock_inventory(api)
    mock_sites(api, [GLOBAL, AREA, BLDG])
    api.get("/dna/intent/api/v1/sda/provisionDevices").respond(json={"response": []})
    post = api.post("/dna/intent/api/v1/sda/provisionDevices").respond(
        202, json={"response": {"taskId": "tp"}}
    )
    task_ok(api, "tp")
    s = make_settings(mcp_enable_writes=True, mcp_enable_dangerous=True, mcp_two_person_tools="@dangerous")
    args = {"devices": ["edge-sw1"], "site": "Global/AU/SYD-1"}
    async with Client(create_server(s)) as c:
        with as_caller("alice"):
            out = await run(c, "catc_provision_devices", args)
            with pytest.raises(ToolError):
                await run(c, "catc_provision_devices", {**args, "confirm": out["confirm"]})
        with as_caller("bob"):
            done = await run(c, "catc_provision_devices", {**args, "confirm": out["confirm"]})
    assert done["status"] == "applied" and post.call_count == 1


async def test_truncated_tag_refused(api: respx.MockRouter) -> None:
    mock_template(api)
    api.get("/dna/intent/api/v1/tag").respond(json={"response": [TAG]})
    from stutters_mcp_core.http import paging

    async def partial(*a: Any, **k: Any) -> Any:
        return paging.Page(items=[{"id": DEV_ID}], offset=0, total=99999)

    import catc_mcp.safety as safety

    orig = safety.fetch_all
    safety.fetch_all = partial  # type: ignore[assignment]
    try:
        with pytest.raises(ToolError, match="Narrow the selection"):
            await preview("catc_deploy_template", {"template": TID, "tag": "access"})
    finally:
        safety.fetch_all = orig
