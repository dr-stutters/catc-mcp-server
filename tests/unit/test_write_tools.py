"""Write tools: preview-first flow, blockers and request bodies (respx-mocked)."""

import json
from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client
from fastmcp.exceptions import ToolError

from catc_mcp.server import create_server

from .conftest import make_settings
from .test_read_tools import AREA, BLDG, DEV_ID, DEVICE, GLOBAL, mock_device_lookup


async def run(c: Client, name: str, args: dict[str, Any]) -> Any:  # type: ignore[type-arg]
    res = await c.call_tool(name, args)
    if res.structured_content is not None:
        return res.structured_content
    return json.loads("\n".join(getattr(x, "text", "") for x in res.content))


async def preview_then_apply(name: str, args: dict[str, Any]) -> tuple[Any, Any]:
    async with Client(create_server(make_settings(mcp_enable_writes=True))) as c:
        preview = await run(c, name, args)
        if preview["status"] != "preview":
            return preview, None
        done = await run(c, name, {**args, "confirm": preview["confirm"]})
    return preview, done


def mock_sites(api: respx.MockRouter, sites: list[dict[str, Any]]) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        q = request.url.params
        if "nameHierarchy" in q:
            return httpx.Response(
                200, json={"response": [s for s in sites if s["nameHierarchy"] == q["nameHierarchy"]]}
            )
        if "name" in q:
            return httpx.Response(200, json={"response": [s for s in sites if s["name"] == q["name"]]})
        return httpx.Response(200, json={"response": sites})

    api.get("/dna/intent/api/v1/sites").mock(side_effect=handler)


def task_ok(api: respx.MockRouter, task_id: str, data: str = "new-id", progress: str = "done") -> None:
    api.get(f"/dna/intent/api/v1/task/{task_id}").respond(
        json={"response": {"data": data, "progress": progress, "endTime": 1, "isError": False}}
    )


async def test_create_area_preview_then_apply(api: respx.MockRouter) -> None:
    mock_sites(api, [GLOBAL])
    post = api.post("/dna/intent/api/v1/areas").respond(202, json={"response": {"taskId": "t1"}})
    task_ok(api, "t1", data="area-uuid")
    preview, done = await preview_then_apply("catc_create_site", {"site_type": "area", "name": "AU"})
    assert preview["action"] == "Create area Global/AU" and post.call_count == 1  # only the apply posted
    assert done["result"] == {"site_id": "area-uuid", "nameHierarchy": "Global/AU", "task": "t1"}
    assert json.loads(post.calls.last.request.content) == {"name": "AU", "parentId": GLOBAL["id"]}


async def test_create_site_blockers(api: respx.MockRouter) -> None:
    mock_sites(api, [GLOBAL, AREA])
    preview, _ = await preview_then_apply("catc_create_site", {"site_type": "area", "name": "AU"})
    assert preview["status"] == "blocked" and "already exists" in preview["blockers"][0]
    preview, _ = await preview_then_apply(
        "catc_create_site", {"site_type": "floor", "name": "F1", "parent": "Global/AU"}
    )
    assert preview["status"] == "blocked" and "can't go under a area" in preview["blockers"][0]
    preview, _ = await preview_then_apply(
        "catc_create_site", {"site_type": "building", "name": "B", "parent": "AU"}
    )
    assert any("country" in b for b in preview["blockers"])


async def test_create_floor_defaults(api: respx.MockRouter) -> None:
    mock_sites(api, [GLOBAL, AREA, BLDG])
    post = api.post("/dna/intent/api/v2/floors").respond(202, json={"response": {"taskId": "t2"}})
    task_ok(api, "t2")
    await preview_then_apply(
        "catc_create_site", {"site_type": "floor", "name": "L1", "parent": "Global/AU/SYD-1"}
    )
    body = json.loads(post.calls.last.request.content)
    assert (
        body["parentId"] == BLDG["id"]
        and body["floorNumber"] == 1
        and body["rfModel"] == "Cubes And Walled Offices"
    )


async def test_update_building_changes_and_fingerprint(api: respx.MockRouter) -> None:
    mock_sites(api, [GLOBAL, AREA, BLDG])
    detail = {**BLDG, "parentId": AREA["id"], "country": "Australia", "address": "1 George St"}
    api.get(f"/dna/intent/api/v2/buildings/{BLDG['id']}").mock(
        side_effect=[
            httpx.Response(200, json={"response": detail}),
            httpx.Response(200, json={"response": {**detail, "address": "changed elsewhere"}}),
        ]
    )
    put = api.put(f"/dna/intent/api/v2/buildings/{BLDG['id']}").respond(
        202, json={"response": {"taskId": "t3"}}
    )
    task_ok(api, "t3")
    with pytest.raises(ToolError, match="changed since the preview"):
        await preview_then_apply("catc_update_site", {"site": "Global/AU/SYD-1", "address": "2 George St"})
    assert put.call_count == 0


async def test_update_site_rejects_wrong_fields(api: respx.MockRouter) -> None:
    mock_sites(api, [GLOBAL, AREA])
    api.get(f"/dna/intent/api/v1/areas/{AREA['id']}").respond(
        json={"response": {**AREA, "parentId": GLOBAL["id"]}}
    )
    with pytest.raises(ToolError, match="has no address"):
        await preview_then_apply("catc_update_site", {"site": "Global/AU", "address": "x"})


async def test_tag_members_add_and_remove(api: respx.MockRouter) -> None:
    tag = {"id": "aaaaaaaa-1111-2222-3333-444444444444", "name": "mcp-test", "systemTag": False}
    api.get("/dna/intent/api/v1/tag").respond(json={"response": [tag]})
    api.get(f"/dna/intent/api/v1/tag/{tag['id']}/member").respond(json={"response": []})
    mock_device_lookup(api)
    add = api.post(f"/dna/intent/api/v1/tag/{tag['id']}/member").respond(
        202, json={"response": {"taskId": "t4"}}
    )
    task_ok(api, "t4")
    preview, done = await preview_then_apply(
        "catc_update_tag_members", {"tag": "mcp-test", "add": ["edge-sw1"]}
    )
    assert preview["preview"]["add"] == ["edge-sw1.lab.local (10.0.0.11)"]
    assert json.loads(add.calls.last.request.content) == {"networkdevice": [DEV_ID]}
    preview, _ = await preview_then_apply(
        "catc_update_tag_members", {"tag": "mcp-test", "remove": ["edge-sw1"]}
    )
    assert preview["status"] == "blocked"  # not a member, nothing to do


async def test_discovery_masks_secrets(api: respx.MockRouter) -> None:
    api.get("/dna/intent/api/v1/globalCredentials").respond(
        json={"response": [{"id": "c1", "type": "CLI", "description": "lab", "username": "u"}]}
    )
    api.get("/dna/intent/api/v1/discovery/count").respond(json={"response": 0})
    post = api.post("/dna/intent/api/v1/discovery").respond(202, json={"response": {"taskId": "t5"}})
    api.get("/dna/intent/api/v1/task/t5").respond(json={"response": {"data": "7", "progress": "7"}})
    args = {"name": "d1", "ip_ranges": ["10.0.0.1-10.0.0.9"], "cli_username": "u", "cli_password": "S3cret!"}
    preview, done = await preview_then_apply("catc_create_discovery", args)
    assert "S3cret!" not in json.dumps(preview) and "S3cret!" not in json.dumps(done)
    sent = json.loads(post.calls.last.request.content)
    assert sent["passwordList"] == ["S3cret!"] and sent["globalCredentialIdList"] == ["c1"]
    assert done["result"]["discovery_id"] == "7"


async def test_assign_to_site_needs_building_or_floor(api: respx.MockRouter) -> None:
    mock_sites(api, [GLOBAL, AREA, BLDG])
    mock_device_lookup(api)
    api.get(f"/dna/intent/api/v1/networkDevices/{DEV_ID}/assignedToSite").respond(
        json={"response": {"deviceId": DEV_ID, "siteNameHierarchy": "Global"}}
    )
    preview, _ = await preview_then_apply(
        "catc_assign_devices_to_site", {"devices": ["edge-sw1"], "site": "Global/AU"}
    )
    assert preview["status"] == "blocked"
    post = api.post("/dna/intent/api/v1/networkDevices/assignToSite/apply").respond(
        202, json={"response": {"taskId": "t6"}}
    )
    task_ok(api, "t6")
    _, done = await preview_then_apply(
        "catc_assign_devices_to_site", {"devices": ["10.0.0.11"], "site": "SYD-1"}
    )
    assert done["status"] == "applied"
    assert json.loads(post.calls.last.request.content) == {"deviceIds": [DEV_ID], "siteId": BLDG["id"]}
    # Already there: nothing to do.
    api.get(f"/dna/intent/api/v1/networkDevices/{DEV_ID}/assignedToSite").respond(
        json={"response": {"deviceId": DEV_ID, "siteNameHierarchy": BLDG["nameHierarchy"]}}
    )
    preview, _ = await preview_then_apply(
        "catc_assign_devices_to_site", {"devices": ["10.0.0.11"], "site": "SYD-1"}
    )
    assert preview["status"] == "blocked" and "already" in preview["blockers"][0]


async def test_task_failure_surfaces(api: respx.MockRouter) -> None:
    mock_sites(api, [GLOBAL])
    api.post("/dna/intent/api/v1/areas").respond(202, json={"response": {"taskId": "t7"}})
    api.get("/dna/intent/api/v1/task/t7").respond(
        json={"response": {"isError": True, "endTime": 1, "failureReason": "NCGR10001: bad name"}}
    )
    with pytest.raises(ToolError, match="NCGR10001"):
        await preview_then_apply("catc_create_site", {"site_type": "area", "name": "X"})


async def test_template_create_and_commit(api: respx.MockRouter) -> None:
    proj = {"id": "bbbbbbbb-1111-2222-3333-444444444444", "name": "P1", "templates": []}
    api.get("/dna/intent/api/v1/template-programmer/project").respond(json=[proj])
    tpl_list = api.get("/dna/intent/api/v1/template-programmer/template").respond(json=[])
    post = api.post(f"/dna/intent/api/v1/template-programmer/project/{proj['id']}/template").respond(
        202, json={"response": {"taskId": "t8"}}
    )
    task_ok(api, "t8", data="tpl-1")
    _, done = await preview_then_apply(
        "catc_create_template", {"project": "P1", "name": "T1", "content": "hostname {{ h }}"}
    )
    assert done["result"]["template_id"] == "tpl-1"
    body = json.loads(post.calls.last.request.content)
    assert body["projectName"] == "P1" and body["deviceTypes"] == [{"productFamily": "Switches and Hubs"}]
    assert tpl_list.calls.last.request.url.params["unCommitted"] == "true"


async def test_device_write_tools_hidden_when_read_only() -> None:
    async with Client(create_server(make_settings())) as c:
        names = {t.name for t in await c.list_tools()}
    assert "catc_create_site" not in names and "catc_list_devices" in names


def test_device_fixture_shape() -> None:
    assert DEVICE["id"] == DEV_ID


async def test_confirm_refused_when_device_resolution_changes(api: respx.MockRouter) -> None:
    """The token binds the resolved device ids: if the name now points at another device, refuse."""
    other = {**DEVICE, "id": "99999999-2222-3333-4444-555555555555"}
    api.get("/dna/intent/api/v1/network-device").mock(
        side_effect=[
            httpx.Response(200, json={"response": [DEVICE]}),
            httpx.Response(200, json={"response": [other]}),
        ]
    )
    sync = api.put("/dna/intent/api/v1/network-device/sync").respond(202, json={"response": {"taskId": "t9"}})
    with pytest.raises(ToolError, match="changed since the preview"):
        await preview_then_apply("catc_resync_devices", {"devices": ["10.0.0.11"]})
    assert sync.call_count == 0


async def test_issue_status_looks_up_issues(api: respx.MockRouter) -> None:
    iid = "cccccccc-1111-2222-3333-444444444444"
    api.get(f"/dna/data/api/v1/assuranceIssues/{iid}").respond(
        json={"response": [{"id": iid, "name": "ap_down", "status": "active"}]}
    )
    post = api.post("/dna/intent/api/v1/assuranceIssues/resolve").respond(
        json={"response": {"successfulIssueIds": [iid]}}
    )
    preview, done = await preview_then_apply(
        "catc_update_issue_status", {"issue_ids": [iid], "action": "resolve"}
    )
    assert preview["preview"]["issues"][0]["name"] == "ap_down"
    assert done["status"] == "applied" and json.loads(post.calls.last.request.content) == {"issueIds": [iid]}


async def test_discovery_password_needs_username(api: respx.MockRouter) -> None:
    api.get("/dna/intent/api/v1/globalCredentials").respond(json={"response": []})
    api.get("/dna/intent/api/v1/discovery/count").respond(json={"response": 0})
    preview, _ = await preview_then_apply(
        "catc_create_discovery", {"name": "d", "ip_ranges": ["10.0.0.1"], "cli_password": "x"}
    )
    assert preview["status"] == "blocked"
