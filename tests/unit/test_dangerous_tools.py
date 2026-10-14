"""Dangerous tools (mocked: the lab has no devices or images to deploy, provision or upgrade)."""

import json
from typing import Any

import httpx
import respx
from fastmcp import Client

from catc_mcp.server import create_server
from catc_mcp.tools.dangerous import deploy_outcome

from .conftest import make_settings
from .test_read_tools import AREA, BLDG, DEV_ID, GLOBAL, fixture, mock_device_lookup
from .test_write_tools import mock_sites, run, task_ok

TID = "72a0afc4-0b5c-4c69-b47f-f647eb34d71b"


async def flow(name: str, args: dict[str, Any], *, dangerous: bool = True) -> tuple[Any, Any]:
    settings = make_settings(mcp_enable_writes=True, mcp_enable_dangerous=dangerous)
    async with Client(create_server(settings)) as c:
        preview = await run(c, name, args)
        if preview.get("status") != "preview":
            return preview, None
        done = await run(c, name, {**args, "confirm": preview["confirm"]})
    return preview, done


async def test_dangerous_hidden_without_flag() -> None:
    async with Client(create_server(make_settings(mcp_enable_writes=True))) as c:
        names = {t.name for t in await c.list_tools()}
    assert "catc_create_site" in names
    assert not names & {
        "catc_deploy_template",
        "catc_delete_site",
        "catc_provision_devices",
        "catc_activate_image",
    }


def test_deploy_outcome_parsing() -> None:
    text = (
        "Deployment of  Template: x.nonApplicableTargets: {10.255.255.1=Device does not exist in inventory}."
        "ApplicableTargets: None. None of the targets are applicable for the template. Hence not deploying"
    )
    out = deploy_outcome(text)
    assert out["deployed"] is False and "does not exist" in out["not_applicable"]
    assert deploy_outcome("Template Deployemnt Id: 3c4d5e6f-1111-2222-3333-444455556666")["deployment_id"]


async def test_deploy_template_blocks_uncommitted(api: respx.MockRouter) -> None:
    api.get("/dna/intent/api/v1/template-programmer/template").respond(json=fixture("templates.json"))
    mock_device_lookup(api)
    api.put("/dna/intent/api/v1/template-programmer/template/preview").respond(
        json={"cliPreview": "aaa new-model"}
    )
    preview, _ = await flow("catc_deploy_template", {"template": TID, "devices": ["edge-sw1"]})
    assert preview["status"] == "blocked" and "never been committed" in preview["blockers"][0]


async def test_deploy_template_applies_and_polls_deployment(api: respx.MockRouter) -> None:
    tpl = {**fixture("templates.json")[0], "versionsInfo": [{"version": "1"}]}
    api.get("/dna/intent/api/v1/template-programmer/template").respond(json=[tpl])
    mock_device_lookup(api)
    api.put("/dna/intent/api/v1/template-programmer/template/preview").respond(
        json={"cliPreview": "enable secret 9 $9$x\naaa new-model", "validationErrors": []}
    )
    dep = "3c4d5e6f-1111-2222-3333-444455556666"
    post = api.post("/dna/intent/api/v2/template-programmer/template/deploy").respond(
        202, json={"response": {"taskId": "td"}}
    )
    task_ok(api, "td", data=TID, progress=f"Template Deployemnt Id: {dep}")
    api.get(f"/dna/intent/api/v1/template-programmer/template/deploy/status/{dep}").mock(
        side_effect=[
            httpx.Response(200, json={"status": "IN_PROGRESS"}),
            httpx.Response(
                200, json={"status": "SUCCESS", "devices": [{"deviceId": DEV_ID, "status": "SUCCESS"}]}
            ),
        ]
    )
    preview, done = await flow(
        "catc_deploy_template", {"template": TID, "devices": ["edge-sw1"], "params": {"a": 1}}
    )
    assert (
        "$9$x" not in json.dumps(preview)
        and "aaa new-model" in preview["preview"]["rendered_cli_first_device"]
    )
    assert done["result"]["deployment"]["status"] == "SUCCESS"
    body = json.loads(post.calls.last.request.content)
    assert body["targetInfo"] == [{"id": DEV_ID, "type": "MANAGED_DEVICE_UUID", "params": {"a": 1}}]


async def test_provision_devices(api: respx.MockRouter) -> None:
    mock_sites(api, [GLOBAL, AREA, BLDG])
    mock_device_lookup(api)
    api.get("/dna/intent/api/v1/sda/provisionDevices").respond(json={"response": []})
    post = api.post("/dna/intent/api/v1/sda/provisionDevices").respond(
        202, json={"response": {"taskId": "tp"}}
    )
    task_ok(api, "tp")
    preview, done = await flow("catc_provision_devices", {"devices": ["edge-sw1"], "site": "Global/AU/SYD-1"})
    assert preview["side_effects"] and done["status"] == "applied"
    assert json.loads(post.calls.last.request.content) == [{"networkDeviceId": DEV_ID, "siteId": BLDG["id"]}]
    preview, _ = await flow("catc_provision_devices", {"devices": ["edge-sw1"], "site": "Global/AU"})
    assert preview["status"] == "blocked"


async def test_activate_image(api: respx.MockRouter) -> None:
    mock_device_lookup(api)
    img = {
        "id": "dddddddd-1111-2222-3333-444444444444",
        "name": "cat9k_iosxe.17.12.04.SPA.bin",
        "version": "17.12.4",
    }
    api.get("/dna/intent/api/v1/images").respond(json={"response": [img]})
    post = api.post(f"/dna/intent/api/v1/networkDeviceImages/{DEV_ID}/activate").respond(
        202, json={"response": {"taskId": "ta"}}
    )
    task_ok(api, "ta")
    preview, done = await flow("catc_activate_image", {"device": "edge-sw1", "image": img["name"]})
    assert "RELOADS" in preview["side_effects"][0] and preview["preview"]["current_version"] == "17.9.4"
    assert json.loads(post.calls.last.request.content) == {"installedImages": [{"id": img["id"]}]}
    assert done["status"] == "applied"


async def test_distribute_image_body(api: respx.MockRouter) -> None:
    mock_device_lookup(api)
    img = {"id": "dddddddd-1111-2222-3333-444444444444", "name": "img.bin", "version": "17.12.4"}
    api.get("/dna/intent/api/v1/images").respond(json={"response": [img]})
    post = api.post(f"/dna/intent/api/v1/networkDeviceImages/{DEV_ID}/distribute").respond(
        202, json={"response": {"taskId": "tdi"}}
    )
    task_ok(api, "tdi")
    await flow("catc_distribute_image", {"device": "edge-sw1", "image": "img.bin"})
    assert json.loads(post.calls.last.request.content) == {"distributedImages": [{"id": img["id"]}]}


async def test_delete_site_recursive_order(api: respx.MockRouter) -> None:
    floor = {
        "id": "aaaaaaaa-0000-0000-0000-000000000003",
        "name": "L1",
        "nameHierarchy": "Global/AU/SYD-1/L1",
        "type": "floor",
    }
    mock_sites(api, [GLOBAL, AREA, BLDG, floor])
    api.get("/dna/intent/api/v1/networkDevices/assignedToSite/count").respond(json={"response": {"count": 0}})
    preview, _ = await flow("catc_delete_site", {"site": "Global/AU"})
    assert preview["status"] == "blocked" and "recursive" in preview["blockers"][0]
    calls: list[str] = []
    for path in (
        f"/dna/intent/api/v2/floors/{floor['id']}",
        f"/dna/intent/api/v2/buildings/{BLDG['id']}",
        f"/dna/intent/api/v1/areas/{AREA['id']}",
    ):
        api.delete(path).mock(
            side_effect=lambda req, p=path: (
                calls.append(p),
                httpx.Response(202, json={"response": {"taskId": "tx"}}),
            )[1]
        )
    task_ok(api, "tx")
    _, done = await flow("catc_delete_site", {"site": "Global/AU", "recursive": True})
    assert done["result"]["deleted"] == ["Global/AU/SYD-1/L1", "Global/AU/SYD-1", "Global/AU"]
    assert calls[0].endswith(floor["id"]) and calls[-1].endswith(AREA["id"])


async def test_delete_site_blocked_by_devices(api: respx.MockRouter) -> None:
    mock_sites(api, [GLOBAL, AREA, BLDG])
    api.get("/dna/intent/api/v1/networkDevices/assignedToSite/count").respond(json={"response": {"count": 3}})
    preview, _ = await flow("catc_delete_site", {"site": "Global/AU/SYD-1"})
    assert preview["status"] == "blocked" and "3 device(s)" in preview["blockers"][0]


async def test_delete_device(api: respx.MockRouter) -> None:
    mock_device_lookup(api)
    api.get("/dna/intent/api/v1/sda/provisionDevices").respond(json={"response": []})
    route = api.delete(f"/dna/intent/api/v1/network-device/{DEV_ID}").respond(
        202, json={"response": {"taskId": "tdd"}}
    )
    task_ok(api, "tdd")
    _, done = await flow("catc_delete_device", {"device": "edge-sw1", "clean_config": True})
    assert done["status"] == "applied" and route.calls.last.request.url.params["cleanConfig"] == "true"


async def test_deploy_preview_masks_secret_params(api: respx.MockRouter) -> None:
    tpl = {**fixture("templates.json")[0], "versionsInfo": [{"id": "v1", "version": "1"}]}
    api.get("/dna/intent/api/v1/template-programmer/template").respond(json=[tpl])
    mock_device_lookup(api)
    api.put("/dna/intent/api/v1/template-programmer/template/preview").respond(json={"cliPreview": "x"})
    api.post("/dna/intent/api/v2/template-programmer/template/deploy").respond(202, json={"response": {}})
    preview, _ = await flow(
        "catc_deploy_template",
        {"template": TID, "devices": ["edge-sw1"], "params": {"enable_password": "Sup3r", "vlan": 5}},
    )
    assert "Sup3r" not in json.dumps(preview) and preview["preview"]["params"]["vlan"] == 5


async def test_activate_refused_if_image_resolution_changes(api: respx.MockRouter) -> None:
    mock_device_lookup(api)
    a = {"id": "dddddddd-1111-2222-3333-444444444444", "name": "img.bin", "version": "17.12.4"}
    b = {**a, "id": "eeeeeeee-1111-2222-3333-444444444444"}
    api.get("/dna/intent/api/v1/images").mock(
        side_effect=[httpx.Response(200, json={"response": [a]}), httpx.Response(200, json={"response": [b]})]
    )
    post = api.post(f"/dna/intent/api/v1/networkDeviceImages/{DEV_ID}/activate")
    import pytest
    from fastmcp.exceptions import ToolError

    with pytest.raises(ToolError, match="changed since the preview"):
        await flow("catc_activate_image", {"device": "edge-sw1", "image": "img.bin"})
    assert post.call_count == 0


async def test_delete_provisioned_device_uses_provisioning_api(api: respx.MockRouter) -> None:
    mock_device_lookup(api)
    api.get("/dna/intent/api/v1/sda/provisionDevices").respond(
        json={"response": [{"id": "prov-1", "networkDeviceId": DEV_ID, "siteId": "s"}]}
    )
    route = api.delete("/dna/intent/api/v1/sda/provisionDevices/prov-1").respond(
        202, json={"response": {"taskId": "tdp"}}
    )
    task_ok(api, "tdp")
    preview, done = await flow("catc_delete_device", {"device": "edge-sw1"})
    assert preview["preview"]["provisioned"] is True and preview["action"].startswith(
        "Un-provision and delete"
    )
    assert done["status"] == "applied" and route.calls.last.request.url.params["cleanUpConfig"] == "false"
