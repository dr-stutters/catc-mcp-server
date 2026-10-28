"""D123 user-defined fields: catc_list_udfs, catc_set_udf, catc_set_device_udfs (respx, payloads shaped
like the 3.2.2 spec and a 3.2.2 lab read: GET user-defined-field -> {"response": [], "version": "1.0"},
GET networkDevices?views=USER_DEFINED_FIELDS -> rows with "userDefinedFields": {})."""

import json
from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client
from fastmcp.exceptions import ToolError

from catc_mcp.server import create_server

from .conftest import make_settings
from .test_read_tools import DEV_ID, call, mock_device_lookup

UDF = "/dna/intent/api/v1/network-device/user-defined-field"
UDF_ID = "6b3a1f0e-1111-2222-3333-444444444444"
DEV2_ID = "22222222-3333-4444-5555-666666666666"


def row(dev_id: str, host: str, udfs: dict[str, str]) -> dict[str, Any]:
    return {
        "id": dev_id,
        "managementAddress": "192.0.2.11",
        "hostname": host,
        "status": "MANAGED",
        "userDefinedFields": udfs,
    }


def mock_udfs(api: respx.MockRouter, udfs: list[dict[str, Any]]) -> None:
    api.get(UDF).respond(json={"response": udfs, "version": "1.0"})


def mock_inventory(api: respx.MockRouter, rows: list[dict[str, Any]]) -> respx.Route:
    return api.get("/dna/intent/api/v1/networkDevices").respond(json={"response": rows, "version": "1.0"})


def mock_device_udfs(api: respx.MockRouter, dev_id: str, udfs: dict[str, str]) -> respx.Route:
    return api.get(f"/dna/intent/api/v1/networkDevices/{dev_id}").respond(
        json={"response": row(dev_id, "edge-sw1.lab.local", udfs), "version": "1.0"}
    )


def task_ok(api: respx.MockRouter, task_id: str) -> None:
    api.get(f"/dna/intent/api/v1/task/{task_id}").respond(
        json={"response": {"progress": "done", "endTime": 1, "isError": False}}
    )


async def run(c: Client, name: str, args: dict[str, Any]) -> Any:  # type: ignore[type-arg]
    res = await c.call_tool(name, args)
    if res.structured_content is not None:
        return res.structured_content
    return json.loads("\n".join(getattr(x, "text", "") for x in res.content))


async def preview_then_apply(name: str, args: dict[str, Any], **settings: Any) -> tuple[Any, Any]:
    async with Client(create_server(make_settings(mcp_enable_writes=True, **settings))) as c:
        preview = await run(c, name, args)
        if preview.get("status") != "preview":
            return preview, None
        done = await run(c, name, {**args, "confirm": preview["confirm"]})
    return preview, done


ASSET = {"id": UDF_ID, "name": "mcp-asset-tag", "description": "Asset tag"}


async def test_list_udfs_empty_and_with_devices(api: respx.MockRouter) -> None:
    mock_udfs(api, [])
    out = await call("catc_list_udfs", {"response_format": "json"})
    assert out["results"] == [] and out["total"] == 0
    mock_udfs(api, [ASSET, {"id": "u2", "name": "owner", "description": ""}])
    inv = mock_inventory(
        api,
        [
            row(DEV_ID, "edge-sw1", {"mcp-asset-tag": "A-1"}),
            row(DEV2_ID, "edge-sw2", {"mcp-asset-tag": "A-2", "owner": "neteng"}),
        ],
    )
    out = await call("catc_list_udfs", {"devices": True, "response_format": "json"})
    counts = {r["name"]: r["device_count"] for r in out["results"]}
    assert counts == {"mcp-asset-tag": 2, "owner": 1} and out["devices_scanned"] == 2
    assert inv.calls.last.request.url.params["views"] == "USER_DEFINED_FIELDS"
    out = await call(
        "catc_list_udfs",
        {"name": "mcp-asset-tag", "devices": True, "value": "A-2", "response_format": "json"},
    )
    assert out["results"] == [{"device": "edge-sw2", "id": DEV2_ID, "value": "A-2"}]
    with pytest.raises(ToolError, match="No user-defined field 'nope'"):
        await call("catc_list_udfs", {"name": "nope"})
    with pytest.raises(ToolError, match="give name and devices=true"):
        await call("catc_list_udfs", {"value": "x"})


async def test_create_udf_preview_then_apply(api: respx.MockRouter) -> None:
    state: list[dict[str, Any]] = []
    api.get(UDF).mock(side_effect=lambda r: httpx.Response(200, json={"response": state, "version": "1.0"}))

    def create(request: httpx.Request) -> httpx.Response:
        state.append({"id": UDF_ID, **json.loads(request.content)})
        return httpx.Response(202, json={"response": {"taskId": "t1", "url": "/task/t1"}, "version": "1.0"})

    post = api.post(UDF).mock(side_effect=create)
    task_ok(api, "t1")
    preview, done = await preview_then_apply(
        "catc_set_udf", {"name": "mcp-asset-tag", "description": "Asset tag"}
    )
    assert preview["action"] == "Create user-defined field mcp-asset-tag" and post.call_count == 1
    assert json.loads(post.calls.last.request.content) == {
        "name": "mcp-asset-tag",
        "description": "Asset tag",
    }
    assert done["result"]["udf"] == ASSET and done["result"]["task"] == "t1"


async def test_update_udf_and_noop(api: respx.MockRouter) -> None:
    mock_udfs(api, [ASSET])
    put = api.put(f"{UDF}/{UDF_ID}").respond(202, json={"response": {"taskId": "t2"}})
    task_ok(api, "t2")
    preview, done = await preview_then_apply("catc_set_udf", {"name": "mcp-asset-tag", "description": "CMDB"})
    assert preview["preview"]["before"]["description"] == "Asset tag"
    assert json.loads(put.calls.last.request.content) == {"name": "mcp-asset-tag", "description": "CMDB"}
    assert done is not None
    same, _ = await preview_then_apply("catc_set_udf", {"name": "mcp-asset-tag", "description": "Asset tag"})
    assert same["status"] == "no_change"


async def test_delete_udf_in_use_needs_dangerous(api: respx.MockRouter) -> None:
    mock_udfs(api, [ASSET])
    mock_inventory(api, [row(DEV_ID, "edge-sw1", {"mcp-asset-tag": "A-1"})])
    delete = api.delete(f"{UDF}/{UDF_ID}").respond(202, json={"response": {"taskId": "t3"}})
    task_ok(api, "t3")
    preview, _ = await preview_then_apply("catc_set_udf", {"name": "mcp-asset-tag", "delete": True})
    assert preview["status"] == "blocked" and "MCP_ENABLE_DANGEROUS" in json.dumps(preview)
    assert delete.call_count == 0
    preview, done = await preview_then_apply(
        "catc_set_udf", {"name": "mcp-asset-tag", "delete": True}, mcp_enable_dangerous=True
    )
    assert preview["preview"]["devices_carrying"][0]["value"] == "A-1"
    assert delete.call_count == 1 and done["result"]["task"] == "t3"


async def test_delete_unused_udf_is_write_tier(api: respx.MockRouter) -> None:
    mock_udfs(api, [ASSET])
    mock_inventory(api, [row(DEV_ID, "edge-sw1", {})])
    delete = api.delete(f"{UDF}/{UDF_ID}").respond(202, json={"response": {"taskId": "t4"}})
    task_ok(api, "t4")
    preview, done = await preview_then_apply("catc_set_udf", {"name": UDF_ID, "delete": True})
    assert preview["status"] == "preview" and delete.call_count == 1 and done is not None


async def test_set_device_udfs_before_after(api: respx.MockRouter) -> None:
    mock_udfs(api, [ASSET, {"id": "u2", "name": "owner", "description": ""}])
    mock_device_lookup(api)
    values = {"owner": "old"}
    api.get(f"/dna/intent/api/v1/networkDevices/{DEV_ID}").mock(
        side_effect=lambda r: httpx.Response(
            200, json={"response": row(DEV_ID, "edge-sw1.lab.local", dict(values)), "version": "1.0"}
        )
    )

    def put_handler(request: httpx.Request) -> httpx.Response:
        for item in json.loads(request.content):
            values[item["name"]] = item["value"]
        return httpx.Response(202, json={"response": {"taskId": "t5"}})

    def del_handler(request: httpx.Request) -> httpx.Response:
        values.pop(request.url.params["name"], None)
        return httpx.Response(202, json={"response": {"taskId": "t6"}})

    path = f"/dna/intent/api/v1/network-device/{DEV_ID}/user-defined-field"
    put = api.put(path).mock(side_effect=put_handler)
    dele = api.delete(path).mock(side_effect=del_handler)
    task_ok(api, "t5")
    task_ok(api, "t6")
    rows = [
        {"device": "edge-sw1", "name": "mcp-asset-tag", "value": "A-1001"},
        {"device": "10.0.0.11", "name": "owner", "value": None},
    ]
    preview, done = await preview_then_apply("catc_set_device_udfs", {"rows": rows})
    change = preview["preview"]["changes"][0]
    assert change["before"] == {"owner": "old"} and change["after"] == {"mcp-asset-tag": "A-1001"}
    assert change["set"] == {"mcp-asset-tag": "A-1001"} and change["clear"] == ["owner"]
    assert json.loads(put.calls.last.request.content) == [{"name": "mcp-asset-tag", "value": "A-1001"}]
    assert dele.calls.last.request.url.params["name"] == "owner"
    assert done["result"]["done"][0]["after"] == {"mcp-asset-tag": "A-1001"}
    again, _ = await preview_then_apply("catc_set_device_udfs", {"rows": rows})
    assert again["status"] == "no_change"


async def test_set_device_udfs_refuses_undefined_field(api: respx.MockRouter) -> None:
    mock_udfs(api, [])
    mock_device_lookup(api)
    mock_device_udfs(api, DEV_ID, {})
    preview, _ = await preview_then_apply(
        "catc_set_device_udfs", {"rows": [{"device": "edge-sw1", "name": "rack", "value": "R1"}]}
    )
    assert preview["status"] == "blocked" and "catc_set_udf" in json.dumps(preview)


async def test_set_device_udfs_device_cap(api: respx.MockRouter) -> None:
    mock_udfs(api, [ASSET])

    def lookup(request: httpx.Request) -> httpx.Response:
        h = request.url.params.get("hostname", "")
        n = h.split("sw")[-1].split(".")[0]
        return httpx.Response(
            200, json={"response": [{"id": f"00000000-0000-0000-0000-{int(n):012d}", "hostname": h}]}
        )

    api.get("/dna/intent/api/v1/network-device").mock(side_effect=lookup)
    api.get(path__regex=r"^/dna/intent/api/v1/networkDevices/[0-9a-f-]+$").respond(
        json={"response": {"userDefinedFields": {}}, "version": "1.0"}
    )
    rows = [{"device": f"sw{i}", "name": "mcp-asset-tag", "value": str(i)} for i in range(1, 4)]
    preview, _ = await preview_then_apply("catc_set_device_udfs", {"rows": rows}, max_devices_per_change=2)
    assert preview["status"] == "blocked" and "CATC_MAX_DEVICES_PER_CHANGE" in json.dumps(preview)
