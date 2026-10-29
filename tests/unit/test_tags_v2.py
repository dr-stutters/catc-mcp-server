"""D59: tags v2 (respx). Payloads follow the bundled 3.2.2 spec: POST tags/{interfaces|networkDevices}/
membersAssociations/query returns [{id, tags: [{id, name}]}] (members without tags left out, as a 3.2.2 read
of the GET listing shows: an empty list when nothing is tagged); PUT .../membersAssociations/bulk takes
[{id, tags: [{id}]}] and answers {taskId, url}; GET tag/member/type returned ["networkdevice", "interface"]
on a 3.2.2 appliance."""

import json
from typing import Any

import httpx
import pytest
import respx
from fastmcp.exceptions import ToolError

from catc_mcp.tools.tags import before_after, membership_change

from .test_read_tools import DEV_ID, DEVICE
from .test_safety import DEV2, mock_inventory
from .test_write_tools import preview_then_apply, task_ok

V2 = "/dna/intent/api/v1/tags"
TAG = {"id": "aaaaaaaa-1111-2222-3333-444444444444", "name": "mcp-uplinks", "systemTag": False}
OTHER = {"id": "bbbbbbbb-1111-2222-3333-444444444444", "name": "mcp-other"}
PORTS = [
    {"id": "p1", "instanceUuid": "p1", "deviceId": DEV_ID, "portName": "GigabitEthernet1/0/1"},
    {"id": "p2", "instanceUuid": "p2", "deviceId": DEV_ID, "portName": "GigabitEthernet1/0/2"},
    {"id": "p3", "instanceUuid": "p3", "deviceId": DEV_ID, "portName": "GigabitEthernet1/0/3"},
]


def mock_tag(api: respx.MockRouter, tag: dict[str, Any] = TAG) -> None:
    api.get("/dna/intent/api/v1/tag").respond(json={"response": [tag]})
    api.get("/dna/intent/api/v1/tag/member/type").respond(
        json={"response": ["networkdevice", "interface"], "version": "1.0"}
    )


def mock_query(api: respx.MockRouter, kind: str, assoc: dict[str, list[dict[str, Any]]]) -> respx.Route:
    def handler(request: httpx.Request) -> httpx.Response:
        ids = json.loads(request.content)["ids"]
        rows = [{"id": i, "tags": assoc[i]} for i in ids if assoc.get(i)]
        return httpx.Response(200, json={"response": rows, "version": "1.0"})

    return api.post(f"{V2}/{kind}/membersAssociations/query").mock(side_effect=handler)


def mock_bulk(api: respx.MockRouter, kind: str, task: str = "tb") -> respx.Route:
    route = api.put(f"{V2}/{kind}/membersAssociations/bulk").respond(
        202, json={"response": {"taskId": task, "url": f"/api/v1/task/{task}"}, "version": "1.0"}
    )
    task_ok(api, task)
    return route


def test_membership_change_keeps_other_tags() -> None:
    current = {
        "a": [{"id": OTHER["id"], "name": OTHER["name"]}],
        "b": [{"id": TAG["id"], "name": TAG["name"]}],
    }
    body, unchanged = membership_change(current, TAG, "add")
    assert body == [{"id": "a", "tags": [{"id": OTHER["id"]}, {"id": TAG["id"]}]}] and unchanged == ["b"]
    body, unchanged = membership_change(current, TAG, "remove")
    assert body == [{"id": "b", "tags": []}] and unchanged == ["a"]
    assert before_after(current["a"], TAG, "add") == {
        "before": ["mcp-other"],
        "after": ["mcp-other", "mcp-uplinks"],
    }


async def test_tag_interfaces_preview_then_apply(api: respx.MockRouter) -> None:
    mock_tag(api)
    mock_inventory(api, [DEVICE])
    api.get(f"/dna/intent/api/v1/interface/network-device/{DEV_ID}").respond(json={"response": PORTS})
    mock_query(api, "interfaces", {"p1": [{"id": OTHER["id"], "name": OTHER["name"]}]})
    bulk = mock_bulk(api, "interfaces")
    preview, done = await preview_then_apply(
        "catc_tag_interfaces",
        {"tag": "mcp-uplinks", "device": "edge-sw1", "interfaces": ["Gi1/0/1", "GigabitEthernet1/0/2"]},
    )
    assert preview["status"] == "preview" and bulk.call_count == 1  # only the apply sent the PUT
    rows = {r["name"]: r for r in preview["preview"]["interfaces"]}
    assert rows["GigabitEthernet1/0/1"]["before"] == ["mcp-other"]
    assert rows["GigabitEthernet1/0/1"]["after"] == ["mcp-other", "mcp-uplinks"]
    assert rows["GigabitEthernet1/0/2"]["after"] == ["mcp-uplinks"]
    assert json.loads(bulk.calls.last.request.content) == [
        {"id": "p1", "tags": [{"id": OTHER["id"]}, {"id": TAG["id"]}]},
        {"id": "p2", "tags": [{"id": TAG["id"]}]},
    ]
    assert done is not None
    assert done["result"]["tagged"] == ["GigabitEthernet1/0/1", "GigabitEthernet1/0/2"]


async def test_untag_interfaces_and_noop(api: respx.MockRouter) -> None:
    mock_tag(api)
    mock_inventory(api, [DEVICE])
    api.get(f"/dna/intent/api/v1/interface/network-device/{DEV_ID}").respond(json={"response": PORTS})
    mock_query(api, "interfaces", {"p3": [{"id": TAG["id"], "name": TAG["name"]}]})
    bulk = mock_bulk(api, "interfaces")
    args = {
        "tag": "mcp-uplinks",
        "device": "edge-sw1",
        "interfaces": ["Gi1/0/3", "Gi1/0/2"],
        "action": "remove",
    }
    preview, done = await preview_then_apply("catc_tag_interfaces", args)
    assert preview["preview"]["unchanged"] == ["GigabitEthernet1/0/2"]
    assert json.loads(bulk.calls.last.request.content) == [{"id": "p3", "tags": []}]
    assert done is not None and done["result"]["untagged"] == ["GigabitEthernet1/0/3"]
    preview, _ = await preview_then_apply("catc_tag_interfaces", {**args, "interfaces": ["Gi1/0/2"]})
    assert preview["status"] == "no_change" and bulk.call_count == 1


async def test_tag_interfaces_refuses_dynamic_tag_and_unknown_port(api: respx.MockRouter) -> None:
    mock_tag(api, {**TAG, "dynamicRules": [{"memberType": "interface", "rules": {}}]})
    mock_inventory(api, [DEVICE])
    api.get(f"/dna/intent/api/v1/interface/network-device/{DEV_ID}").respond(json={"response": PORTS})
    mock_query(api, "interfaces", {})
    args = {"tag": "mcp-uplinks", "device": "edge-sw1", "interfaces": ["Gi1/0/1"]}
    preview, _ = await preview_then_apply("catc_tag_interfaces", args)
    assert preview["status"] == "blocked" and "dynamic tag" in preview["blockers"][0]
    with pytest.raises(ToolError, match="No interface"):
        await preview_then_apply("catc_tag_interfaces", {**args, "interfaces": ["Gi9/9/9"]})


async def test_tag_interfaces_member_type_check(api: respx.MockRouter) -> None:
    mock_tag(api)
    api.get("/dna/intent/api/v1/tag/member/type").respond(json={"response": ["networkdevice"]})
    mock_inventory(api, [DEVICE])
    api.get(f"/dna/intent/api/v1/interface/network-device/{DEV_ID}").respond(json={"response": PORTS})
    mock_query(api, "interfaces", {})
    preview, _ = await preview_then_apply(
        "catc_tag_interfaces", {"tag": "mcp-uplinks", "device": "edge-sw1", "interfaces": ["Gi1/0/1"]}
    )
    assert preview["status"] == "blocked" and "'interface'" in preview["blockers"][0]


async def test_tag_devices_bulk(api: respx.MockRouter) -> None:
    mock_tag(api)
    mock_inventory(api)
    mock_query(api, "networkDevices", {DEV2["id"]: [{"id": TAG["id"], "name": TAG["name"]}]})
    bulk = mock_bulk(api, "networkDevices")
    preview, done = await preview_then_apply(
        "catc_tag_devices", {"tag": "mcp-uplinks", "devices": ["edge-sw1", "10.0.0.12"]}
    )
    assert preview["status"] == "preview" and preview["blast_radius"] == 1
    assert preview["preview"]["unchanged"] == ["edge-sw2 (10.0.0.12)"]
    assert json.loads(bulk.calls.last.request.content) == [{"id": DEV_ID, "tags": [{"id": TAG["id"]}]}]
    assert done is not None and done["result"]["tagged"] == ["edge-sw1.lab.local (10.0.0.11)"]
    assert done["undo"]["tool"] == "catc_tag_devices" and done["undo"]["args"]["action"] == "remove"


async def test_tag_devices_refuses_system_tag_and_duplicates(api: respx.MockRouter) -> None:
    mock_tag(api, {**TAG, "systemTag": True})
    mock_inventory(api)
    mock_query(api, "networkDevices", {})
    preview, _ = await preview_then_apply("catc_tag_devices", {"tag": "mcp-uplinks", "devices": ["edge-sw1"]})
    assert preview["status"] == "blocked" and "system tag" in preview["blockers"][0]
    with pytest.raises(ToolError, match="listed twice"):
        await preview_then_apply(
            "catc_tag_devices", {"tag": "mcp-uplinks", "devices": ["edge-sw1", "EDGE-SW1"]}
        )
