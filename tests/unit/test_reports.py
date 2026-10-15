"""D16: reports and ITSM reads (respx)."""

import json
from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client
from fastmcp.exceptions import ToolError

from catc_mcp.server import create_server

from .conftest import make_settings
from .test_write_tools import run

DATA = "/dna/intent/api/v1/data"
GID, VID, RID = "g1", "v1", "r1"
VIEW = {
    "viewId": VID,
    "viewName": "All Data",
    "formats": [{"format": "PDF"}, {"format": "CSV"}],
    "filters": [{"name": "DeviceFamily", "displayName": "Device Family", "type": "MULTI_SELECT"}],
    "fieldGroups": [
        {
            "fieldGroupName": "inv",
            "fieldGroupDisplayName": "All",
            "fields": [{"name": "hostname", "displayName": "Name"}],
        }
    ],
}


def mock_views(api: respx.MockRouter) -> None:
    api.get(f"{DATA}/view-groups").respond(
        json=[{"viewGroupId": GID, "name": "Inventory", "category": "Inventory"}]
    )
    api.get(f"{DATA}/view-groups/{GID}").respond(
        json={"viewGroupId": GID, "views": [{"viewId": VID, "viewName": "All Data"}]}
    )
    api.get(f"{DATA}/view-groups/{GID}/views/{VID}").respond(json=VIEW)


async def call(name: str, args: dict[str, Any], **settings: Any) -> Any:
    async with Client(create_server(make_settings(**settings))) as c:
        return await run(c, name, args)


async def test_view_reads(api: respx.MockRouter) -> None:
    mock_views(api)
    out = await call("catc_get_report_view", {"group": "inventory", "view": "all data"})
    assert out["formats"] == ["PDF", "CSV"] and out["filters"][0]["name"] == "DeviceFamily"
    out = await call("catc_list_report_views", {"group": "Inventory"})
    assert out["results"][0]["viewName"] == "All Data"


async def test_create_report_retries_view_group_version(api: respx.MockRouter) -> None:
    mock_views(api)
    api.get(f"{DATA}/reports").respond(404, json={"message": "none"})
    post = api.post(f"{DATA}/reports").mock(
        side_effect=[
            httpx.Response(500, json={"message": "ViewGroup does not exist with id, g1 and version, 2.0.0"}),
            httpx.Response(200, json={"reportId": RID, "name": "inv"}),
        ]
    )
    args = {"name": "inv", "group": "Inventory", "view": "All Data", "filters": {"DeviceFamily": ["Routers"]}}
    async with Client(create_server(make_settings(mcp_enable_writes=True))) as c:
        preview = await run(c, "catc_create_report", args)
        done = await run(c, "catc_create_report", {**args, "confirm": preview["confirm"]})
    assert done["result"]["report_id"] == RID and post.call_count == 2
    sent = json.loads(post.calls.last.request.content)
    assert (
        sent["viewGroupVersion"] == "1.0.0" and sent["view"]["filters"][0]["value"][0]["value"] == "Routers"
    )
    assert sent["view"]["fieldGroups"][0]["fields"][0]["name"] == "hostname"


async def test_create_report_blockers(api: respx.MockRouter) -> None:
    mock_views(api)
    api.get(f"{DATA}/reports").respond(json=[{"reportId": RID, "name": "inv"}])
    out = await call(
        "catc_create_report",
        {
            "name": "inv",
            "group": "Inventory",
            "view": "All Data",
            "format": "JSON",
            "filters": {"Nope": ["x"]},
        },
        mcp_enable_writes=True,
    )
    text = " ".join(out["blockers"])
    assert "not JSON" in text and "Unknown filter" in text and "exists already" in text


async def test_report_content(api: respx.MockRouter) -> None:
    report = {"reportId": RID, "name": "inv", "view": {"name": "All Data", "format": {"formatType": "CSV"}}}
    api.get(f"{DATA}/reports").respond(json=[report])
    api.get(f"{DATA}/reports/{RID}/executions").respond(
        json={"executions": [{"executionId": "e1", "processStatus": "SUCCESS", "startTime": 5}]}
    )
    dl = api.get(f"{DATA}/reports/{RID}/executions/e1").respond(
        content=("hostname\nr1\n" + "x" * 2000).encode()
    )
    out = await call("catc_get_report_content", {"report": "inv", "max_chars": 500})
    assert out["content"].startswith("hostname\nr1") and "Cut at 500" in out["note"]
    assert dl.calls.last.request.headers["Accept"] == "application/octet-stream"


async def test_report_content_refuses_pdf(api: respx.MockRouter) -> None:
    api.get(f"{DATA}/reports").respond(
        json=[{"reportId": RID, "name": "inv", "view": {"format": {"formatType": "PDF"}}}]
    )
    with pytest.raises(ToolError, match="only CSV and JSON"):
        await call("catc_get_report_content", {"report": "inv"})


async def test_itsm_empty(api: respx.MockRouter) -> None:
    api.get("/dna/intent/api/v1/integration-settings/itsm/instances").respond(
        json={"page": 1, "data": [], "totalRecords": 0}
    )
    out = await call("catc_list_itsm_instances", {})
    assert out["results"] == [] and "No ITSM" in out["note"]
