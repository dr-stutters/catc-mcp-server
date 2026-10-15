"""D3: network profiles, template attach/detach and site assignment."""

import json
from typing import Any

import pytest
import respx

from .test_read_tools import call
from .test_write_tools import preview_then_apply as write_apply

TP = "/dna/intent/api/v1/template-programmer/template"
NP = "/dna/intent/api/v1/networkProfilesForSites"
PID = "aaaaaaaa-1111-2222-3333-444444444444"
PID2 = "aaaaaaaa-1111-2222-3333-555555555555"
TID = "bbbbbbbb-1111-2222-3333-444444444444"
SITE = {"id": "cccccccc-1111-2222-3333-444444444444", "nameHierarchy": "Global/AU", "name": "AU"}
PROFILES = [
    {"id": PID, "name": "mcp-sw", "type": "Switching"},
    {"id": PID2, "name": "mcp-sw2", "type": "Switching"},
]
TEMPLATE = {"templateId": TID, "name": "banner", "projectName": "proj", "versionsInfo": [{"version": "1"}]}


def base(api: respx.MockRouter) -> None:
    api.get(NP).respond(json={"response": PROFILES})
    api.get(TP).respond(json=[TEMPLATE])
    api.get("/dna/intent/api/v1/sites").respond(json={"response": [SITE]})
    api.get("/dna/intent/api/v1/task/t1").respond(
        json={"response": {"id": "t1", "endTime": 1, "isError": False, "progress": "ok"}}
    )


async def apply(name: str, args: dict[str, Any]) -> Any:
    preview, done = await write_apply(name, args)
    assert preview["status"] == "preview", preview
    return preview, done


async def test_get_network_profile(api: respx.MockRouter) -> None:
    base(api)
    api.get(f"{NP}/{PID}/templates").respond(json={"response": [{"id": TID, "name": "banner"}]})
    api.get(f"{NP}/{PID}/siteAssignments").respond(json={"response": [{"id": SITE["id"]}]})
    out = await call("catc_get_network_profile", {"profile": "MCP-SW"})
    assert out["templates"] == [{"name": "banner", "id": TID}] and out["sites"] == ["Global/AU"]


async def test_attach_skips_existing_and_posts_bulk(api: respx.MockRouter) -> None:
    base(api)
    attached: list[dict[str, str]] = [{"id": PID, "name": "mcp-sw"}]
    api.get(f"/dna/intent/api/v1/templates/{TID}/networkProfilesForSites").mock(
        side_effect=lambda r: respx.MockResponse(json={"response": attached})
    )

    def post(request: Any) -> Any:
        attached.append({"id": PID2, "name": "mcp-sw2"})
        return respx.MockResponse(202, json={"response": {"taskId": "t1"}})

    route = api.post(f"/dna/intent/api/v1/templates/{TID}/networkProfilesForSites/bulk").mock(
        side_effect=post
    )
    preview, done = await apply(
        "catc_attach_template_to_profile", {"template": "proj/banner", "profiles": ["mcp-sw", "mcp-sw2"]}
    )
    assert preview["preview"]["unchanged"] == ["mcp-sw"]
    assert json.loads(route.calls.last.request.content) == {"items": [{"profileId": PID2}]}
    assert done["result"]["attached_to"] == ["mcp-sw", "mcp-sw2"]


async def test_attach_nothing_to_do_is_blocked(api: respx.MockRouter) -> None:
    base(api)
    api.get(f"/dna/intent/api/v1/templates/{TID}/networkProfilesForSites").respond(
        json={"response": [{"id": PID, "name": "mcp-sw"}]}
    )
    out = await call(
        "catc_attach_template_to_profile",
        {"template": "proj/banner", "profiles": ["mcp-sw"]},
        mcp_enable_writes=True,
    )
    assert out["status"] == "blocked" and "already attached" in out["blockers"][0]


async def test_detach_deletes_each(api: respx.MockRouter) -> None:
    base(api)
    attached = [{"id": PID, "name": "mcp-sw"}]
    api.get(f"/dna/intent/api/v1/templates/{TID}/networkProfilesForSites").mock(
        side_effect=lambda r: respx.MockResponse(json={"response": attached})
    )

    def delete(request: Any) -> Any:
        attached.clear()
        return respx.MockResponse(202, json={"response": {"taskId": "t1"}})

    route = api.delete(f"/dna/intent/api/v1/templates/{TID}/networkProfilesForSites/{PID}").mock(
        side_effect=delete
    )
    _, done = await apply("catc_detach_template_from_profile", {"template": TID, "profiles": [PID]})
    assert route.called and done["result"]["attached_to"] == []


async def test_assign_profile_to_sites(api: respx.MockRouter) -> None:
    base(api)
    assigned: list[dict[str, str]] = []
    api.get(f"{NP}/{PID}/siteAssignments").mock(
        side_effect=lambda r: respx.MockResponse(json={"response": assigned})
    )

    def post(request: Any) -> Any:
        assigned.append({"id": SITE["id"]})
        return respx.MockResponse(202, json={"response": {"taskId": "t1"}})

    route = api.post(f"{NP}/{PID}/siteAssignments/bulk").mock(side_effect=post)
    preview, done = await apply("catc_assign_profile_to_sites", {"profile": "mcp-sw", "sites": ["Global/AU"]})
    assert preview["preview"]["sites"] == ["Global/AU"]
    assert json.loads(route.calls.last.request.content) == {"items": [{"id": SITE["id"]}]}
    assert done["result"]["sites"] == ["Global/AU"]
    again = await call(
        "catc_assign_profile_to_sites", {"profile": "mcp-sw", "sites": ["Global/AU"]}, mcp_enable_writes=True
    )
    assert again["status"] == "blocked"


async def test_create_switching_profile_refuses_duplicate(api: respx.MockRouter) -> None:
    base(api)
    out = await call("catc_create_switching_profile", {"name": "MCP-SW"}, mcp_enable_writes=True)
    assert out["status"] == "blocked"


async def test_create_switching_profile_falls_back_to_siteprofile(api: respx.MockRouter) -> None:
    profiles: list[dict[str, str]] = []
    api.get(NP).mock(side_effect=lambda r: respx.MockResponse(json={"response": profiles}))
    api.post("/dna/intent/api/v1/sda/switchNetworkProfiles").respond(404, json={"message": "no"})

    def internal(request: Any) -> Any:
        profiles.append({"id": PID, "name": "new-sw", "type": "Switching"})
        return respx.MockResponse(202, json={"response": {"taskId": "t1"}})

    route = api.post("/api/v1/siteprofile").mock(side_effect=internal)
    api.get("/dna/intent/api/v1/task/t1").respond(
        json={"response": {"id": "t1", "endTime": 1, "isError": False, "progress": "created"}}
    )
    _, done = await apply("catc_create_switching_profile", {"name": "new-sw"})
    assert json.loads(route.calls.last.request.content)["namespace"] == "switching"
    assert done["result"]["profile_id"] == PID and done["result"]["via"] == "/api/v1/siteprofile"


async def test_attach_token_refused_when_target_changes(api: respx.MockRouter) -> None:
    """The confirm token binds the resolved profile ids, not just the names."""
    from fastmcp import Client
    from fastmcp.exceptions import ToolError

    from catc_mcp.server import create_server

    from .conftest import make_settings

    base(api)
    api.get(f"/dna/intent/api/v1/templates/{TID}/networkProfilesForSites").respond(json={"response": []})
    profiles = list(PROFILES)
    api.get(NP).mock(side_effect=lambda r: respx.MockResponse(json={"response": profiles}))
    args = {"template": "proj/banner", "profiles": ["mcp-sw"]}
    async with Client(create_server(make_settings(mcp_enable_writes=True))) as c:
        preview = (await c.call_tool("catc_attach_template_to_profile", args)).structured_content
        profiles[0] = {"id": "dddddddd-1111-2222-3333-444444444444", "name": "mcp-sw", "type": "Switching"}
        with pytest.raises(ToolError):
            await c.call_tool("catc_attach_template_to_profile", {**args, "confirm": preview["confirm"]})


async def test_unassign_partial_failure_reports_progress(api: respx.MockRouter) -> None:
    base(api)
    site2 = {"id": "cccccccc-1111-2222-3333-555555555555", "nameHierarchy": "Global/NZ", "name": "NZ"}
    api.get("/dna/intent/api/v1/sites").mock(
        side_effect=lambda r: respx.MockResponse(
            json={
                "response": [
                    s for s in (SITE, site2) if s["nameHierarchy"] == r.url.params.get("nameHierarchy")
                ]
                or [SITE, site2]
            }
        )
    )
    api.get(f"{NP}/{PID}/siteAssignments").respond(
        json={"response": [{"id": SITE["id"]}, {"id": site2["id"]}]}
    )
    api.delete(f"{NP}/{PID}/siteAssignments/{SITE['id']}").respond(202, json={"response": {"taskId": "t1"}})
    api.delete(f"{NP}/{PID}/siteAssignments/{site2['id']}").respond(500, json={"message": "boom"})
    from fastmcp.exceptions import ToolError

    with pytest.raises(ToolError, match="Done: .*" + SITE["id"]):
        await apply(
            "catc_unassign_profile_from_sites", {"profile": "mcp-sw", "sites": ["Global/AU", "Global/NZ"]}
        )


async def test_create_switching_profile_no_fallback_on_500(api: respx.MockRouter) -> None:
    api.get(NP).respond(json={"response": []})
    api.post("/dna/intent/api/v1/sda/switchNetworkProfiles").respond(500, json={"message": "no"})
    internal = api.post("/api/v1/siteprofile")
    from fastmcp.exceptions import ToolError

    with pytest.raises(ToolError):
        await apply("catc_create_switching_profile", {"name": "x"})
    assert not internal.called
