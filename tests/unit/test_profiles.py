"""D3: network profiles, template attach/detach and site assignment."""

import json
from typing import Any

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
