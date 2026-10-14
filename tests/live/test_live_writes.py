"""Live write tests: create, verify, update and remove mcp-test-* objects on the lab.

Cleanup of objects whose delete tool is in the dangerous tier (sites, discoveries) goes straight
through the API client so these tests only depend on the write tier."""

import contextlib
import json
import uuid
from collections.abc import AsyncIterator
from typing import Any

import pytest
from fastmcp import Client

from catc_mcp.client import CatcApp
from catc_mcp.config import Settings

pytestmark = pytest.mark.live

RUN = uuid.uuid4().hex[:6]


async def call(c: Client, name: str, args: dict[str, Any]) -> Any:  # type: ignore[type-arg]
    res = await c.call_tool(name, args)
    if res.structured_content is not None:
        return res.structured_content
    return json.loads("\n".join(getattr(x, "text", "") for x in res.content))


async def apply(c: Client, name: str, args: dict[str, Any]) -> Any:  # type: ignore[type-arg]
    preview = await call(c, name, args)
    assert preview["status"] == "preview", preview
    done = await call(c, name, {**args, "confirm": preview["confirm"]})
    assert done["status"] == "applied", done
    return done.get("result")


@pytest.fixture
async def raw(lab_rw_settings: Settings) -> AsyncIterator[CatcApp]:
    app = CatcApp(lab_rw_settings)
    yield app
    await app.aclose()


async def test_site_lifecycle(lab_rw: Client, raw: CatcApp) -> None:  # type: ignore[type-arg]
    area = f"mcp-test-area-{RUN}"
    created: list[tuple[str, str]] = []
    try:
        r = await apply(lab_rw, "catc_create_site", {"site_type": "area", "name": area})
        created.append(("/dna/intent/api/v1/areas/", r["site_id"]))
        dup = await call(lab_rw, "catc_create_site", {"site_type": "area", "name": area})
        assert dup["status"] == "blocked"
        bad = await call(
            lab_rw, "catc_create_site", {"site_type": "floor", "name": "f", "parent": f"Global/{area}"}
        )
        assert bad["status"] == "blocked"  # floors need a building
        r = await apply(
            lab_rw,
            "catc_create_site",
            {
                "site_type": "building",
                "name": "mcp-test-bldg",
                "parent": f"Global/{area}",
                "country": "Australia",
                "address": "1 George Street, Sydney NSW 2000",
            },
        )
        created.append(("/dna/intent/api/v2/buildings/", r["site_id"]))
        bpath = f"Global/{area}/mcp-test-bldg"
        r = await apply(
            lab_rw,
            "catc_create_site",
            {
                "site_type": "floor",
                "name": "mcp-test-floor",
                "parent": bpath,
                "floor_number": 2,
                "units": "meters",
            },
        )
        created.append(("/dna/intent/api/v2/floors/", r["site_id"]))
        site = await call(lab_rw, "catc_get_site", {"site": bpath})
        assert site["country"] == "Australia"
        assert [c["name"] for c in site["children"]] == ["mcp-test-floor"]

        upd = await call(lab_rw, "catc_update_site", {"site": bpath, "address": "2 George Street, Sydney"})
        assert upd["preview"]["changes"]["address"]["to"] == "2 George Street, Sydney"
        await apply(lab_rw, "catc_update_site", {"site": bpath, "address": "2 George Street, Sydney"})
        site = await call(lab_rw, "catc_get_site", {"site": bpath})
        assert site["address"] == "2 George Street, Sydney"
        await apply(lab_rw, "catc_update_site", {"site": f"{bpath}/mcp-test-floor", "rf_model": "Free Space"})

        tree = await call(
            lab_rw, "catc_get_site_hierarchy", {"root": f"Global/{area}", "response_format": "json"}
        )
        assert tree["count"] == 3
    finally:
        for prefix, sid in reversed(created):
            with contextlib.suppress(Exception):
                await raw.run_job("DELETE", prefix + sid)


async def test_tag_lifecycle(lab_rw: Client) -> None:  # type: ignore[type-arg]
    name = f"mcp-test-tag-{RUN}"
    r = await apply(lab_rw, "catc_create_tag", {"name": name, "description": "live test"})
    assert r["tag_id"]
    try:
        tags = await call(lab_rw, "catc_list_tags", {"name": name, "response_format": "json"})
        assert tags["results"][0]["name"] == name
        sys_tag = await call(lab_rw, "catc_delete_tag", {"tag": "WAN"})
        assert sys_tag["status"] == "blocked"
    finally:
        await apply(lab_rw, "catc_delete_tag", {"tag": name})
    tags = await call(lab_rw, "catc_list_tags", {"name": name, "response_format": "json"})
    assert tags["returned"] == 0


async def test_template_lifecycle(lab_rw: Client, raw: CatcApp) -> None:  # type: ignore[type-arg]
    proj = f"mcp-test-proj-{RUN}"
    r = await apply(lab_rw, "catc_create_template_project", {"name": proj})
    try:
        r = await apply(
            lab_rw,
            "catc_create_template",
            {
                "project": proj,
                "name": "mcp-test-tpl",
                "content": "hostname {{ hostname }}\nvlan {{ vlan_id }}\n name mcp-test",
            },
        )
        assert r["template_id"]
        tpl = f"{proj}/mcp-test-tpl"
        full = await call(lab_rw, "catc_get_template", {"template": tpl})
        assert {p["parameterName"] for p in full["templateParams"]} == {"hostname", "vlan_id"}
        prev = await call(
            lab_rw, "catc_preview_template", {"template": tpl, "params": {"hostname": "sw9", "vlan_id": 42}}
        )
        assert "hostname sw9" in prev["cliPreview"] and "vlan 42" in prev["cliPreview"]
        await apply(lab_rw, "catc_update_template", {"template": tpl, "content": "hostname {{ hostname }}\n"})
        await apply(lab_rw, "catc_commit_template", {"template": tpl, "comment": "mcp live test"})
        listed = await call(lab_rw, "catc_list_templates", {"project": proj, "response_format": "json"})
        assert listed["results"][0]["versions"] == 1
        await apply(lab_rw, "catc_delete_template", {"template": tpl})
    finally:
        await apply(lab_rw, "catc_delete_template_project", {"project": proj})
    projects = await call(lab_rw, "catc_list_template_projects", {"name": proj, "response_format": "json"})
    assert projects["returned"] == 0


async def test_discovery_create(lab_rw: Client, raw: CatcApp) -> None:  # type: ignore[type-arg]
    name = f"mcp-test-disc-{RUN}"
    args = {
        "name": name,
        "ip_ranges": ["192.0.2.10-192.0.2.11"],
        "cli_username": "mcp-test",
        "cli_password": "not-a-real-password",
        "snmp_ro_community": "not-a-real-community",
        "timeout_seconds": 1,
    }
    preview = await call(lab_rw, "catc_create_discovery", args)
    assert "not-a-real" not in json.dumps(preview)
    r = await call(lab_rw, "catc_create_discovery", {**args, "confirm": preview["confirm"]})
    disc_id = r["result"]["discovery_id"]
    try:
        assert disc_id
        found = await call(lab_rw, "catc_list_discoveries", {"name": name, "response_format": "json"})
        assert found["results"][0]["name"] == name
        assert "not-a-real" not in json.dumps(found)
    finally:
        await raw.run_job("DELETE", f"/dna/intent/api/v1/discovery/{disc_id}")


async def test_device_writes_refuse_unknown_devices(lab_rw: Client) -> None:  # type: ignore[type-arg]
    from fastmcp.exceptions import ToolError

    for tool, args in [
        ("catc_resync_devices", {"devices": ["mcp-test-none"]}),
        ("catc_run_compliance", {"devices": ["192.0.2.77"]}),
        ("catc_assign_devices_to_site", {"devices": ["mcp-test-none"], "site": "Global"}),
    ]:
        with pytest.raises(ToolError, match="No network device"):
            await lab_rw.call_tool(tool, args)
