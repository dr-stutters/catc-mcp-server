"""Read-only live tests. The lab inventory is empty, so device/client tools are checked for clean
'not found' / empty answers rather than content."""

import json
from typing import Any

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError

pytestmark = pytest.mark.live


async def call(c: Client, name: str, args: dict[str, Any] | None = None) -> Any:  # type: ignore[type-arg]
    res = await c.call_tool(name, args or {})
    if res.structured_content is not None:
        return res.structured_content
    text = "\n".join(getattr(x, "text", "") for x in res.content)
    try:
        return json.loads(text)
    except ValueError:
        return text


async def test_site_hierarchy(lab: Client) -> None:  # type: ignore[type-arg]
    out = await call(lab, "catc_get_site_hierarchy", {"response_format": "json"})
    assert any(s["nameHierarchy"] == "Global" for s in out["sites"])
    md = await call(lab, "catc_get_site_hierarchy")
    assert "Global" in md


async def test_get_site_and_settings(lab: Client) -> None:  # type: ignore[type-arg]
    site = await call(lab, "catc_get_site", {"site": "Global"})
    assert site["type"] == "global"
    settings = await call(lab, "catc_get_site_settings", {"site": "Global", "categories": ["dns", "ntp"]})
    assert settings["site"] == "Global"


async def test_list_devices_and_unknown_device(lab: Client) -> None:  # type: ignore[type-arg]
    out = await call(lab, "catc_list_devices", {"response_format": "json"})
    assert "results" in out
    with pytest.raises(ToolError, match="No network device"):
        await lab.call_tool("catc_get_device", {"device": "mcp-test-nonexistent"})
    with pytest.raises(ToolError, match="No network device"):
        await lab.call_tool("catc_device_360", {"device": "192.0.2.99"})


async def test_assurance(lab: Client) -> None:  # type: ignore[type-arg]
    health = await call(lab, "catc_get_network_health")
    assert "network_health" in health
    assert "client_health" in await call(lab, "catc_get_client_health")
    for tool, args in [
        ("catc_list_device_health", {}),
        ("catc_list_issues", {"hours": 72}),
        ("catc_list_events", {"device_family": "Switches and Hubs"}),
        ("catc_list_audit_logs", {"limit": 30}),
    ]:
        out = await call(lab, tool, {**args, "response_format": "json"})
        assert "results" in out, tool
    audit = await call(lab, "catc_list_audit_logs", {"limit": 30, "response_format": "json"})
    assert audit["returned"] >= 1  # our own logins are audited


async def test_client_unknown(lab: Client) -> None:  # type: ignore[type-arg]
    out = await call(lab, "catc_client_360", {"mac": "00:11:22:33:44:55"})
    assert out["mac"] == "00:11:22:33:44:55"


async def test_topology(lab: Client) -> None:  # type: ignore[type-arg]
    phys = await call(lab, "catc_get_physical_topology", {"response_format": "json"})
    assert "node_count" in phys
    l3 = await call(lab, "catc_get_l3_topology", {"protocol": "ospf", "response_format": "json"})
    assert "link_count" in l3
    assert "count" in await call(lab, "catc_get_vlan_topology")


async def test_compliance(lab: Client) -> None:  # type: ignore[type-arg]
    out = await call(lab, "catc_get_compliance_summary")
    assert "COMPLIANT" in out["counts"]


async def test_templates(lab: Client) -> None:  # type: ignore[type-arg]
    projects = await call(lab, "catc_list_template_projects", {"response_format": "json"})
    assert any(p["name"] == "Reference Templates" for p in projects["results"])
    tpls = await call(
        lab, "catc_list_templates", {"project": "Reference Templates", "response_format": "json"}
    )
    assert tpls["results"]
    first = tpls["results"][0]
    full = await call(lab, "catc_get_template", {"template": f"Reference Templates/{first['name']}"})
    assert full["name"] == first["name"]


async def test_images_discoveries_tags(lab: Client) -> None:  # type: ignore[type-arg]
    for tool in ("catc_list_images", "catc_list_discoveries", "catc_list_tags"):
        out = await call(lab, tool, {"response_format": "json"})
        assert "results" in out, tool
    tags = await call(lab, "catc_list_tags", {"response_format": "json"})
    assert any(t["name"] == "WAN" for t in tags["results"])
    members = await call(lab, "catc_list_tag_members", {"tag": "WAN", "response_format": "json"})
    assert "results" in members


async def test_path_trace_reports_failure(lab: Client) -> None:  # type: ignore[type-arg]
    out = await call(lab, "catc_path_trace", {"source_ip": "192.0.2.1", "dest_ip": "192.0.2.2"})
    assert out["status"] == "FAILED"
    assert "failureReason" in out


async def test_show_commands_guard(lab: Client) -> None:  # type: ignore[type-arg]
    with pytest.raises(ToolError, match="only 'show"):
        await lab.call_tool("catc_run_show_commands", {"devices": ["x"], "commands": ["conf t"]})


async def test_spec_tools(lab: Client) -> None:  # type: ignore[type-arg]
    hits = await call(lab, "catc_search_spec", {"query": "flow analysis"})
    assert any("flow-analysis" in h["name"] for h in hits["results"])
    d = await call(lab, "catc_get_definition", {"name": "POST /dna/intent/api/v1/flow-analysis"})
    assert d["operations"]
    raw = await call(lab, "catc_api_call", {"path": "/dna/intent/api/v1/site"})
    assert raw["response"][0]["name"] == "Global"
