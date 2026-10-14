"""Live dangerous-tier tests that the empty lab allows: deleting sites (recursive) and discoveries.
Template deploy, provisioning and SWIM need managed devices/images and are covered by unit tests."""

import uuid

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError

from .test_live_writes import apply, call

pytestmark = pytest.mark.live
RUN = uuid.uuid4().hex[:6]


async def test_delete_site_recursive(lab_rw: Client) -> None:  # type: ignore[type-arg]
    area = f"mcp-test-del-{RUN}"
    await apply(lab_rw, "catc_create_site", {"site_type": "area", "name": area})
    await apply(
        lab_rw,
        "catc_create_site",
        {
            "site_type": "building",
            "name": "b1",
            "parent": f"Global/{area}",
            "country": "Australia",
            "latitude": -33.86,
            "longitude": 151.2,
        },
    )
    blocked = await call(lab_rw, "catc_delete_site", {"site": f"Global/{area}"})
    assert blocked["status"] == "blocked"
    done = await apply(lab_rw, "catc_delete_site", {"site": f"Global/{area}", "recursive": True})
    assert done["deleted"] == [f"Global/{area}/b1", f"Global/{area}"]
    with pytest.raises(ToolError, match="No site"):
        await lab_rw.call_tool("catc_get_site", {"site": f"Global/{area}"})


async def test_delete_discovery(lab_rw: Client) -> None:  # type: ignore[type-arg]
    name = f"mcp-test-ddisc-{RUN}"
    await apply(
        lab_rw,
        "catc_create_discovery",
        {
            "name": name,
            "ip_ranges": ["192.0.2.20"],
            "discovery_type": "Single",
            "cli_username": "x",
            "cli_password": "y",
        },
    )
    await apply(lab_rw, "catc_delete_discovery", {"discovery": name})
    found = await call(lab_rw, "catc_list_discoveries", {"name": name, "response_format": "json"})
    assert found["returned"] == 0


async def test_deploy_refuses_unknown_device(lab_rw: Client) -> None:  # type: ignore[type-arg]
    with pytest.raises(ToolError, match="No network device"):
        await lab_rw.call_tool(
            "catc_deploy_template",
            {"template": "Reference Templates/AAA-Configuration", "devices": ["192.0.2.50"]},
        )
