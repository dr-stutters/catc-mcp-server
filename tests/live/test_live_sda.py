"""Live SD-Access flow (D13) on two switches discovered and provisioned at CATC_LIVE_FABRIC_BUILDING:
CATC_LIVE_FABRIC_BORDER (border + control plane) and CATC_LIVE_FABRIC_EDGE (edge; a client port
CATC_LIVE_FABRIC_PORT, default GigabitEthernet1/0/3), with the IP pool CATC_LIVE_FABRIC_POOL reserved at
the building (docs/live-tests.md). Then:
fabric site -> border CP+border -> edge -> VN -> anycast gateway -> port assignment -> edge CLI check, and
everything removed again in reverse order.

When the SD-Access application isn't running (seen on a 3.2.2 lab image), Catalyst Center refuses fabric
sites with NCSP11008 and virtual networks with NCSP11000. The test then skips (the previews were still
checked).
"""

from __future__ import annotations

import contextlib
from typing import Any

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError

from .conftest import live_env, need, require_reachable
from .test_live_writes import RUN, apply, call

pytestmark = pytest.mark.live

BLDG = live_env("CATC_LIVE_FABRIC_BUILDING")
BCP, EDGE = live_env("CATC_LIVE_FABRIC_BORDER"), live_env("CATC_LIVE_FABRIC_EDGE")
POOL, VN = live_env("CATC_LIVE_FABRIC_POOL"), f"MCP_VN_{RUN[:4]}"
PORT = live_env("CATC_LIVE_FABRIC_PORT", "GigabitEthernet1/0/3")


async def test_sda_fabric_flow(lab_rw: Client[Any]) -> None:
    need(
        "CATC_LIVE_FABRIC_BUILDING",
        "CATC_LIVE_FABRIC_BORDER",
        "CATC_LIVE_FABRIC_EDGE",
        "CATC_LIVE_FABRIC_POOL",
    )
    require_reachable(EDGE, "CATC_LIVE_FABRIC_EDGE")
    for ip in (BCP, EDGE):
        try:
            await call(lab_rw, "catc_get_device", {"device": ip})
        except ToolError:
            pytest.skip(f"{ip} is not in the inventory (discover and provision the fabric switches)")
    # Previews against real objects
    out = await call(lab_rw, "catc_create_fabric_site", {"site": f"{BLDG}"})
    if out["status"] == "blocked":
        pytest.skip(f"fabric site exists already: {out['blockers']}")
    assert out["preview"]["body"][0]["authenticationProfileName"] == "No Authentication"
    with pytest.raises(ToolError, match="not a fabric site"):
        await call(
            lab_rw, "catc_add_fabric_device", {"device": EDGE, "fabric_site": BLDG, "roles": ["EDGE_NODE"]}
        )

    try:
        await apply(lab_rw, "catc_create_fabric_site", {"site": BLDG})
    except ToolError as e:
        if "SD-Access application" in str(e):
            pytest.skip(f"SD-Access not available on this Catalyst Center: {str(e)[:200]}")
        raise
    created: list[tuple[str, dict[str, Any]]] = []
    try:
        await apply(
            lab_rw,
            "catc_add_fabric_device",
            {
                "device": BCP,
                "fabric_site": BLDG,
                "roles": ["CONTROL_PLANE_NODE", "BORDER_NODE"],
                "border_asn": "65001",
            },
        )
        await apply(
            lab_rw, "catc_add_fabric_device", {"device": EDGE, "fabric_site": BLDG, "roles": ["EDGE_NODE"]}
        )
        await apply(lab_rw, "catc_create_virtual_network", {"name": VN, "fabric_sites": [BLDG]})
        created.append(("virtual_network", {"name": VN}))
        gw = await apply(
            lab_rw, "catc_add_anycast_gateway", {"fabric_site": BLDG, "virtual_network": VN, "ip_pool": POOL}
        )
        created.append(("anycast_gateway", {"id": gw["gateway"]["id"]}))
        await apply(
            lab_rw,
            "catc_assign_fabric_port",
            {"device": EDGE, "interface": PORT, "data_vlan": POOL},
        )
        fabric = await call(lab_rw, "catc_get_sda_fabric", {"site": BLDG})
        assert fabric
        cli = await call(
            lab_rw,
            "catc_run_show_commands",
            {"devices": [EDGE], "commands": [f"show run interface {PORT}"]},
        )
        assert "access vlan" in str(cli)
    finally:
        # Reverse order: ports -> gateways -> VN -> fabric devices -> fabric site.
        with contextlib.suppress(Exception):
            fabric = await call(lab_rw, "catc_get_sda_fabric", {"site": BLDG})
            entry = fabric["fabric_sites"][0]
            for p in entry.get("port_assignments", []):
                with contextlib.suppress(Exception):
                    await apply(lab_rw, "catc_delete_sda_object", {"kind": "port_assignment", "id": p["id"]})
            for kind, args in reversed(created):
                with contextlib.suppress(Exception):
                    await apply(lab_rw, "catc_delete_sda_object", {"kind": kind, **args})
            edges_first = sorted(entry.get("devices", []), key=lambda d: "EDGE_NODE" not in d["roles"])
            for d in edges_first:
                with contextlib.suppress(Exception):
                    await apply(lab_rw, "catc_delete_sda_object", {"kind": "fabric_device", "id": d["id"]})
            await apply(lab_rw, "catc_delete_sda_object", {"kind": "fabric_site", "id": entry["id"]})
