"""Live SD-Access flow (D13) on CML lab `mcp-catc-fabric` (labs/mcp-catc-fabric.yaml): bcp 198.18.128.174
(border + control plane), edge1 .175, fusion DHCP 10.255.255.14, Alpine client on edge1 Gi1/0/3.

Needs bcp/edge1 discovered and provisioned at Global/mcp-test-lab/mcp-test-fabric with the IP pool
mcp-test-fab-clients (10.10.40.0/24, gateway .1) reserved there (see LAB-REBUILD.md / notes). Then:
fabric site -> bcp CP+border -> edge1 edge -> VN -> anycast gateway -> port assignment -> edge CLI check, and
everything removed again in reverse order.

On the lab 3.2.2 image the SD-Access application isn't running: Catalyst Center refuses fabric sites with
NCSP11008 and virtual networks with NCSP11000. The test then skips (the previews were still checked).
"""

from __future__ import annotations

import contextlib
from typing import Any

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError

from .conftest import require_reachable
from .test_live_writes import RUN, apply, call

pytestmark = pytest.mark.live

BLDG = "Global/mcp-test-lab/mcp-test-fabric"
BCP, EDGE = "198.18.128.174", "198.18.128.175"
POOL, VN = "mcp-test-fab-clients", f"MCP_VN_{RUN[:4]}"


async def test_sda_fabric_flow(lab_rw: Client[Any]) -> None:
    require_reachable(EDGE, "edge1 of CML lab mcp-catc-fabric")
    for ip in (BCP, EDGE):
        try:
            await call(lab_rw, "catc_get_device", {"device": ip})
        except ToolError:
            pytest.skip(f"{ip} is not in the inventory (discover and provision the mcp-catc-fabric switches)")
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
            {"device": EDGE, "interface": "GigabitEthernet1/0/3", "data_vlan": POOL},
        )
        fabric = await call(lab_rw, "catc_get_sda_fabric", {"site": BLDG})
        assert fabric
        cli = await call(
            lab_rw,
            "catc_run_show_commands",
            {"devices": [EDGE], "commands": ["show run interface GigabitEthernet1/0/3"]},
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
