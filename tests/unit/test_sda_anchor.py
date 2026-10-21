"""D105: anchored virtual networks (respx); payloads follow the 3.2.2 spec's PUT sda/layer3VirtualNetworks."""

import json
from typing import Any

import httpx
import pytest
import respx
from fastmcp.exceptions import ToolError

from .test_read_tools import AREA, BLDG, GLOBAL
from .test_sda import FABRIC, FID, flow
from .test_write_tools import mock_sites, task_ok

SDA = "/dna/intent/api/v1/sda"
BLDG2 = {
    **BLDG,
    "id": "aaaaaaaa-0000-0000-0000-000000000012",
    "nameHierarchy": "Global/AU/SYD-2",
    "name": "SYD-2",
}
FID2 = "eeeeeeee-1111-2222-3333-444444444444"
FABRIC2 = {"id": FID2, "siteId": BLDG2["id"], "authenticationProfileName": "No Authentication"}
TRANSIT = {"id": "t1", "name": "mcp-sda-transit", "type": "SDA_LISP_PUB_SUB_TRANSIT"}


class Lab:
    def __init__(self, api: respx.MockRouter, vn: dict[str, Any], transits: list[dict[str, Any]]) -> None:
        self.vn, self.puts = vn, []
        mock_sites(api, [GLOBAL, AREA, BLDG, BLDG2])
        for b in (BLDG, BLDG2):
            api.get(f"/dna/intent/api/v1/sites/{b['id']}").respond(json={"response": b})
        api.get(f"{SDA}/fabricSites").respond(json={"response": [FABRIC, FABRIC2]})
        api.get(f"{SDA}/fabricDevices").mock(
            side_effect=lambda r: httpx.Response(
                200, json={"response": [{"id": f"fd-{r.url.params.get('fabricId')}"}]}
            )
        )
        api.get(f"{SDA}/layer3VirtualNetworks").mock(
            side_effect=lambda r: httpx.Response(200, json={"response": [self.vn]})
        )
        api.get(f"{SDA}/transitNetworks").respond(json={"response": transits})
        api.put(f"{SDA}/layer3VirtualNetworks").mock(side_effect=self.put)
        task_ok(api, "ta")

    def put(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        self.puts.append(body)
        self.vn = body[0]
        return httpx.Response(202, json={"response": {"taskId": "ta"}})


async def test_anchor_and_extend(api: respx.MockRouter) -> None:
    lab = Lab(api, {"id": "vn1", "virtualNetworkName": "MCP_GUEST", "fabricIds": [FID]}, [TRANSIT])
    args = {
        "virtual_network": "MCP_GUEST",
        "anchor_site": "Global/AU/SYD-1",
        "fabric_sites": ["Global/AU/SYD-2"],
    }
    preview, done = await flow("catc_anchor_virtual_network", args)
    assert (
        preview["action"] == "Anchor MCP_GUEST at Global/AU/SYD-1 across 2 fabric site(s)"
        and preview["blast_radius"] == 2
    )
    assert done and lab.puts == [
        [
            {
                "id": "vn1",
                "virtualNetworkName": "MCP_GUEST",
                "fabricIds": sorted([FID, FID2]),
                "anchoredSiteId": FID,
            }
        ]
    ]
    assert done["result"]["virtual_network"]["anchoredSiteId"] == FID


async def test_remove_anchor(api: respx.MockRouter) -> None:
    lab = Lab(
        api,
        {"id": "vn1", "virtualNetworkName": "MCP_GUEST", "fabricIds": [FID, FID2], "anchoredSiteId": FID},
        [],
    )
    _, done = await flow(
        "catc_anchor_virtual_network", {"virtual_network": "MCP_GUEST", "remove_anchor": True}
    )
    assert (
        done and "anchoredSiteId" not in lab.puts[0][0] and lab.puts[0][0]["fabricIds"] == sorted([FID, FID2])
    )


@pytest.mark.parametrize(
    ("vn", "transits", "args", "needle"),
    [
        ({"fabricIds": [FID]}, [TRANSIT], {"anchor_site": FID}, "at least two fabric sites"),
        (
            {"fabricIds": [FID]},
            [{"type": "IP_BASED_TRANSIT"}],
            {"anchor_site": FID, "fabric_sites": [FID2]},
            "No SD-Access transit",
        ),
        (
            {"fabricIds": [FID, FID2], "anchoredSiteId": FID},
            [TRANSIT],
            {"anchor_site": FID},
            "already anchored",
        ),
        ({"fabricIds": [FID]}, [TRANSIT], {}, "Give anchor_site"),
        ({"fabricIds": [FID]}, [TRANSIT], {"remove_anchor": True}, "is not anchored"),
    ],
)
async def test_blockers(
    api: respx.MockRouter,
    vn: dict[str, Any],
    transits: list[dict[str, Any]],
    args: dict[str, Any],
    needle: str,
) -> None:
    lab = Lab(api, {"id": "vn1", "virtualNetworkName": "MCP_GUEST", **vn}, transits)
    out, _ = await flow("catc_anchor_virtual_network", {"virtual_network": "MCP_GUEST", **args})
    assert out["status"] == "blocked" and needle in " ".join(out["blockers"]) and not lab.puts


async def test_unknown_vn(api: respx.MockRouter) -> None:
    Lab(api, {"id": "vn1", "virtualNetworkName": "OTHER"}, [TRANSIT])
    with pytest.raises(ToolError, match="No layer 3 virtual network MCP_GUEST"):
        await flow("catc_anchor_virtual_network", {"virtual_network": "MCP_GUEST", "anchor_site": FID})
