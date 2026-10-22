"""D105: anchored virtual networks (respx); payloads follow the 3.2.2 spec's POST and PUT
sda/layer3VirtualNetworks."""

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
    """`apply` says what the appliance does with a POST or PUT: replace the record, merge it (fields left out
    stay), or apply the site assignment only (the anchor fails). `vn=None`: the VN doesn't exist yet."""

    def __init__(
        self,
        api: respx.MockRouter,
        vn: dict[str, Any] | None,
        transits: list[dict[str, Any]],
        apply: str = "replace",
    ) -> None:
        self.vn, self.sent, self.mode = vn, [], apply
        mock_sites(api, [GLOBAL, AREA, BLDG, BLDG2])
        for b in (BLDG, BLDG2):
            api.get(f"/dna/intent/api/v1/sites/{b['id']}").respond(json={"response": b})
        api.get(f"{SDA}/fabricSites").respond(json={"response": [FABRIC, FABRIC2]})
        api.get(f"{SDA}/fabricDevices").mock(side_effect=self.fabric_devices)
        api.get(f"{SDA}/layer3VirtualNetworks").mock(
            side_effect=lambda r: httpx.Response(200, json={"response": [self.vn] if self.vn else []})
        )
        api.get(f"{SDA}/transitNetworks").respond(json={"response": transits})
        api.post(f"{SDA}/layer3VirtualNetworks").mock(side_effect=self.post)
        api.put(f"{SDA}/layer3VirtualNetworks").mock(side_effect=self.put)
        task_ok(api, "ta")

    @staticmethod
    def fabric_devices(request: httpx.Request) -> httpx.Response:
        fid = request.url.params.get("fabricId")
        dev = {
            "id": f"fd-{fid}",
            "networkDeviceId": f"nd-{fid}",
            "fabricId": fid,
            "deviceRoles": ["EDGE_NODE"],
        }
        return httpx.Response(200, json={"response": [dev]})

    @property
    def puts(self) -> list[Any]:
        return [body for method, body in self.sent if method == "PUT"]

    def post(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        self.sent.append(("POST", body))
        made = {"id": "vn-new", **body[0]}
        if self.mode == "sites":
            made.pop("anchoredSiteId", None)
        self.vn = made
        return httpx.Response(202, json={"response": {"taskId": "ta"}})

    def put(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        self.sent.append(("PUT", body))
        assert self.vn is not None
        if self.mode == "replace":
            self.vn = body[0]
        elif self.mode == "merge":
            self.vn = {**self.vn, **body[0]}
        else:  # sites only
            self.vn = {**self.vn, "fabricIds": body[0]["fabricIds"]}
        return httpx.Response(202, json={"response": {"taskId": "ta"}})


ARGS = {"virtual_network": "MCP_GUEST", "anchor_site": "Global/AU/SYD-1", "fabric_sites": ["Global/AU/SYD-2"]}


async def test_create_anchored_and_extend(api: respx.MockRouter) -> None:
    """Live 2026-10-22 (#190): a POST creating the VN with one fabric site and anchoredSiteId worked, and a
    later PUT extended it to the second site (anchor_verified true)."""
    lab = Lab(api, None, [TRANSIT])
    preview, done = await flow("catc_anchor_virtual_network", ARGS)
    assert (
        preview["action"] == "Create MCP_GUEST anchored at Global/AU/SYD-1 across 2 fabric site(s)"
        and preview["blast_radius"] == 2
        and [r["method"] for r in preview["preview"]["requests"]] == ["POST", "PUT"]
    )
    # The POST names the anchor site alone (a request anchoring with more sites: NCHS20464); the PUT extends
    # it to the other sites with the new VN's id and the anchor kept.
    assert done and lab.sent == [
        ("POST", [{"virtualNetworkName": "MCP_GUEST", "fabricIds": [FID], "anchoredSiteId": FID}]),
        (
            "PUT",
            [
                {
                    "id": "vn-new",
                    "virtualNetworkName": "MCP_GUEST",
                    "fabricIds": sorted([FID, FID2]),
                    "anchoredSiteId": FID,
                }
            ],
        ),
    ]
    assert done["result"]["anchor_verified"] is True and done["result"]["anchored_at"] == FID
    assert done["result"]["virtual_network"]["fabricIds"] == sorted([FID, FID2])


async def test_existing_unanchored_vn_is_refused(api: respx.MockRouter) -> None:
    """Live 2026-10-22: anchoring the existing MCP_VN (gateways and multicast at the anchor site) failed task
    validation with 'Invalid Message Code NCSO20386'; 3.2.2 anchors a VN only when it creates it."""
    lab = Lab(api, {"id": "vn1", "virtualNetworkName": "MCP_GUEST", "fabricIds": [FID]}, [TRANSIT])
    out, _ = await flow("catc_anchor_virtual_network", ARGS)
    text = " ".join(out["blockers"])
    assert out["status"] == "blocked" and "NCSO20386" in text and "Anchor a new VN" in text and not lab.sent


async def test_existing_vn_on_other_sites_is_refused(api: respx.MockRouter) -> None:
    lab = Lab(api, {"id": "vn1", "virtualNetworkName": "MCP_GUEST", "fabricIds": [FID, FID2]}, [TRANSIT])
    out, _ = await flow("catc_anchor_virtual_network", {"virtual_network": "MCP_GUEST", "anchor_site": FID})
    assert out["status"] == "blocked" and "NCSO20386" in " ".join(out["blockers"]) and not lab.sent


async def test_anchor_does_not_move(api: respx.MockRouter) -> None:
    lab = Lab(
        api,
        {"id": "vn1", "virtualNetworkName": "MCP_GUEST", "fabricIds": [FID, FID2], "anchoredSiteId": FID2},
        [TRANSIT],
    )
    out, _ = await flow("catc_anchor_virtual_network", {"virtual_network": "MCP_GUEST", "anchor_site": FID})
    text = " ".join(out["blockers"])
    assert out["status"] == "blocked" and "is anchored at Global/AU/SYD-2" in text and "can't move" in text
    assert not lab.sent


ANCHORED = {"id": "vn1", "virtualNetworkName": "MCP_GUEST", "fabricIds": [FID, FID2], "anchoredSiteId": FID}


async def test_remove_anchor_read_back(api: respx.MockRouter) -> None:
    lab = Lab(api, dict(ANCHORED), [], apply="replace")
    _, done = await flow(
        "catc_anchor_virtual_network", {"virtual_network": "MCP_GUEST", "remove_anchor": True}
    )
    assert (
        done and "anchoredSiteId" not in lab.puts[0][0] and lab.puts[0][0]["fabricIds"] == sorted([FID, FID2])
    )
    assert done["result"]["anchor_verified"] is True and done["result"]["anchored_at"] is None


async def test_remove_anchor_not_cleared_is_reported(api: respx.MockRouter) -> None:
    Lab(api, dict(ANCHORED), [], apply="merge")  # an appliance that keeps fields left out of the PUT
    _, done = await flow(
        "catc_anchor_virtual_network", {"virtual_network": "MCP_GUEST", "remove_anchor": True}
    )
    assert done and done["result"]["anchor_verified"] is False and done["result"]["anchored_at"] == FID
    assert "did not clear the anchor" in done["result"]["warning"]


async def test_anchor_that_did_not_apply_is_reported(api: respx.MockRouter) -> None:
    """A VN that comes back unanchored after the POST is not extended: it would be an ordinary multi-site
    VN."""
    lab = Lab(api, None, [TRANSIT], apply="sites")
    _, done = await flow("catc_anchor_virtual_network", ARGS)
    assert done and [m for m, _ in lab.sent] == ["POST"]
    assert done["result"]["anchor_verified"] is False and done["result"]["anchored_at"] is None
    assert "anchoring did not apply, so it was not extended" in done["result"]["warning"]


async def test_extend_an_anchored_vn(api: respx.MockRouter) -> None:
    lab = Lab(api, {**ANCHORED, "fabricIds": [FID]}, [TRANSIT])
    preview, done = await flow("catc_anchor_virtual_network", ARGS)
    assert preview["action"] == "Extend MCP_GUEST, anchored at Global/AU/SYD-1, to 2 fabric site(s)"
    assert done and lab.sent == [
        (
            "PUT",
            [
                {
                    "id": "vn1",
                    "virtualNetworkName": "MCP_GUEST",
                    "fabricIds": sorted([FID, FID2]),
                    "anchoredSiteId": FID,
                }
            ],
        )
    ]
    assert done["result"]["anchor_verified"] is True


async def test_extending_an_anchored_vn_keeps_the_anchor(api: respx.MockRouter) -> None:
    """catc_create_virtual_network adds a site with a PUT: it must carry anchoredSiteId."""
    Lab(api, {**ANCHORED, "fabricIds": [FID]}, [TRANSIT])
    out, _ = await flow(
        "catc_create_virtual_network", {"name": "MCP_GUEST", "fabric_sites": ["Global/AU/SYD-2"]}
    )
    assert out["preview"]["body"][0]["anchoredSiteId"] == FID


@pytest.mark.parametrize(
    ("vn", "transits", "args", "needle"),
    [
        (None, [TRANSIT], {"anchor_site": FID}, "at least two fabric sites"),
        (
            None,
            [{"type": "IP_BASED_TRANSIT"}],
            {"anchor_site": FID, "fabric_sites": [FID2]},
            "No SD-Access transit",
        ),
        (
            None,
            [TRANSIT],
            {"virtual_network": "MCP_GUEST_TOO_LONG", "anchor_site": FID, "fabric_sites": [FID2]},
            "can't be a VN name",
        ),
        (None, [TRANSIT], {"fabric_sites": [FID2]}, "Give anchor_site"),
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
    vn: dict[str, Any] | None,
    transits: list[dict[str, Any]],
    args: dict[str, Any],
    needle: str,
) -> None:
    lab = Lab(api, None if vn is None else {"id": "vn1", "virtualNetworkName": "MCP_GUEST", **vn}, transits)
    out, _ = await flow("catc_anchor_virtual_network", {"virtual_network": "MCP_GUEST", **args})
    assert out["status"] == "blocked" and needle in " ".join(out["blockers"]) and not lab.sent


async def test_remove_anchor_of_unknown_vn(api: respx.MockRouter) -> None:
    Lab(api, {"id": "vn1", "virtualNetworkName": "OTHER"}, [TRANSIT])
    with pytest.raises(ToolError, match="No layer 3 virtual network MCP_GUEST"):
        await flow("catc_anchor_virtual_network", {"virtual_network": "MCP_GUEST", "remove_anchor": True})


# --- anycast gateways of an anchored VN (catc_add_anycast_gateway) ------------------------------------------

POOL = "mcp-anchor-clients"


def mock_gateways(api: respx.MockRouter) -> respx.Route:
    """The pool is reserved at the anchor site (SYD-1, fabric FID) only."""
    api.get("/dna/intent/api/v1/network-device").respond(json={"response": []})
    api.get("/dna/intent/api/v1/ipam/siteIpAddressPools").mock(
        side_effect=lambda r: httpx.Response(
            200, json={"response": [{"name": POOL}] if r.url.params.get("siteId") == BLDG["id"] else []}
        )
    )
    api.get(f"{SDA}/anycastGateways").respond(json={"response": []})
    return api.post(f"{SDA}/anycastGateways").respond(202, json={"response": {"taskId": "ta"}})


GW = {"fabric_site": "Global/AU/SYD-2", "virtual_network": "MCP_GUEST", "ip_pool": POOL}


async def test_gateway_at_a_remote_site_uses_the_anchor_pool(api: respx.MockRouter) -> None:
    """Live 2026-10-22 (#190): a gateway at mcp-test-fabric2 for MCP_ANCHOR_VN (anchored at
    mcp-test-fabric) with the pool reserved only at the anchor site succeeded; edge2 got the VRF, the SVI,
    the anchor's LISP instance id and a LISP session to the anchor's control plane."""
    Lab(api, dict(ANCHORED), [TRANSIT])
    post = mock_gateways(api)
    preview, done = await flow("catc_add_anycast_gateway", GW)
    assert preview["status"] == "preview" and preview["preview"]["anchored_at"] == "Global/AU/SYD-1"
    effects = " ".join(preview["side_effects"])
    assert f"anchor's pool {POOL}" in effects and "underlay reachability" in effects
    assert done and json.loads(post.calls.last.request.content)[0]["fabricId"] == FID2


async def test_gateway_pool_missing_at_the_anchor(api: respx.MockRouter) -> None:
    Lab(api, dict(ANCHORED), [TRANSIT])
    mock_gateways(api)
    out, _ = await flow("catc_add_anycast_gateway", {**GW, "ip_pool": "other-pool"})
    assert out["status"] == "blocked" and (
        "No IP pool 'other-pool' is reserved at the anchor site Global/AU/SYD-1 (MCP_GUEST is anchored there)"
        in " ".join(out["blockers"])
    )


async def test_gateway_of_an_unanchored_vn_needs_the_local_pool(api: respx.MockRouter) -> None:
    Lab(api, {"id": "vn1", "virtualNetworkName": "MCP_GUEST", "fabricIds": [FID, FID2]}, [TRANSIT])
    post = mock_gateways(api)
    out, _ = await flow("catc_add_anycast_gateway", GW)
    assert out["status"] == "blocked" and not post.called
    assert f"No IP pool '{POOL}' is reserved at Global/AU/SYD-2 (catc_create_ip_pool)." in out["blockers"]
