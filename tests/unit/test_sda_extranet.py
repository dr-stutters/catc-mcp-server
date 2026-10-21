"""D95: SD-Access extranet policies (respx); payloads follow the 3.2.2 spec."""

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
POLICY = {
    "id": "xp-1",
    "extranetPolicyName": "mcp-shared",
    "providerVirtualNetworkName": "SHARED",
    "subscriberVirtualNetworkNames": ["MCP_VN"],
    "fabricIds": [FID],
}


class Lab:
    def __init__(self, api: respx.MockRouter, policies: list[dict[str, Any]]) -> None:
        self.policies = list(policies)
        self.sent: list[tuple[str, Any, Any]] = []
        mock_sites(api, [GLOBAL, AREA, BLDG])
        api.get(f"/dna/intent/api/v1/sites/{BLDG['id']}").respond(json={"response": BLDG})
        api.get(f"{SDA}/fabricSites").respond(json={"response": [FABRIC]})
        api.get(f"{SDA}/fabricDevices").respond(
            json={
                "response": [
                    {"id": "fd1", "networkDeviceId": "d1", "fabricId": FID, "deviceRoles": ["EDGE_NODE"]}
                ]
            }
        )
        api.get(f"{SDA}/layer3VirtualNetworks").respond(
            json={"response": [{"virtualNetworkName": n} for n in ("SHARED", "MCP_VN", "GUEST")]}
        )
        api.get(f"{SDA}/extranetPolicies").mock(
            side_effect=lambda r: httpx.Response(
                200,
                json={
                    "response": [
                        p
                        for p in self.policies
                        if r.url.params.get("extranetPolicyName") in (None, p["extranetPolicyName"])
                    ]
                },
            )
        )
        api.route(path=f"{SDA}/extranetPolicies", method__in=["POST", "PUT", "DELETE"]).mock(
            side_effect=self.write
        )
        task_ok(api, "tx")

    def write(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content) if request.content else None
        self.sent.append((request.method, body, dict(request.url.params)))
        if request.method == "DELETE":
            self.policies = []
        else:
            self.policies = [{**body[0], "id": body[0].get("id", "xp-new")}]
        return httpx.Response(202, json={"response": {"taskId": "tx"}})


async def test_create(api: respx.MockRouter) -> None:
    lab = Lab(api, [])
    args = {
        "name": "mcp-shared",
        "provider_vn": "SHARED",
        "subscriber_vns": ["MCP_VN"],
        "fabric_sites": ["Global/AU/SYD-1"],
    }
    preview, done = await flow("catc_set_extranet_policy", args)
    assert preview["action"] == "Create extranet policy mcp-shared" and preview["blast_radius"] == 1
    assert preview["preview"]["fabric_sites"] == ["Global/AU/SYD-1"]
    assert done and lab.sent == [
        (
            "POST",
            [
                {
                    "extranetPolicyName": "mcp-shared",
                    "providerVirtualNetworkName": "SHARED",
                    "subscriberVirtualNetworkNames": ["MCP_VN"],
                    "fabricIds": [FID],
                }
            ],
            {},
        )
    ]
    assert done["result"]["policy"]["id"] == "xp-new"


async def test_update_keeps_unset_fields(api: respx.MockRouter) -> None:
    lab = Lab(api, [POLICY])
    _, done = await flow(
        "catc_set_extranet_policy", {"name": "mcp-shared", "subscriber_vns": ["MCP_VN", "GUEST"]}
    )
    assert done and lab.sent[0][0] == "PUT"
    assert lab.sent[0][1][0] == {**POLICY, "subscriberVirtualNetworkNames": ["MCP_VN", "GUEST"]}


async def test_noop_and_delete(api: respx.MockRouter) -> None:
    lab = Lab(api, [POLICY])
    out, _ = await flow("catc_set_extranet_policy", {"name": "mcp-shared", "subscriber_vns": ["MCP_VN"]})
    assert out["status"] == "blocked" and "Nothing to change" in out["blockers"][0]
    preview, done = await flow("catc_set_extranet_policy", {"name": "mcp-shared", "delete": True})
    assert "lose the provider" in preview["side_effects"][0]
    assert done and lab.sent == [("DELETE", None, {"extranetPolicyName": "mcp-shared"})]
    with pytest.raises(ToolError, match="No extranet policy mcp-shared"):
        await flow("catc_set_extranet_policy", {"name": "mcp-shared", "delete": True})


@pytest.mark.parametrize(
    ("args", "needle"),
    [
        ({"subscriber_vns": ["MCP_VN"]}, "provider_vn is required"),
        ({"provider_vn": "SHARED"}, "at least one subscriber"),
        ({"provider_vn": "NOPE", "subscriber_vns": ["MCP_VN"]}, "No layer 3 virtual network NOPE"),
        ({"provider_vn": "SHARED", "subscriber_vns": ["SHARED"]}, "can't also be a subscriber"),
    ],
)
async def test_blockers(api: respx.MockRouter, args: dict[str, Any], needle: str) -> None:
    lab = Lab(api, [])
    out, _ = await flow("catc_set_extranet_policy", {"name": "mcp-x", **args})
    assert out["status"] == "blocked" and needle in " ".join(out["blockers"]) and not lab.sent
