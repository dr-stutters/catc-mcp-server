"""D104: SD-Access fabric site settings (respx); payloads follow the 3.2.2 spec's PUT sda/fabricSites."""

import json
from typing import Any

import httpx
import pytest
import respx

from .test_read_tools import AREA, BLDG, GLOBAL
from .test_sda import FID, flow
from .test_write_tools import mock_sites, task_ok

SDA = "/dna/intent/api/v1/sda"
CP_BORDER = ["CONTROL_PLANE_NODE", "BORDER_NODE"]
# the lab's fabric: a control plane + border, an edge and a border-only node, listed in that order
THREE = [CP_BORDER, ["EDGE_NODE"], ["BORDER_NODE"]]


class Lab:
    def __init__(
        self,
        api: respx.MockRouter,
        pub_sub: bool,
        transport: str | None = "IPV4",
        roles: list[list[str]] | None = None,
    ) -> None:
        self.site: dict[str, Any] = {
            "id": FID,
            "siteId": BLDG["id"],
            "authenticationProfileName": "Closed Authentication",
            "isPubSubEnabled": pub_sub,
        }
        if transport:
            self.site["underlayTransport"] = transport
        self.puts: list[Any] = []
        mock_sites(api, [GLOBAL, AREA, BLDG])
        api.get(f"/dna/intent/api/v1/sites/{BLDG['id']}").respond(json={"response": BLDG})
        api.get(f"{SDA}/fabricSites").mock(
            side_effect=lambda r: httpx.Response(200, json={"response": [self.site]})
        )
        api.get(f"{SDA}/fabricDevices").respond(
            json={
                "response": [
                    {"id": f"fd{i}", "networkDeviceId": f"d{i}", "fabricId": FID, "deviceRoles": r}
                    for i, r in enumerate(roles or [])
                ]
            }
        )
        # the pub/sub blocker names the devices ('hostname (IP)'); d2 isn't in the inventory: it stays an id
        api.get("/dna/intent/api/v1/network-device").respond(
            json={
                "response": [
                    {"id": "d0", "hostname": "bcp2", "managementIpAddress": "10.0.0.21"},
                    {"id": "d1", "hostname": "edge2", "managementIpAddress": "10.0.0.22"},
                ]
            }
        )
        api.put(f"{SDA}/fabricSites").mock(side_effect=self.put)
        task_ok(api, "ts")

    def put(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        self.puts.append(body)
        self.site = body[0]
        return httpx.Response(202, json={"response": {"taskId": "ts"}})


async def test_move_to_pub_sub_on_empty_fabric(api: respx.MockRouter) -> None:
    lab = Lab(api, pub_sub=False)
    preview, done = await flow("catc_update_fabric_site", {"fabric_site": "Global/AU/SYD-1", "pub_sub": True})
    assert preview["action"] == "Update fabric site Global/AU/SYD-1: isPubSubEnabled False -> True"
    assert preview.get("blast_radius") is None
    assert any("devices added afterwards" in s for s in preview["side_effects"])
    assert done and lab.puts == [
        [
            {
                "id": FID,
                "siteId": BLDG["id"],
                "authenticationProfileName": "Closed Authentication",  # kept as it was
                "isPubSubEnabled": True,
                "underlayTransport": "IPV4",
            }
        ]
    ]
    assert done["result"]["fabric_site"]["isPubSubEnabled"] is True


@pytest.mark.parametrize("before", [False, True])
async def test_pub_sub_change_blocked_with_fabric_devices(api: respx.MockRouter, before: bool) -> None:
    """Live on 3.2.2 (2026-10-22, lab mcp-catc-fabric2), the PUT with bcp2 and edge2 in the fabric answered
    'NCHS20420: Bad Request: Fabric Site update request failed in SDA Fabric. isPubSubEnabled cannot be
    updated while there are devices in the fabric.' after a clean preview; removing both, switching, then
    adding them back worked. The preview now blocks and gives that order."""
    lab = Lab(api, pub_sub=before, roles=THREE)
    out, done = await flow("catc_update_fabric_site", {"fabric_site": FID, "pub_sub": not before})
    assert out["status"] == "blocked" and done is None and not lab.puts
    (blocker,) = [b for b in out["blockers"] if "isPubSubEnabled" in b]
    assert "NCHS20420" in blocker and "it has 3:" in blocker
    # removal order: the edge, then the border, the control plane last
    assert blocker.index("edge2 (10.0.0.22) [EDGE_NODE]") < blocker.index("d2 [BORDER_NODE]")
    assert blocker.index("d2 [BORDER_NODE]") < blocker.index(
        "bcp2 (10.0.0.21) [CONTROL_PLANE_NODE, BORDER_NODE]"
    )
    assert "catc_delete_fabric_device" in blocker and "catc_add_fabric_device" in blocker
    assert "proven live" in blocker


async def test_pub_sub_blocker_names_the_first_ten(api: respx.MockRouter) -> None:
    Lab(api, pub_sub=False, roles=[["EDGE_NODE"]] * 12 + [CP_BORDER])
    out, _ = await flow("catc_update_fabric_site", {"fabric_site": FID, "pub_sub": True})
    (blocker,) = [b for b in out["blockers"] if "isPubSubEnabled" in b]
    assert "it has 13:" in blocker and "and 3 more" in blocker and "CONTROL_PLANE_NODE" not in blocker


async def test_underlay_transport_not_blocked(api: respx.MockRouter) -> None:
    lab = Lab(api, pub_sub=True, roles=THREE)
    preview, done = await flow(
        "catc_update_fabric_site", {"fabric_site": FID, "underlay_transport": "IPV4_IPV6"}
    )
    assert preview["status"] == "preview" and preview["blast_radius"] == 3
    assert preview["side_effects"][0].startswith(
        "Catalyst Center re-provisions the fabric configuration of 3"
    )
    assert any("not tried live" in s for s in preview["side_effects"])
    assert done and lab.puts[0][0]["underlayTransport"] == "IPV4_IPV6" and lab.puts[0][0]["isPubSubEnabled"]


async def test_back_to_lisp_bgp_warns(api: respx.MockRouter) -> None:
    Lab(api, pub_sub=True, transport=None)
    out, _ = await flow(
        "catc_update_fabric_site", {"fabric_site": FID, "pub_sub": False, "underlay_transport": "IPV4_IPV6"}
    )
    assert out["status"] == "preview"
    assert "may be refused" in out["side_effects"][-1]
    assert set(out["preview"]["changes"]) == {"isPubSubEnabled", "underlayTransport"}


@pytest.mark.parametrize("args", [{}, {"pub_sub": True}, {"underlay_transport": "IPV4"}])
async def test_nothing_to_change(api: respx.MockRouter, args: dict[str, Any]) -> None:
    lab = Lab(api, pub_sub=True, roles=THREE)
    out, _ = await flow("catc_update_fabric_site", {"fabric_site": FID, **args})
    assert out["status"] == "blocked" and "Nothing to change" in out["blockers"][0] and not lab.puts
    assert not any("isPubSubEnabled" in b for b in out["blockers"])
