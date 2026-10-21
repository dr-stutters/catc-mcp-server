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


class Lab:
    def __init__(self, api: respx.MockRouter, pub_sub: bool, transport: str | None = "IPV4") -> None:
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
                "response": [{"id": f"fd{i}", "networkDeviceId": f"d{i}", "fabricId": FID} for i in range(3)]
            }
        )
        api.put(f"{SDA}/fabricSites").mock(side_effect=self.put)
        task_ok(api, "ts")

    def put(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        self.puts.append(body)
        self.site = body[0]
        return httpx.Response(202, json={"response": {"taskId": "ts"}})


async def test_move_to_pub_sub(api: respx.MockRouter) -> None:
    lab = Lab(api, pub_sub=False)
    preview, done = await flow("catc_update_fabric_site", {"fabric_site": "Global/AU/SYD-1", "pub_sub": True})
    assert preview["action"] == "Update fabric site Global/AU/SYD-1: isPubSubEnabled False -> True"
    assert preview["blast_radius"] == 3
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


async def test_back_to_lisp_bgp_warns(api: respx.MockRouter) -> None:
    Lab(api, pub_sub=True, transport=None)
    out, _ = await flow(
        "catc_update_fabric_site", {"fabric_site": FID, "pub_sub": False, "underlay_transport": "IPV4_IPV6"}
    )
    assert "may be refused" in out["side_effects"][1]
    assert set(out["preview"]["changes"]) == {"isPubSubEnabled", "underlayTransport"}


@pytest.mark.parametrize("args", [{}, {"pub_sub": True}, {"underlay_transport": "IPV4"}])
async def test_nothing_to_change(api: respx.MockRouter, args: dict[str, Any]) -> None:
    lab = Lab(api, pub_sub=True)
    out, _ = await flow("catc_update_fabric_site", {"fabric_site": FID, **args})
    assert out["status"] == "blocked" and "Nothing to change" in out["blockers"][0] and not lab.puts
