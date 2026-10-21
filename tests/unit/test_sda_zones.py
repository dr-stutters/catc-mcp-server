"""D97: SD-Access fabric zones (respx); payloads follow the 3.2.2 spec's sda/fabricZones."""

import json
from typing import Any

import httpx
import respx

from .test_read_tools import AREA, BLDG, GLOBAL
from .test_sda import FABRIC, flow
from .test_write_tools import mock_sites, task_ok

SDA = "/dna/intent/api/v1/sda"
FLOOR = {
    **BLDG,
    "id": "aaaaaaaa-0000-0000-0000-000000000003",
    "nameHierarchy": "Global/AU/SYD-1/F1",
    "name": "F1",
    "type": "floor",
}
ZONE_ID = "a0000000-0000-0000-0000-0000000000e1"


class Lab:
    def __init__(
        self,
        api: respx.MockRouter,
        *,
        zones: list[dict[str, Any]],
        fabrics: list[dict[str, Any]] | None = None,
    ) -> None:
        self.zones = list(zones)
        self.sent: list[tuple[str, str, Any]] = []
        mock_sites(api, [GLOBAL, AREA, BLDG, FLOOR])
        for site in (BLDG, FLOOR, AREA):
            api.get(f"/dna/intent/api/v1/sites/{site['id']}").respond(json={"response": site})
        api.get(f"{SDA}/fabricSites").respond(json={"response": [FABRIC] if fabrics is None else fabrics})

        def zones_q(r: httpx.Request) -> httpx.Response:
            q = r.url.params
            rows = [
                z
                for z in self.zones
                if q.get("siteId") in (None, z["siteId"]) and q.get("id") in (None, z["id"])
            ]
            return httpx.Response(200, json={"response": rows})

        api.get(f"{SDA}/fabricZones").mock(side_effect=zones_q)
        api.post(f"{SDA}/fabricZones").mock(side_effect=self.post)
        api.delete(f"{SDA}/fabricZones/{ZONE_ID}").mock(side_effect=self.delete)
        task_ok(api, "tz")

    def post(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        self.sent.append(("POST", "/fabricZones", body))
        self.zones.append({"id": ZONE_ID, **body[0]})
        return httpx.Response(202, json={"response": {"taskId": "tz"}})

    def delete(self, request: httpx.Request) -> httpx.Response:
        self.sent.append(("DELETE", request.url.path, None))
        return httpx.Response(202, json={"response": {"taskId": "tz"}})


async def test_create_zone_inherits_auth(api: respx.MockRouter) -> None:
    lab = Lab(api, zones=[])
    preview, done = await flow("catc_create_fabric_zone", {"site": "Global/AU/SYD-1/F1"})
    assert preview["action"] == "Make Global/AU/SYD-1/F1 a fabric zone of Global/AU/SYD-1 (No Authentication)"
    assert done and done["result"]["zone_id"] == ZONE_ID
    assert lab.sent == [
        ("POST", "/fabricZones", [{"siteId": FLOOR["id"], "authenticationProfileName": "No Authentication"}])
    ]


async def test_create_zone_blockers(api: respx.MockRouter) -> None:
    Lab(
        api,
        zones=[{"id": ZONE_ID, "siteId": FLOOR["id"], "authenticationProfileName": "Closed Authentication"}],
    )
    out, _ = await flow(
        "catc_create_fabric_zone", {"site": "Global/AU/SYD-1/F1", "authentication_profile": "Low Impact"}
    )
    assert out["status"] == "blocked" and "already a fabric zone" in out["blockers"][0]
    out, _ = await flow("catc_create_fabric_zone", {"site": "Global/AU/SYD-1"})
    assert "is a fabric site itself" in out["blockers"][0]


async def test_zone_needs_a_fabric(api: respx.MockRouter) -> None:
    Lab(api, zones=[], fabrics=[])
    out, _ = await flow("catc_create_fabric_zone", {"site": "Global/AU/SYD-1/F1"})
    assert out["status"] == "blocked" and "not inside a fabric site" in out["blockers"][0]


async def test_delete_zone_kind(api: respx.MockRouter) -> None:
    lab = Lab(
        api, zones=[{"id": ZONE_ID, "siteId": FLOOR["id"], "authenticationProfileName": "No Authentication"}]
    )
    gws = api.get(f"{SDA}/anycastGateways").respond(json={"response": [{"id": "g1", "fabricId": ZONE_ID}]})
    api.get(f"{SDA}/portAssignments").respond(json={"response": []})
    out, _ = await flow("catc_delete_sda_object", {"kind": "fabric_zone", "id": ZONE_ID})
    assert out["status"] == "blocked" and "1 anycast gateway(s) and 0 port" in out["blockers"][0]
    gws.respond(json={"response": []})
    preview, done = await flow("catc_delete_sda_object", {"kind": "fabric_zone", "id": ZONE_ID})
    assert (
        preview["status"] == "preview"
        and done
        and lab.sent == [("DELETE", f"{SDA}/fabricZones/{ZONE_ID}", None)]
    )
