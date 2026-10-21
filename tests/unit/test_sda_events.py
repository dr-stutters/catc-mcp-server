"""D100: pending fabric events (respx); payloads follow the 3.2.2 spec (PendingFabricEventBase)."""

import json
from typing import Any

import httpx
import pytest
import respx
from fastmcp.exceptions import ToolError

from .test_read_tools import AREA, BLDG, GLOBAL, call
from .test_sda import FABRIC, FID, flow
from .test_write_tools import mock_sites, task_ok

SDA = "/dna/intent/api/v1/sda"
EVENTS = [
    {
        "id": "ev-1",
        "fabricId": FID,
        "detail": "Re-provision edge mcp-catc-fab-edge1 (LISP instance 4099 missing)",
    },
    {"id": "ev-2", "fabricId": FID, "detail": "Border mcp-catc-fab-bcp: anycast gateway update"},
]


class Pending:
    def __init__(self, api: respx.MockRouter, events: list[dict[str, Any]]) -> None:
        self.events = list(events)
        self.applied: list[Any] = []
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
        api.get(f"{SDA}/pendingFabricEvents").mock(
            side_effect=lambda r: httpx.Response(200, json={"response": self.events})
        )
        api.post(f"{SDA}/pendingFabricEvents/apply").mock(side_effect=self.apply)
        task_ok(api, "tp")

    def apply(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        self.applied.append(body)
        self.events = [e for e in self.events if e["id"] != body[0]["id"]]
        return httpx.Response(202, json={"response": {"taskId": "tp"}})


async def test_list(api: respx.MockRouter) -> None:
    Pending(api, EVENTS)
    out = await call("catc_list_pending_fabric_events", {"response_format": "json"})
    assert out["total"] == 2 and out["results"][0]["fabric_site"] == "Global/AU/SYD-1"
    assert "LISP instance" in out["results"][0]["detail"] and out["note"].startswith("Apply with")
    out = await call(
        "catc_list_pending_fabric_events",
        {"fabric_site": "Global/AU/SYD-1", "limit": 1, "offset": 1, "response_format": "json"},
    )
    assert out["fabric_sites_checked"] == 1 and [e["id"] for e in out["results"]] == ["ev-2"]


async def test_apply_all_one_request_each(api: respx.MockRouter) -> None:
    p = Pending(api, EVENTS)
    preview, done = await flow("catc_apply_pending_fabric_events", {"fabric_site": FID})
    assert preview["status"] == "preview" and preview["blast_radius"] == 1
    assert [e["id"] for e in preview["preview"]["events"]] == ["ev-1", "ev-2"]
    assert done and done["result"] == {"applied": ["ev-1", "ev-2"], "still_pending": []}
    assert p.applied == [[{"fabricId": FID, "id": "ev-1"}], [{"fabricId": FID, "id": "ev-2"}]]


async def test_apply_some_and_unknown(api: respx.MockRouter) -> None:
    p = Pending(api, EVENTS)
    _, done = await flow("catc_apply_pending_fabric_events", {"fabric_site": FID, "event_ids": ["ev-2"]})
    assert done and done["result"]["applied"] == ["ev-2"] and len(p.applied) == 1
    with pytest.raises(ToolError, match="Not pending at Global/AU/SYD-1: ev-9"):
        await flow("catc_apply_pending_fabric_events", {"fabric_site": FID, "event_ids": ["ev-9"]})


async def test_nothing_pending_and_failure(api: respx.MockRouter) -> None:
    Pending(api, [])
    out, _ = await flow("catc_apply_pending_fabric_events", {"fabric_site": FID})
    assert out["status"] == "blocked" and "No pending fabric events" in out["blockers"][0]
    out = await call("catc_list_pending_fabric_events", {"response_format": "json"})
    assert out["total"] == 0 and out["note"].startswith("No pending")


async def test_failure_stops(api: respx.MockRouter) -> None:
    Pending(api, EVENTS)
    api.post(f"{SDA}/pendingFabricEvents/apply").respond(202, json={"response": {"taskId": "tbad"}})
    api.get("/dna/intent/api/v1/task/tbad").respond(
        json={"response": {"isError": True, "endTime": 1, "failureReason": "NCSP10011: device unreachable"}}
    )
    with pytest.raises(ToolError, match=r"Stopped at event ev-1 \(0 of 2 applied"):
        await flow("catc_apply_pending_fabric_events", {"fabric_site": FID})


async def test_no_fabric_sites(api: respx.MockRouter) -> None:
    api.get(f"{SDA}/fabricSites").respond(json={"response": []})
    out = await call("catc_list_pending_fabric_events", {"response_format": "json"})
    assert (
        out["results"] == []
        and out["fabric_sites_checked"] == 0
        and out["note"] == "No SD-Access fabric sites."
    )
