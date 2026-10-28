"""D121: Assurance health score definitions (respx). Rows follow the 3.2.2 lab appliance's live answer
(2026-10-28, GET healthScoreDefinitions?deviceType=ROUTER, ids replaced): ROUTER cpuUtilizationThreshold
95.0 DEFAULT. Write bodies follow the 3.2.2 spec (PUT /{id}, POST /bulkUpdate)."""

import json
from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client
from fastmcp.exceptions import ToolError

from catc_mcp.server import create_server

from .conftest import make_settings
from .test_write_tools import preview_then_apply, run

PATH = "/dna/intent/api/v1/healthScoreDefinitions"
CPU_ID = "86476100-0000-4000-8000-000000000001"
MEM_ID = "4ed21ae3-0000-4000-8000-000000000002"
SW_CPU_ID = "5c0c0c0c-0000-4000-8000-000000000003"
RSSI_ID = "7e7e7e7e-0000-4000-8000-000000000004"
LINK_ID = "9a9a9a9a-0000-4000-8000-000000000005"


def kpi(did: str, name: str, display: str, family: str, value: float, **kw: Any) -> dict[str, Any]:
    return {
        "id": did,
        "name": name,
        "displayName": display,
        "deviceFamily": family,
        "description": display,
        "includeForOverallHealth": True,
        "definitionStatus": "DEFAULT",
        "thresholdValue": value,
        "synchronizeToIssueThreshold": False,
        **kw,
    }


ROWS = [
    kpi(CPU_ID, "cpuUtilizationThreshold", "ct_hs_cpu_utilization", "ROUTER", 95.0),
    kpi(MEM_ID, "memoryUtilizationThreshold", "ct_hs_memory_utilization", "ROUTER", 95.0),
    kpi(
        SW_CPU_ID,
        "cpuUtilizationThreshold",
        "ct_hs_cpu_utilization",
        "SWITCH_AND_HUB",
        80.0,
        definitionStatus="CUSTOM",  # what 3.2.2 reports for a changed KPI (#279)
    ),
    kpi(RSSI_ID, "rssiThreshold", "ct_hs_rssi", "WIRELESS_CLIENT", -72.0),
    # Another release may say MODIFIED: still changed from the default.
    kpi(LINK_ID, "linkErrorThreshold", "ct_hs_link_error", "WIRED_CLIENT", 2.0, definitionStatus="MODIFIED"),
]
DEVICES = {
    "Routers": [{"id": "r1", "family": "Routers"}, {"id": "r2", "family": "Routers"}],
    "Switches and Hubs": [{"id": "s1", "family": "Switches and Hubs"}],
}


class Lab:
    def __init__(self, api: respx.MockRouter) -> None:
        self.rows = {d["id"]: dict(d) for d in ROWS}
        self.sent: list[tuple[str, str, Any]] = []
        self.queries: list[dict[str, str]] = []
        api.get(PATH).mock(side_effect=self.list)
        api.get(url__regex=rf"{PATH}/[0-9a-f-]{{36}}$").mock(side_effect=self.get)
        api.put(url__regex=rf"{PATH}/[0-9a-f-]{{36}}$").mock(side_effect=self.put)
        api.post(f"{PATH}/bulkUpdate").mock(side_effect=self.bulk)
        api.get("/dna/intent/api/v1/network-device").mock(side_effect=self.devices)

    def list(self, request: httpx.Request) -> httpx.Response:
        q = request.url.params
        self.queries.append(dict(q))
        rows = [
            d
            for d in self.rows.values()
            if q.get("deviceType") in (None, d["deviceFamily"])
            and q.get("includeForOverallHealth") in (None, str(d["includeForOverallHealth"]).lower())
        ]
        start = int(q.get("offset", "1")) - 1
        size = int(q.get("limit", "25"))
        chunk = rows[start : start + size]
        page = {"limit": size, "offset": start + 1, "count": len(chunk)}
        return httpx.Response(200, json={"response": chunk, "version": "1.0", "page": page})

    def get(self, request: httpx.Request) -> httpx.Response:
        d = self.rows.get(request.url.path.rsplit("/", 1)[1])
        if d is None:
            return httpx.Response(404, json={"response": {"errorCode": "NOT_FOUND"}})
        return httpx.Response(200, json={"response": [d], "version": "1.0"})

    def _apply(self, did: str, body: dict[str, Any]) -> dict[str, Any]:
        self.rows[did] = {**self.rows[did], **body, "definitionStatus": "CUSTOM"}
        return self.rows[did]

    def put(self, request: httpx.Request) -> httpx.Response:
        did = request.url.path.rsplit("/", 1)[1]
        body = json.loads(request.content)
        self.sent.append(("PUT", did, body))
        return httpx.Response(200, json={"response": self._apply(did, body), "version": "1.0"})

    def bulk(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        self.sent.append(("POST", "bulkUpdate", body))
        out = [self._apply(b["id"], {k: v for k, v in b.items() if k != "id"}) for b in body]
        return httpx.Response(200, json={"response": out, "version": "1.0"})

    def devices(self, request: httpx.Request) -> httpx.Response:
        q = request.url.params
        rows = DEVICES.get(q.get("family", ""), [])
        start = int(q.get("offset", "1")) - 1
        return httpx.Response(200, json={"response": rows[start:]})


async def test_list_definitions(api: respx.MockRouter) -> None:
    lab = Lab(api)
    async with Client(create_server(make_settings())) as c:
        out = await run(
            c, "catc_list_health_score_definitions", {"device_family": "ROUTER", "response_format": "json"}
        )
        rows = {r["name"]: r for r in out["results"]}
        cpu = rows["cpuUtilizationThreshold"]
        assert cpu["threshold"] == 95.0 and cpu["status"] == "DEFAULT" and cpu["include_for_overall"] is True
        assert cpu["sync_to_issue"] is False and "factory_threshold" not in cpu
        assert lab.queries[-1]["deviceType"] == "ROUTER"
        out = await run(
            c, "catc_list_health_score_definitions", {"modified_only": True, "response_format": "json"}
        )
        assert [(r["device_family"], r["status"], r["factory_threshold"]) for r in out["results"]] == [
            ("SWITCH_AND_HUB", "CUSTOM", 95.0),
            ("WIRED_CLIENT", "MODIFIED", 1.0),
        ]
        assert out["modified"] == 2
        out = await run(c, "catc_list_health_score_definitions", {"response_format": "json"})
        assert out["total"] == 5 and out["modified"] == 2
        out = await run(
            c, "catc_list_health_score_definitions", {"search": "rssi", "response_format": "json"}
        )
        assert [r["id"] for r in out["results"]] == [RSSI_ID]


async def test_update_single_put(api: respx.MockRouter) -> None:
    lab = Lab(api)
    args = {"definitions": [{"name": "cpuUtilizationThreshold", "device_family": "ROUTER", "threshold": 90}]}
    preview, done = await preview_then_apply("catc_update_health_score_definition", args)
    assert preview["status"] == "preview"
    details = preview["preview"]
    assert details["method"] == "PUT" and details["path"] == f"{PATH}/{CPU_ID}"
    kpi_ = details["definitions"][0]
    assert kpi_["changes"] == {"threshold": {"from": 95.0, "to": 90.0}}
    assert kpi_["status"] == {"from": "DEFAULT", "to": "CUSTOM"}
    assert details["blast_radius"] == {"ROUTER": "2 device(s) in inventory with family 'Routers'"}
    assert any("re-scores 2 device(s)" in s for s in preview["side_effects"])
    assert done and done["result"]["updated"][0]["threshold"] == 90.0
    assert lab.sent == [
        (
            "PUT",
            CPU_ID,
            {"thresholdValue": 90.0, "includeForOverallHealth": True, "synchronizeToIssueThreshold": False},
        )
    ]


async def test_update_bulk_and_by_id(api: respx.MockRouter) -> None:
    lab = Lab(api)
    args = {
        "definitions": [
            {"name": "memoryUtilizationThreshold", "device_family": "ROUTER", "include_for_overall": False},
            {"name": RSSI_ID, "threshold": -70},
        ]
    }
    preview, done = await preview_then_apply("catc_update_health_score_definition", args)
    details = preview["preview"]
    assert details["method"] == "POST" and details["path"] == f"{PATH}/bulkUpdate"
    assert details["blast_radius"]["WIRELESS_CLIENT"] == "every wireless client's health score"
    assert any("no longer pulls" in s for s in preview["side_effects"])
    assert done and len(done["result"]["updated"]) == 2
    method, _, body = lab.sent[0]
    assert method == "POST"
    assert body == [
        {
            "id": MEM_ID,
            "thresholdValue": 95.0,
            "includeForOverallHealth": False,
            "synchronizeToIssueThreshold": False,
        },
        {
            "id": RSSI_ID,
            "thresholdValue": -70.0,
            "includeForOverallHealth": True,
            "synchronizeToIssueThreshold": False,
        },
    ]


async def test_reset_to_default(api: respx.MockRouter) -> None:
    lab = Lab(api)
    args = {
        "definitions": [{"name": "ct_hs_cpu_utilization", "device_family": "SWITCH_AND_HUB"}],
        "reset_to_default": True,
    }
    preview, done = await preview_then_apply("catc_update_health_score_definition", args)
    kpi_ = preview["preview"]["definitions"][0]
    assert kpi_["changes"] == {"threshold": {"from": 80.0, "to": 95.0}}
    assert kpi_["status"] == {"from": "CUSTOM", "to": "DEFAULT"}
    assert done and lab.sent[0][:2] == ("PUT", SW_CPU_ID)
    assert lab.sent[0][2]["thresholdValue"] == 95.0


async def test_changed_kpi_is_listed_after_update(api: respx.MockRouter) -> None:
    """#279: the live sequence on 3.2.2. A KPI written back as CUSTOM shows under modified_only and in the
    count, and a KPI already changed (MODIFIED) keeps its status in the preview."""
    Lab(api)
    args = {"definitions": [{"name": "cpuUtilizationThreshold", "device_family": "ROUTER", "threshold": 90}]}
    _, done = await preview_then_apply("catc_update_health_score_definition", args)
    assert done and done["result"]["updated"][0]["status"] == "CUSTOM"
    async with Client(create_server(make_settings())) as c:
        out = await run(
            c,
            "catc_list_health_score_definitions",
            {"device_family": "ROUTER", "modified_only": True, "response_format": "json"},
        )
    assert [(r["name"], r["status"], r["factory_threshold"]) for r in out["results"]] == [
        ("cpuUtilizationThreshold", "CUSTOM", 95.0)
    ]
    assert out["modified"] == 1
    args = {"definitions": [{"name": LINK_ID, "threshold": 3}]}
    preview, _ = await preview_then_apply("catc_update_health_score_definition", args)
    assert preview["preview"]["definitions"][0]["status"] == {"from": "MODIFIED", "to": "MODIFIED"}


async def test_blockers_and_errors(api: respx.MockRouter) -> None:
    lab = Lab(api)
    out, _ = await preview_then_apply(
        "catc_update_health_score_definition",
        {"definitions": [{"name": "cpuUtilizationThreshold", "device_family": "ROUTER", "threshold": 95}]},
    )
    assert out["status"] == "blocked" and "nothing would change" in out["blockers"][0]
    out, _ = await preview_then_apply(
        "catc_update_health_score_definition",
        {"definitions": [{"name": "cpuUtilizationThreshold", "device_family": "ROUTER", "threshold": 150}]},
    )
    assert out["status"] == "blocked" and "percentage" in out["blockers"][0]
    assert lab.sent == []
    async with Client(create_server(make_settings(mcp_enable_writes=True))) as c:
        with pytest.raises(ToolError, match="No ROUTER health score definition named 'cpuUtilisation'"):
            await run(
                c,
                "catc_update_health_score_definition",
                {"definitions": [{"name": "cpuUtilisation", "device_family": "ROUTER", "threshold": 90}]},
            )
        with pytest.raises(ToolError, match="Give device_family"):
            await run(
                c,
                "catc_update_health_score_definition",
                {"definitions": [{"name": "cpuUtilizationThreshold", "threshold": 90}]},
            )
        with pytest.raises(ToolError, match="nothing to change"):
            await run(
                c,
                "catc_update_health_score_definition",
                {"definitions": [{"name": "cpuUtilizationThreshold", "device_family": "ROUTER"}]},
            )
        with pytest.raises(ToolError, match="reset_to_default takes only"):
            await run(
                c,
                "catc_update_health_score_definition",
                {
                    "definitions": [
                        {"name": "cpuUtilizationThreshold", "device_family": "ROUTER", "threshold": 9}
                    ],
                    "reset_to_default": True,
                },
            )


async def test_write_needs_the_write_tier(api: respx.MockRouter) -> None:
    Lab(api)
    async with Client(create_server(make_settings())) as c:
        names = {t.name for t in await c.list_tools()}
    assert "catc_list_health_score_definitions" in names
    assert "catc_update_health_score_definition" not in names
