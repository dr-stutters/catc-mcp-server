"""D53: Assurance issue definitions (respx). The system rows follow the 3.2.2 lab appliance's live answer
(2026-10-28, GET systemIssueDefinitions?limit=3&offset=1, ids replaced); the empty custom list is its live
answer too. Custom definitions with rules follow the 3.2.2 spec (customIssueDefinitions), except that the
appliance returns rules[].severity as a string ("5"), as recorded live (#262). Like the appliance, the fake
GET without issueEnabled leaves out disabled definitions, even with name= set (#262)."""

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

SYSTEM = "/dna/intent/api/v1/systemIssueDefinitions"
CUSTOM = "/dna/intent/api/v1/customIssueDefinitions"
BGP_ID = "3e4250c4-0000-4000-8000-000000000001"
WLC_ID = "01d34dd7-0000-4000-8000-000000000002"
SENSOR_ID = "009e5b42-0000-4000-8000-000000000003"
CUSTOM_ID = "c0c0c0c0-0000-4000-8000-000000000004"
RADIO_ID = "2a2a2a2a-0000-4000-8000-000000000005"

BGP = {
    "id": BGP_ID,
    "name": "BGP_Down",
    "displayName": "Network Device Interface Connectivity - BGP Down",
    "description": "Time duration BGP on a Router/Switch can be down for before issue is generated",
    "priority": "P2",
    "defaultPriority": "P2",
    "deviceType": "SWITCH_AND_HUB",
    "issueEnabled": True,
    "profileId": "global",
    "definitionStatus": "DEFAULT",
    "categoryName": "CONNECTIVITY",
    "synchronizeToHealthThreshold": False,
    "thresholdValue": 3.0,
}
WLC = {
    "id": WLC_ID,
    "name": "wlc_monitor",
    "displayName": "WLC Monitor",
    "description": "Cisco Catalyst Center is not receiving data from Wireless Controller",
    "priority": "P1",
    "defaultPriority": "P3",
    "deviceType": "WIRELESS_CONTROLLER",
    "issueEnabled": False,
    "profileId": "global",
    "definitionStatus": "MODIFIED",
    "categoryName": "AVAILABILITY",
    "synchronizeToHealthThreshold": False,
}
SENSOR = {
    "id": SENSOR_ID,
    "name": "global_sensor_outlook_fail_trigger",
    "displayName": "Sensors - Outlook Server Test Fail",
    "description": "Multiple sensors are reporting a failure to connect to Outlook Web Access",
    "priority": "P3",
    "defaultPriority": "P3",
    "deviceType": "SENSOR",
    "issueEnabled": True,
    "profileId": "global",
    "definitionStatus": "DEFAULT",
    "categoryName": "SENSOR_TEST",
    "synchronizeToHealthThreshold": False,
}
OSPF = {
    "id": CUSTOM_ID,
    "name": "mcp-ospf-down",
    "description": "OSPF neighbour lost",
    "priority": "P2",
    "isEnabled": True,
    "isNotificationEnabled": True,
    "isDeletable": True,
    "profileId": "global",
    "rules": [
        {
            "type": "SYSLOG",
            "severity": 5,
            "facility": "OSPF",
            "mnemonic": "ADJCHG",
            "pattern": "from FULL to DOWN",
            "occurrences": 1,
        }
    ],
}
# Factory-disabled (one of the six 2.4 GHz radio definitions on 3.2.2); absent from the default GET.
RADIO = {
    "id": RADIO_ID,
    "name": "radio_util_trigger_2_4ghz",
    "displayName": "Radio - High Utilization 2.4 GHz",
    "description": "Radio channel utilization is above the threshold on the 2.4 GHz band",
    "priority": "P3",
    "defaultPriority": "P3",
    "deviceType": "UNIFIED_AP",
    "issueEnabled": False,
    "profileId": "global",
    "definitionStatus": "DEFAULT",
    "categoryName": "UTILIZATION",
    "synchronizeToHealthThreshold": False,
}
# A custom rule as the appliance returns it: severity as a string.
OSPF_LIVE = {**OSPF, "rules": [{**OSPF["rules"][0], "severity": "5"}]}


def rw_server() -> Any:
    return create_server(make_settings(mcp_enable_writes=True))


class Lab:
    """A fake appliance holding system and custom definitions; records the writes."""

    def __init__(self, api: respx.MockRouter, custom: list[dict[str, Any]] | None = None) -> None:
        self.system = {d["id"]: dict(d) for d in (BGP, WLC, SENSOR, RADIO)}
        self.custom = [dict(d) for d in (custom or [])]
        self.sent: list[tuple[str, str, Any]] = []
        self.queries: list[dict[str, str]] = []
        api.get(SYSTEM).mock(side_effect=self.list_system)
        api.get(url__regex=rf"{SYSTEM}/[0-9a-f-]{{36}}$").mock(side_effect=self.get_system)
        api.put(url__regex=rf"{SYSTEM}/[0-9a-f-]{{36}}$").mock(side_effect=self.put_system)
        api.get(CUSTOM).mock(side_effect=self.list_custom)
        api.get(url__regex=rf"{CUSTOM}/[0-9a-f-]{{36}}$").mock(side_effect=self.get_custom)
        api.post(CUSTOM).mock(side_effect=self.post_custom)
        api.delete(url__regex=rf"{CUSTOM}/[0-9a-f-]{{36}}$").mock(side_effect=self.delete_custom)

    @staticmethod
    def _page(rows: list[dict[str, Any]], q: Any) -> httpx.Response:
        start = int(q.get("offset", "1")) - 1  # one-based
        size = int(q.get("limit", "25"))
        chunk = rows[start : start + size]
        page = {"limit": size, "offset": start + 1, "count": len(chunk)}
        return httpx.Response(200, json={"response": chunk, "version": "1.0", "page": page})

    def list_system(self, request: httpx.Request) -> httpx.Response:
        q = request.url.params
        self.queries.append(dict(q))
        rows = [
            d
            for d in self.system.values()
            if q.get("name") in (None, d["name"])
            and q.get("priority") in (None, d["priority"])
            and q.get("deviceType") in (None, d["deviceType"])
            # 3.2.2: no issueEnabled -> enabled definitions only.
            and q.get("issueEnabled", "true") == str(d["issueEnabled"]).lower()
        ]
        return self._page(rows, q)

    def get_system(self, request: httpx.Request) -> httpx.Response:
        d = self.system.get(request.url.path.rsplit("/", 1)[1])
        if d is None:
            return httpx.Response(404, json={"response": {"errorCode": "NOT_FOUND"}})
        return httpx.Response(200, json={"response": d, "version": "1.0"})

    def put_system(self, request: httpx.Request) -> httpx.Response:
        did = request.url.path.rsplit("/", 1)[1]
        body = json.loads(request.content)
        self.sent.append(("PUT", did, body))
        self.system[did] = {**self.system[did], **body, "definitionStatus": "MODIFIED"}
        return httpx.Response(200, json={"response": self.system[did], "version": "1.0"})

    def list_custom(self, request: httpx.Request) -> httpx.Response:
        q = request.url.params
        self.queries.append(dict(q))
        rows = [d for d in self.custom if q.get("name") in (None, d["name"])]
        resp = self._page(rows, q)
        body = json.loads(resp.content)
        body["page"]["sortBy"] = [{"name": "name", "order": "asc"}]
        return httpx.Response(200, json=body)

    def get_custom(self, request: httpx.Request) -> httpx.Response:
        did = request.url.path.rsplit("/", 1)[1]
        rows = [d for d in self.custom if d["id"] == did]
        if not rows:
            return httpx.Response(404, json={"response": {"errorCode": "NOT_FOUND"}})
        return httpx.Response(200, json={"response": rows[0], "version": "1.0"})

    def post_custom(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        self.sent.append(("POST", CUSTOM, body))
        made = {**body, "id": CUSTOM_ID, "isDeletable": True, "profileId": "global"}
        self.custom.append(made)
        return httpx.Response(200, json={"response": made, "version": "1.0"})

    def delete_custom(self, request: httpx.Request) -> httpx.Response:
        did = request.url.path.rsplit("/", 1)[1]
        self.sent.append(("DELETE", did, None))
        self.custom = [d for d in self.custom if d["id"] != did]
        return httpx.Response(204)


async def test_list_system_definitions(api: respx.MockRouter) -> None:
    lab = Lab(api)
    async with Client(create_server(make_settings())) as c:
        out = await run(c, "catc_list_issue_definitions", {"response_format": "json"})
        rows = {r["name"]: r for r in out["results"]}
        assert rows["BGP_Down"]["threshold"] == 3.0 and rows["BGP_Down"]["enabled"] is True
        assert rows["wlc_monitor"]["changed_from_default"] is True
        assert rows["wlc_monitor"]["priority"] == "P1" and rows["wlc_monitor"]["default_priority"] == "P3"
        assert lab.queries[-1]["offset"] == "1" and lab.queries[-1]["profileId"] == "global"
        out = await run(
            c,
            "catc_list_issue_definitions",
            {"enabled": False, "device_type": "WIRELESS_CONTROLLER", "response_format": "json"},
        )
        assert [r["name"] for r in out["results"]] == ["wlc_monitor"]
        assert lab.queries[-1]["issueEnabled"] == "false"
        out = await run(c, "catc_list_issue_definitions", {"search": "outlook", "response_format": "json"})
        assert [r["name"] for r in out["results"]] == ["global_sensor_outlook_fail_trigger"]


async def test_list_custom_definitions(api: respx.MockRouter) -> None:
    Lab(api)
    async with Client(create_server(make_settings())) as c:
        out = await run(c, "catc_list_issue_definitions", {"kind": "custom", "response_format": "json"})
        assert out["results"] == [] and "No custom" in out["note"]


async def test_list_custom_rule_text(api: respx.MockRouter) -> None:
    Lab(api, custom=[OSPF])
    async with Client(create_server(make_settings())) as c:
        out = await run(c, "catc_list_issue_definitions", {"kind": "custom", "response_format": "json"})
        row = out["results"][0]
        assert row["rules"] == [
            "severity 5 (notice), %OSPF-5-ADJCHG, text matching /from FULL to DOWN/, 1 time(s)"
        ]
        with pytest.raises(ToolError, match="system definitions only"):
            await run(c, "catc_list_issue_definitions", {"kind": "custom", "device_type": "ROUTER"})


async def test_update_disable_by_name(api: respx.MockRouter) -> None:
    lab = Lab(api)
    preview, done = await preview_then_apply(
        "catc_update_issue_definition", {"definition": "BGP_Down", "enabled": False}
    )
    assert preview["status"] == "preview"
    details = preview["preview"]
    assert details["changes"] == {"enabled": {"from": True, "to": False}}
    assert details["before"]["enabled"] is True and details["after"]["enabled"] is False
    assert any("stops raising" in s for s in preview["side_effects"])
    assert done and done["result"]["definition"]["enabled"] is False
    assert lab.sent == [
        (
            "PUT",
            BGP_ID,
            {
                "issueEnabled": False,
                "priority": "P2",
                "synchronizeToHealthThreshold": False,
                "thresholdValue": 3.0,
            },
        )
    ]


async def test_update_priority_default_and_threshold(api: respx.MockRouter) -> None:
    lab = Lab(api)
    preview, done = await preview_then_apply(
        "catc_update_issue_definition", {"definition": "WLC Monitor", "priority": "default", "enabled": True}
    )
    assert preview["preview"]["changes"]["priority"] == {"from": "P1", "to": "P3"}
    assert done and lab.sent[-1] == (
        "PUT",
        WLC_ID,
        {"issueEnabled": True, "priority": "P3", "synchronizeToHealthThreshold": False},
    )
    # By id, a threshold change.
    _, done = await preview_then_apply(
        "catc_update_issue_definition", {"definition": BGP_ID, "threshold": 10}
    )
    assert done and lab.sent[-1][2]["thresholdValue"] == 10


async def test_update_blockers(api: respx.MockRouter) -> None:
    lab = Lab(api)
    out, _ = await preview_then_apply(
        "catc_update_issue_definition", {"definition": "wlc_monitor", "threshold": 5}
    )
    assert out["status"] == "blocked" and "has no threshold" in out["blockers"][0]
    out, _ = await preview_then_apply(
        "catc_update_issue_definition", {"definition": "BGP_Down", "priority": "P2"}
    )
    assert out["status"] == "blocked" and "nothing would change" in out["blockers"][0]
    assert lab.sent == []
    async with Client(rw_server()) as c:
        with pytest.raises(ToolError, match="Nothing to change"):
            await run(c, "catc_update_issue_definition", {"definition": "BGP_Down"})
        with pytest.raises(ToolError, match="No system issue definition named 'bgp-dwn'"):
            await run(c, "catc_update_issue_definition", {"definition": "bgp-dwn", "enabled": False})


async def test_writes_need_the_write_tier(api: respx.MockRouter) -> None:
    Lab(api)
    async with Client(create_server(make_settings())) as c:
        names = {t.name for t in await c.list_tools()}
    assert "catc_list_issue_definitions" in names
    assert (
        not {"catc_update_issue_definition", "catc_create_custom_issue", "catc_delete_custom_issue"} & names
    )


async def test_create_custom_issue(api: respx.MockRouter) -> None:
    lab = Lab(api)
    args = {
        "name": "mcp-ospf-down",
        "severity": 5,
        "facility": "ospf",
        "mnemonic": "adjchg",
        "pattern": "from FULL to DOWN",
        "occurrences": 2,
        "duration_minutes": 10,
        "priority": "P2",
        "notify": True,
    }
    preview, done = await preview_then_apply("catc_create_custom_issue", args)
    assert preview["status"] == "preview"
    assert preview["preview"]["rule"] == (
        "severity 5 (notice), %OSPF-5-ADJCHG, text matching /from FULL to DOWN/, 2 time(s) in 10 min"
    )
    assert done and done["result"]["created"]["id"] == CUSTOM_ID
    method, path, body = lab.sent[0]
    assert (method, path) == ("POST", CUSTOM)
    assert body["rules"] == [
        {
            "severity": 5,
            "occurrences": 2,
            "facility": "OSPF",
            "mnemonic": "ADJCHG",
            "pattern": "from FULL to DOWN",
            "durationInMinutes": 10,
        }
    ]
    assert body["isEnabled"] is True and body["isNotificationEnabled"] is True and body["priority"] == "P2"


async def test_create_custom_issue_blockers(api: respx.MockRouter) -> None:
    lab = Lab(api, custom=[OSPF])
    out, _ = await preview_then_apply(
        "catc_create_custom_issue", {"name": "mcp-ospf-down", "severity": 5, "mnemonic": "ADJCHG"}
    )
    assert out["status"] == "blocked" and "exists already" in out["blockers"][0]
    out, _ = await preview_then_apply("catc_create_custom_issue", {"name": "mcp-any", "severity": 3})
    assert "severity alone" in out["blockers"][0]
    out, _ = await preview_then_apply(
        "catc_create_custom_issue", {"name": "mcp-x", "severity": 3, "mnemonic": "X", "occurrences": 3}
    )
    assert "duration_minutes" in out["blockers"][0]
    assert lab.sent == []
    async with Client(rw_server()) as c:  # preview only
        out = await run(c, "catc_create_custom_issue", {"name": "mcp-x", "severity": 3, "pattern": "([bad"})
    assert out["status"] == "preview" and any("doesn't compile" in s for s in out["side_effects"])
    assert lab.sent == []


async def test_delete_custom_issue(api: respx.MockRouter) -> None:
    lab = Lab(api, custom=[OSPF])
    preview, done = await preview_then_apply("catc_delete_custom_issue", {"definition": "mcp-ospf-down"})
    assert preview["status"] == "preview" and preview["preview"]["definition"]["priority"] == "P2"
    assert any("Notifications subscribed" in s for s in preview["side_effects"])
    assert done and done["result"]["deleted"] == CUSTOM_ID
    assert lab.sent == [("DELETE", CUSTOM_ID, None)]


async def test_delete_points_system_definitions_to_disable(api: respx.MockRouter) -> None:
    Lab(api)
    async with Client(rw_server()) as c:
        with pytest.raises(ToolError, match="disable it with catc_update_issue_definition"):
            await run(c, "catc_delete_custom_issue", {"definition": "BGP_Down"})
        with pytest.raises(ToolError, match="No custom issue definition"):
            await run(c, "catc_delete_custom_issue", {"definition": CUSTOM_ID})


async def test_delete_not_deletable(api: respx.MockRouter) -> None:
    lab = Lab(api, custom=[{**OSPF, "isDeletable": False}])
    out, _ = await preview_then_apply("catc_delete_custom_issue", {"definition": CUSTOM_ID})
    assert out["status"] == "blocked" and "not deletable" in out["blockers"][0]
    assert lab.sent == []


async def test_default_listing_includes_disabled(api: respx.MockRouter) -> None:
    lab = Lab(api)
    async with Client(create_server(make_settings())) as c:
        out = await run(c, "catc_list_issue_definitions", {"response_format": "json"})
        names = [r["name"] for r in out["results"]]
        assert sorted(names) == sorted(
            ["BGP_Down", "global_sensor_outlook_fail_trigger", "wlc_monitor", "radio_util_trigger_2_4ghz"]
        )
        assert len(names) == len(set(names))
        assert {q.get("issueEnabled") for q in lab.queries} == {"true", "false"}
        out = await run(c, "catc_list_issue_definitions", {"search": "2.4 ghz", "response_format": "json"})
        assert [r["name"] for r in out["results"]] == ["radio_util_trigger_2_4ghz"]
        out = await run(
            c, "catc_list_issue_definitions", {"name": "radio_util_trigger_2_4ghz", "response_format": "json"}
        )
        assert [r["enabled"] for r in out["results"]] == [False]
        lab.queries.clear()
        out = await run(c, "catc_list_issue_definitions", {"enabled": True, "response_format": "json"})
        assert "radio_util_trigger_2_4ghz" not in [r["name"] for r in out["results"]]
        assert {q.get("issueEnabled") for q in lab.queries} == {"true"}


async def test_reenable_disabled_by_name(api: respx.MockRouter) -> None:
    lab = Lab(api)
    preview, done = await preview_then_apply(
        "catc_update_issue_definition", {"definition": "radio_util_trigger_2_4ghz", "enabled": True}
    )
    assert preview["status"] == "preview"
    assert preview["preview"]["changes"] == {"enabled": {"from": False, "to": True}}
    assert done and lab.sent[-1][:2] == ("PUT", RADIO_ID) and lab.sent[-1][2]["issueEnabled"] is True
    # By display name too (resolved from the merged full list).
    _, done = await preview_then_apply(
        "catc_update_issue_definition", {"definition": "WLC Monitor", "enabled": True}
    )
    assert done and lab.sent[-1][:2] == ("PUT", WLC_ID)
    # Disable then re-enable the same definition by name (the live failure in #262).
    await preview_then_apply("catc_update_issue_definition", {"definition": "BGP_Down", "enabled": False})
    _, done = await preview_then_apply(
        "catc_update_issue_definition", {"definition": "BGP_Down", "enabled": True}
    )
    assert done and lab.sent[-1] == (
        "PUT",
        BGP_ID,
        {
            "issueEnabled": True,
            "priority": "P2",
            "synchronizeToHealthThreshold": False,
            "thresholdValue": 3.0,
        },
    )


async def test_string_severity_rule_text(api: respx.MockRouter) -> None:
    text = "severity 5 (notice), %OSPF-5-ADJCHG, text matching /from FULL to DOWN/, 1 time(s)"
    lab = Lab(api, custom=[OSPF_LIVE])
    async with Client(create_server(make_settings())) as c:
        out = await run(c, "catc_list_issue_definitions", {"kind": "custom", "response_format": "json"})
    assert out["results"][0]["rules"] == [text]
    preview, _ = await preview_then_apply("catc_delete_custom_issue", {"definition": "mcp-ospf-down"})
    assert preview["preview"]["definition"]["rules"] == [text]
    assert lab.sent == [("DELETE", CUSTOM_ID, None)]


async def test_create_result_with_string_severity(api: respx.MockRouter) -> None:
    lab = Lab(api)

    def post_live(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        lab.sent.append(("POST", CUSTOM, body))
        made = {
            **body,
            "id": CUSTOM_ID,
            "rules": [{**r, "severity": str(r["severity"])} for r in body["rules"]],
        }
        return httpx.Response(200, json={"response": made, "version": "1.0"})

    api.post(CUSTOM).mock(side_effect=post_live)
    _, done = await preview_then_apply(
        "catc_create_custom_issue",
        {"name": "mcp-ospf-adj", "severity": 5, "facility": "OSPF", "mnemonic": "ADJCHG"},
    )
    assert done and done["result"]["created"]["rules"] == ["severity 5 (notice), %OSPF-5-ADJCHG, 1 time(s)"]
