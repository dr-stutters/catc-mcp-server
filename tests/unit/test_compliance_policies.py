"""D4: compliance policy authoring (payloads, rollback, violations, site assignment)."""

import json
from typing import Any

import httpx
import pytest
import respx
from fastmcp.exceptions import ToolError

from catc_mcp.tools.compliance_policies import ConditionSpec, condition_body, violation_rows

from .test_read_tools import DEV_ID, call, mock_device_lookup
from .test_write_tools import preview_then_apply

CP = "/dna/intent/api/v1/compliancePolicys"
PID = "eeeeeeee-1111-2222-3333-444444444444"
RID = "eeeeeeee-1111-2222-3333-555555555555"
LAB = {"id": "cccccccc-1111-2222-3333-444444444444", "nameHierarchy": "Global/Lab", "name": "Lab"}
CHILD = {"id": "cccccccc-1111-2222-3333-555555555555", "nameHierarchy": "Global/Lab/B1", "name": "B1"}
OTHER = {"id": "cccccccc-1111-2222-3333-666666666666", "nameHierarchy": "Global/Other", "name": "Other"}


def sites(api: respx.MockRouter) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        q = request.url.params.get("nameHierarchy")
        found = [s for s in (LAB, CHILD, OTHER) if q is None or s["nameHierarchy"] == q]
        return httpx.Response(200, json={"response": found})

    api.get("/dna/intent/api/v1/sites").mock(side_effect=handler)


def task(api: respx.MockRouter, tid: str, data: str = "", error: bool = False) -> None:
    api.get(f"/dna/intent/api/v1/task/{tid}").respond(
        json={
            "response": {
                "id": tid,
                "endTime": 1,
                "isError": error,
                "data": data,
                "progress": "x",
                "failureReason": "bad regex" if error else None,
            }
        }
    )


def test_condition_body_violation_sides() -> None:
    bad_line = condition_body(
        ConditionSpec(operator="MATCHES_EXPRESSION", value="^ip http server", violation_when="matches")
    )
    assert bad_line["action"] == {
        "matchAction": "RAISE_VIOLATION_AND_CONTINUE",
        "doesNotMatchAction": "DO_NOT_RAISE_VIOLATION_AND_CONTINUE",
        "matchViolationSeverity": "MAJOR",
        "matchViolationMessageType": "DEFAULT_MESSAGE",
    }
    missing = condition_body(
        ConditionSpec(
            operator="CONTAINS_STRING",
            value="banner login",
            violation_when="does_not_match",
            severity="MINOR",
            message="Login banner missing",
            block_start="^line vty",
        )
    )
    assert missing["action"]["doesNotMatchAction"] == "RAISE_VIOLATION_AND_CONTINUE"
    assert missing["action"]["doesNotMatchViolationMessage"] == "Login banner missing"
    assert missing["parseAsBlocks"] is True and missing["blockStartExpression"] == "^line vty"


def test_violation_rows_nested_and_flat() -> None:
    nested = {
        "ruleName": "no-http",
        "violations": [{"violationMessage": "must not match", "severity": "MAJOR", "sequenceNumber": 1}],
        "errors": [],
    }
    assert violation_rows(nested) == [
        {"rule": "no-http", "severity": "MAJOR", "message": "must not match", "condition_seq": 1}
    ]
    flat = {"ruleName": "no-http", "hostname": "r1", "severity": "MAJOR", "violationMessage": "m"}
    assert violation_rows(flat)[0]["device"] == "r1"


RULES = [
    {
        "name": "no-http",
        "conditions": [
            {"operator": "MATCHES_EXPRESSION", "value": "^ip http server", "violation_when": "matches"}
        ],
    }
]


async def test_create_policy_rules_conditions_and_sites(api: respx.MockRouter) -> None:
    sites(api)
    policies: list[dict[str, Any]] = []
    api.get(CP).mock(side_effect=lambda r: httpx.Response(200, json={"response": policies}))
    api.get(f"{CP}/{PID}").respond(
        json={"response": {"id": PID, "name": "p", "status": "ACTIVE", "rulesCount": 1}}
    )

    def make(request: httpx.Request) -> httpx.Response:
        policies.append({"id": PID, "name": "p"})
        return httpx.Response(202, json={"response": {"taskId": "t-pol"}})

    api.post(CP).mock(side_effect=make)
    rule = api.post(f"{CP}/{PID}/rules").respond(202, json={"response": {"taskId": "t-rule"}})
    cond = api.post(f"{CP}/{PID}/rules/{RID}/conditions").respond(202, json={"response": {"taskId": "t-c"}})
    assign = api.put(f"{CP}/{PID}/siteAssignments").respond(202, json={"response": {"taskId": "t-a"}})
    task(api, "t-pol", f"id={PID}")
    task(api, "t-rule", f"id={RID}")
    task(api, "t-c", "id=c1")
    task(api, "t-a")
    preview, done = await preview_then_apply(
        "catc_create_compliance_policy", {"name": "p", "rules": RULES, "sites": ["Global/Lab"]}
    )
    assert preview["preview"]["rules"][0]["conditions"][0]["value"] == "^ip http server"
    assert json.loads(rule.calls.last.request.content)["deviceTypes"] == [
        {"deviceFamily": "Routers"},
        {"deviceFamily": "Switches and Hubs"},
    ]
    assert json.loads(cond.calls.last.request.content)["operator"] == "MATCHES_EXPRESSION"
    assert json.loads(assign.calls.last.request.content) == {"siteIds": [LAB["id"]]}
    assert done["result"]["status"] == "ACTIVE"


async def test_create_policy_rolls_back_on_failure(api: respx.MockRouter) -> None:
    sites(api)
    api.get(CP).respond(json={"response": []})
    api.post(CP).respond(202, json={"response": {"taskId": "t-pol"}})
    api.post(f"{CP}/{PID}/rules").respond(202, json={"response": {"taskId": "t-rule"}})
    api.post(f"{CP}/{PID}/rules/{RID}/conditions").respond(202, json={"response": {"taskId": "t-c"}})
    delete = api.delete(f"{CP}/{PID}").respond(202, json={"response": {"taskId": "t-d"}})
    task(api, "t-pol", f"id={PID}")
    task(api, "t-rule", f"id={RID}")
    task(api, "t-c", error=True)
    task(api, "t-d")
    with pytest.raises(ToolError, match="bad regex"):
        await preview_then_apply("catc_create_compliance_policy", {"name": "p", "rules": RULES})
    assert delete.called


async def test_create_policy_duplicate_blocked(api: respx.MockRouter) -> None:
    api.get(CP).respond(json={"response": [{"id": PID, "name": "P"}]})
    out = await call("catc_create_compliance_policy", {"name": "p", "rules": RULES}, mcp_enable_writes=True)
    assert out["status"] == "blocked"


async def test_assign_modes(api: respx.MockRouter) -> None:
    sites(api)
    api.get(CP).respond(json={"response": [{"id": PID, "name": "p"}]})
    api.get(f"{CP}/{PID}/siteAssignments").respond(json={"response": {"siteIds": [LAB["id"], CHILD["id"]]}})
    added = await call(
        "catc_assign_compliance_policy", {"policy": "p", "sites": ["Global/Other"]}, mcp_enable_writes=True
    )
    assert added["preview"]["after"] == ["Global/Lab", "Global/Lab/B1", "Global/Other"]
    removed = await call(
        "catc_assign_compliance_policy",
        {"policy": "p", "sites": ["Global/Lab"], "mode": "remove"},
        mcp_enable_writes=True,
    )
    assert removed["preview"]["after"] == []
    same = await call(
        "catc_assign_compliance_policy", {"policy": "p", "sites": ["Global/Lab"]}, mcp_enable_writes=True
    )
    assert same["status"] == "blocked"


async def test_device_violations(api: respx.MockRouter) -> None:
    mock_device_lookup(api)
    base = f"/dna/intent/api/v1/compliance/networkDevices/{DEV_ID}/detail/policys"
    api.get(base).respond(json={"response": [{"policyId": PID, "policyName": "p", "violationsCount": 1}]})
    api.get(f"{base}/{PID}/violations").respond(
        json={
            "response": [
                {"ruleName": "no-http", "violations": [{"violationMessage": "m", "severity": "MAJOR"}]}
            ]
        }
    )
    out = await call("catc_list_compliance_violations", {"device": "edge-sw1", "response_format": "json"})
    assert out["results"] == [
        {
            "policy": "p",
            "device": "edge-sw1.lab.local",
            "rule": "no-http",
            "severity": "MAJOR",
            "message": "m",
        }
    ]


async def test_delete_system_policy_blocked(api: respx.MockRouter) -> None:
    api.get(CP).respond(json={"response": [{"id": PID, "name": "sys", "source": "SYSTEM"}]})
    out = await call(
        "catc_delete_compliance_policy", {"policy": "sys"}, mcp_enable_writes=True, mcp_enable_dangerous=True
    )
    assert out["status"] == "blocked"
