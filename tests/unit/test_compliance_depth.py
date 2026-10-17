"""D37: compliance depth (CLI-line rules, policy updates, the compliance report with its trend, and
config drift against a golden device or a template)."""

import copy
import json
import re
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client
from fastmcp.exceptions import ToolError
from pydantic import ValidationError

from catc_mcp.server import create_server
from catc_mcp.tools.compliance import DEFAULT_IGNORE, config_paths, template_missing
from catc_mcp.tools.compliance_policies import RuleSpec, line_regex

from .conftest import make_settings
from .test_compliance_policies import CP, PID, RID, task
from .test_read_tools import call, fixture
from .test_write_tools import preview_then_apply

FIX = fixture("compliance_d37.json")
R1_ID, R2_ID = "11111111-0000-0000-0000-000000000001", "22222222-0000-0000-0000-000000000002"
R1 = {"id": R1_ID, "hostname": "r1.mcp.lab", "managementIpAddress": "10.0.0.1", "family": "Routers"}
R2 = {"id": R2_ID, "hostname": "r2.mcp.lab", "managementIpAddress": "10.0.0.2", "family": "Routers"}
GLOBAL = {"id": "cccccccc-0000-0000-0000-000000000000", "nameHierarchy": "Global", "type": "global"}
BLDG = "Global/Lab/B1"
TPL_ID = "dddddddd-1111-2222-3333-444444444444"
IGNORE = [re.compile(p) for p in DEFAULT_IGNORE]


# --- rules from CLI lines ------------------------------------------------------------------


def test_line_regex_is_exact_and_escaped() -> None:
    rx = line_regex("  ip  access-list extended ACL-1 (x)")
    assert rx == r"^ip\s+access\-list\s+extended\s+ACL\-1\s+\(x\)\s*$"
    assert re.search(rx, "ip access-list extended ACL-1 (x)  ")
    assert not re.search(rx, "ip access-list extended ACL-10 (x)")


def test_rule_from_require_and_forbid_lines() -> None:
    rule = RuleSpec(
        name="r",
        require_lines=["service password-encryption"],
        forbid_lines=["ip http server"],
        severity="CRITICAL",
    )
    req, forbid = rule.all_conditions()
    assert req.violation_when == "does_not_match" and req.operator == "MATCHES_EXPRESSION"
    assert req.value == r"^service\s+password\-encryption\s*$"
    assert req.message == "Missing: service password-encryption" and req.severity == "CRITICAL"
    assert forbid.violation_when == "matches" and forbid.message == "Forbidden: ip http server"
    with pytest.raises(ValidationError, match="needs conditions"):
        RuleSpec(name="empty")


async def test_create_policy_from_cli_lines(api: respx.MockRouter) -> None:
    api.get(CP).respond(json={"response": []})
    out = await call(
        "catc_create_compliance_policy",
        {
            "name": "mcp-d37-pwenc",
            "rules": [
                {
                    "name": "pw",
                    "device_families": ["Routers"],
                    "require_lines": ["service password-encryption"],
                }
            ],
        },
        mcp_enable_writes=True,
    )
    cond = out["preview"]["rules"][0]["conditions"][0]
    assert cond["value"] == r"^service\s+password\-encryption\s*$"
    assert cond["action"]["doesNotMatchAction"] == "RAISE_VIOLATION_AND_CONTINUE"
    assert out["preview"]["rules"][0]["deviceTypes"] == [{"deviceFamily": "Routers"}]


# --- policy updates ------------------------------------------------------------------------


def mock_policy(api: respx.MockRouter) -> None:
    api.get(CP).respond(json={"response": [{"id": PID, "name": "p", "source": "USER"}]})
    api.get(f"{CP}/{PID}").respond(
        json={"response": {"id": PID, "name": "p", "status": "ACTIVE", "rulesCount": 1, "sitesCount": 1}}
    )
    api.get(f"{CP}/{PID}/rules").respond(json={"response": [{"id": RID, "name": "old"}]})


async def test_update_policy_replace_rule_and_rename(api: respx.MockRouter) -> None:
    mock_policy(api)
    new_rid = "eeeeeeee-1111-2222-3333-666666666666"
    order: list[str] = []

    def rec(tag: str, tid: str) -> Any:
        def handler(request: httpx.Request) -> httpx.Response:
            order.append(tag)
            return httpx.Response(202, json={"response": {"taskId": tid}})

        return handler

    put = api.put(f"{CP}/{PID}").mock(side_effect=rec("rename", "t-p"))
    api.delete(f"{CP}/{PID}/rules/{RID}").mock(side_effect=rec("delete", "t-d"))
    add = api.post(f"{CP}/{PID}/rules").mock(side_effect=rec("rule", "t-r"))
    cond = api.post(f"{CP}/{PID}/rules/{new_rid}/conditions").mock(side_effect=rec("cond", "t-c"))
    task(api, "t-p")
    task(api, "t-d")
    task(api, "t-r", f"id={new_rid}")
    task(api, "t-c", "id=c1")
    args = {
        "policy": "p",
        "remove_rules": ["old"],
        "add_rules": [{"name": "old", "forbid_lines": ["ip http server"]}],
        "description": "D37",
    }
    preview, done = await preview_then_apply("catc_update_compliance_policy", args)
    assert preview["status"] == "preview", preview
    assert preview["preview"]["rules_after"] == ["old"]
    assert order == ["rename", "delete", "rule", "cond"]
    assert json.loads(put.calls.last.request.content) == {"id": PID, "name": "p", "description": "D37"}
    assert json.loads(add.calls.last.request.content)["name"] == "old"
    assert json.loads(cond.calls.last.request.content)["action"]["matchAction"].startswith("RAISE")
    assert "removed rule old" in done["result"]["done"]


async def test_update_policy_blockers(api: respx.MockRouter) -> None:
    mock_policy(api)
    out = await call(
        "catc_update_compliance_policy",
        {"policy": "p", "remove_rules": ["nope"], "add_rules": [{"name": "old", "require_lines": ["x"]}]},
        mcp_enable_writes=True,
    )
    assert out["status"] == "blocked"
    assert any("No rule named nope" in b for b in out["blockers"])
    assert any("already exists" in b for b in out["blockers"])
    empty = await call("catc_update_compliance_policy", {"policy": "p"}, mcp_enable_writes=True)
    assert empty["status"] == "blocked" and "Nothing to change" in empty["blockers"][-1]


async def test_update_policy_reports_partial_progress(api: respx.MockRouter) -> None:
    mock_policy(api)
    api.delete(f"{CP}/{PID}/rules/{RID}").respond(202, json={"response": {"taskId": "t-d"}})
    api.post(f"{CP}/{PID}/rules").respond(500, json={"message": "rule boom"})
    task(api, "t-d")
    with pytest.raises(ToolError, match="Done before the failure: removed rule old"):
        await preview_then_apply(
            "catc_update_compliance_policy",
            {"policy": "p", "remove_rules": ["old"], "add_rules": [{"name": "n", "require_lines": ["x"]}]},
        )


# --- compliance report ---------------------------------------------------------------------


def mock_inventory(api: respx.MockRouter) -> None:
    def devices(request: httpx.Request) -> httpx.Response:
        q = request.url.params
        found = [R1, R2]
        if q.get("id"):
            found = [d for d in found if d["id"] in q["id"].split(",")]
        elif q.get("hostname"):
            found = [d for d in found if d["hostname"] == q["hostname"]]
        elif q.get("managementIpAddress") or q.get("serialNumber"):
            found = []
        return httpx.Response(200, json={"response": found})

    api.get("/dna/intent/api/v1/network-device").mock(side_effect=devices)
    for d in (R1, R2):
        api.get(f"/dna/intent/api/v1/network-device/{d['id']}").respond(json={"response": d})
        api.get(f"/dna/intent/api/v1/networkDevices/{d['id']}/assignedToSite").respond(
            json={"response": {"deviceId": d["id"], "siteNameHierarchy": BLDG}}
        )
    api.get("/dna/intent/api/v1/sites").respond(json={"response": [GLOBAL]})


def mock_report(api: respx.MockRouter, devices: dict[str, Any]) -> dict[str, Any]:
    """Mocks the report's calls; the returned holder's "now" is the site's compliance records."""
    mock_inventory(api)
    holder = {"now": devices}
    api.get(f"/dna/intent/api/v1/compliance/sites/{GLOBAL['id']}/networkDevices").mock(
        side_effect=lambda r: httpx.Response(200, json=holder["now"])
    )
    base = f"/dna/intent/api/v1/compliance/networkDevices/{R2_ID}/detail/policys"
    api.get(base).respond(json=FIX["device_policies"])
    api.get(f"{base}/{PID}/violations").respond(json=FIX["device_violations"])
    return holder


async def report(tmp: Path | None) -> Any:
    settings = make_settings(mcp_cache_dir=str(tmp) if tmp else "")
    async with Client(create_server(settings)) as c:
        res = await c.call_tool("catc_compliance_report", {})
    return res.structured_content


async def test_report_by_site_category_severity(api: respx.MockRouter) -> None:
    mock_report(api, FIX["site_devices_run1"])
    out = await report(None)
    assert out["devices"] == 2 and out["non_compliant_devices"] == 2
    assert out["by_status"] == {"NON_COMPLIANT": 1, "COMPLIANT": 1}
    assert out["by_category"]["NETWORK_RULES"] == {"NON_COMPLIANT": 1, "COMPLIANT": 1}
    assert out["by_severity"] == {"MAJOR": 2}
    assert out["by_site"] == [{"site": BLDG, "devices": 2, "non_compliant": 2}]
    r2 = next(b for b in out["non_compliant"] if b["device"] == "r2.mcp.lab")
    assert r2["categories"][0]["category"] == "NETWORK_RULES"
    assert r2["rule_violations"] == [
        {
            "policy": "mcp-d37-pwenc",
            "rule": "password-encryption",
            "severity": "MAJOR",
            "message": "Missing: service password-encryption",
            "condition_seq": 1,
        }
    ]
    assert out["by_rule"] == [
        {"policy": "mcp-d37-pwenc", "rule": "password-encryption", "severity": "MAJOR", "devices": 1}
    ]
    # r2's rule violation appeared in its latest run; r1's unsaved config is older.
    assert out["trend"]["in_last_run"]["new_non_compliant"] == [
        {"device": "r2.mcp.lab", "category": "NETWORK_RULES", "severity": "MAJOR"}
    ]
    assert out["trend"]["in_last_run"]["persisting_non_compliant"] == 1
    assert "since_previous_report" not in out["trend"]  # no cache directory


async def test_report_trend_between_runs(api: respx.MockRouter, tmp_path: Path) -> None:
    run1 = FIX["site_devices_run1"]
    holder = mock_report(api, run1)
    first = await report(tmp_path)
    assert "No earlier report" in first["trend"]["since_previous_report"]
    # Same run again: still nothing to compare with.
    again = await report(tmp_path)
    assert isinstance(again["trend"]["since_previous_report"], str)
    # Next run: r1 saved its config (RUNNING_CONFIG fixed); r2 is still in violation.
    run2 = copy.deepcopy(run1)
    for rec in run2["response"]:
        rec["lastComplianceExecutionTime"] += 3_600_000
    r1 = next(r for r in run2["response"] if r["networkDeviceId"] == R1_ID)
    r1["details"][1]["status"] = "COMPLIANT"
    holder["now"] = run2
    second = await report(tmp_path)
    trend = second["trend"]["since_previous_report"]
    assert trend["resolved"] == [{"device": "r1.mcp.lab", "item": "RUNNING_CONFIG"}]
    assert trend["non_compliant_items_before"] == 3 and trend["non_compliant_items_now"] == 2
    assert "new" not in trend  # empty lists are dropped from the output
    history = json.loads((tmp_path / "compliance-history.json").read_text())
    assert len(next(iter(history.values()))) == 2


# --- config drift --------------------------------------------------------------------------


def test_config_paths_nesting_ignore_and_only() -> None:
    paths = config_paths(FIX["golden_config"], IGNORE)
    assert "service password-encryption" in paths
    assert "interface GigabitEthernet1 > ip address 198.18.128.152 255.255.192.0" in paths
    assert "line vty 0 4 > transport input ssh" in paths
    assert not any(p.startswith(("hostname", "version", "crypto pki", "Building", "end")) for p in paths)
    assert not any("3082" in p for p in paths)  # certificate children go with their parent
    only = config_paths(FIX["golden_config"], IGNORE, [re.compile("^service ")])
    assert only == [
        "service timestamps debug datetime msec",
        "service timestamps log datetime msec",
        "service password-encryption",
    ]


def test_template_missing_handles_negations() -> None:
    have = {"service password-encryption", "interface Gi1 > no shutdown", "interface Gi1 > description x"}
    expected = [
        "service password-encryption",
        "no ip http server",  # absent positive line: satisfied
        "no service password-encryption",  # positive line present: drift
        "interface Gi1 > no description",  # 'description x' present: drift
        "interface Gi1 > no shutdown",
        "logging host 10.0.0.9",
    ]
    assert template_missing(expected, have) == [
        "no service password-encryption",
        "interface Gi1 > no description",
        "logging host 10.0.0.9",
    ]


def mock_archive(api: respx.MockRouter) -> None:
    files = {R1_ID: "f1", R2_ID: "f2"}

    def listing(request: httpx.Request) -> httpx.Response:
        did = request.url.params.get("networkDeviceId")
        if did not in files:
            return httpx.Response(200, json={"response": []})
        return httpx.Response(
            200,
            json={
                "response": [{"id": files[did], "fileType": "RUNNINGCONFIG", "createdTime": 1792201879000}]
            },
        )

    api.get("/dna/intent/api/v1/networkDeviceConfigFiles").mock(side_effect=listing)
    api.post("/dna/intent/api/v1/networkDeviceConfigFiles/f1/downloadMasked").respond(
        json=FIX["golden_config"]
    )
    api.post("/dna/intent/api/v1/networkDeviceConfigFiles/f2/downloadMasked").respond(
        json=FIX["drifted_config"]
    )


async def test_drift_against_golden_device(api: respx.MockRouter) -> None:
    mock_inventory(api)
    mock_archive(api)
    out = await call("catc_config_drift", {"against": "golden", "golden_device": "r1.mcp.lab"})
    assert out["golden"]["device"] == "r1.mcp.lab"
    assert out["checked"] == 1 and out["drifted"] == ["r2.mcp.lab"]
    row = out["results"][0]
    assert "service password-encryption" in row["missing"]
    assert "line vty 0 4 > transport input ssh telnet" in row["extra"]
    # Masked secrets compare equal; certificates and hostnames are ignored.
    assert not any("username" in x or "hostname" in x for x in row["missing"] + row["extra"])
    scoped = await call(
        "catc_config_drift",
        {
            "against": "golden",
            "golden_device": "r1.mcp.lab",
            "devices": ["r2.mcp.lab"],
            "only": ["^service "],
        },
    )
    assert scoped["results"][0]["missing"] == ["service password-encryption"]
    assert scoped["results"][0]["extra_count"] == 0 and "notes" not in scoped


async def test_drift_against_template(api: respx.MockRouter) -> None:
    mock_inventory(api)
    mock_archive(api)
    tpl = {"templateId": TPL_ID, "name": "mcp-d37-baseline", "projectName": "mcp-d37"}
    api.get("/dna/intent/api/v1/template-programmer/template").respond(json=[tpl])
    preview = api.put("/dna/intent/api/v1/template-programmer/template/preview").respond(
        json={
            "cliPreview": "service password-encryption\nline vty 0 4\n transport input ssh\n",
            "validationErrors": [],
        }
    )
    out = await call(
        "catc_config_drift",
        {
            "against": "template",
            "template": "mcp-d37/mcp-d37-baseline",
            "devices": ["r1.mcp.lab", "r2.mcp.lab"],
        },
    )
    assert out["template"] == "mcp-d37/mcp-d37-baseline"
    assert out["drifted"] == ["r2.mcp.lab"] and out["in_line"] == ["r1.mcp.lab"]
    r2 = out["results"][0]
    assert r2["missing"] == ["service password-encryption", "line vty 0 4 > transport input ssh"]
    assert r2["template_lines"] == 3
    sent = json.loads(preview.calls.last.request.content)
    assert sent["templateId"] == TPL_ID and sent["deviceId"] in (R1_ID, R2_ID)


async def test_drift_argument_checks_and_missing_archive(api: respx.MockRouter) -> None:
    mock_inventory(api)
    api.get("/dna/intent/api/v1/networkDeviceConfigFiles").respond(json={"response": []})
    with pytest.raises(ToolError, match="needs golden_device"):
        await call("catc_config_drift", {"against": "golden"})
    with pytest.raises(ToolError, match="needs devices or site"):
        await call("catc_config_drift", {"against": "template", "template": "x"})
    with pytest.raises(ToolError, match="Bad ignore regex"):
        await call("catc_config_drift", {"against": "golden", "golden_device": "r1.mcp.lab", "ignore": ["("]})
    with pytest.raises(ToolError, match="no archived running config"):
        await call("catc_config_drift", {"against": "golden", "golden_device": "r1.mcp.lab"})
