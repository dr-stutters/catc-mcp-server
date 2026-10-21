"""D75: catc_update_policy_server and catc_get_policy_servers' next_action / include_sites, on the
policy-server and integration-status payloads recorded from the 3.2.2 lab (tests/fixtures/
ise_integration_322.json; the WAITING/COMPLETE states follow the same shape). Passwords never leak."""

import copy
import json
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client

from catc_mcp.tools.aaa import next_action, server_row

from .test_aaa import rw
from .test_read_tools import AREA, GLOBAL
from .test_write_tools import mock_sites, run, task_ok

FIX = json.loads((Path(__file__).parent.parent / "fixtures" / "ise_integration_322.json").read_text())
SID = "b35d4a18-cf83-4a88-89c2-f6a95a00dc48"
POLICY = "/dna/intent/api/v1/authentication-policy-servers"
STATUS = "/dna/intent/api/v1/ise-integration-status"
PASSWORD = "ise-pa55-d75"
CERT = {
    "certificateChain": [
        {
            "subjectDn": "CN=ise.mitchcloud.lab",
            "issuerDn": "CN=mitchcloud-CA,DC=mitchcloud,DC=lab",
            "fingerPrints": {"SHA-256": "AB:CD"},
        }
    ]
}


def servers() -> list[dict[str, Any]]:
    return copy.deepcopy(FIX["servers_failed"]["response"])


def status(
    overall: str,
    steps: dict[int, str],
    extra: dict[int, dict[str, Any]] | None = None,
    t: int = 1792300000000,
) -> dict[str, Any]:
    """An integration status in the recorded shape: step order -> stepStatus (and extra step fields)."""
    st: dict[str, Any] = copy.deepcopy(FIX["status_failed"])
    st["overallStatus"] = overall
    st.pop("overallErrorMessage", None)
    for s in st["steps"]:
        s["stepTime"] = t
        s.pop("errorMessage", None)
        if s["stepOrder"] in steps:
            s["stepStatus"] = steps[s["stepOrder"]]
            s.update((extra or {}).get(s["stepOrder"], {}))
    return st


WAITING = status(
    "WAITING_USER_INPUT",
    {1: "COMPLETE", 2: "WAITING_USER_INPUT"},
    {2: {"certificate": json.dumps(CERT)}},
)
COMPLETE = status("COMPLETE", {1: "COMPLETE", 2: "COMPLETE", 3: "COMPLETE", 4: "COMPLETE"})


def summary(st: dict[str, Any]) -> dict[str, Any] | None:
    from catc_mcp.tools.aaa import integration_summary

    return integration_summary(st)


# --- next_action -----------------------------------------------------------------------------------


def test_next_action_recorded_failed_entry_names_the_fqdn() -> None:
    row = server_row(servers()[0])
    act = next_action(row, summary(FIX["status_failed"]))
    assert act["action"] == "update_entry" and act["field"] == "fqdn"
    assert act["tool"] == "catc_update_policy_server" and "certificate" in act["detail"]
    assert "ise.demo.mitchcloud.lab" in act["why"]


@pytest.mark.parametrize(
    ("message", "field", "word"),
    [
        ("Unable to resolve host ise.mitchcloud.lab: Name or service not known", "fqdn", "DNS"),
        ("Invalid credentials: 401 Unauthorized from ERS", "ise_password", "password"),
        ("Something unexpected happened", None, None),
    ],
)
def test_next_action_failure_messages(message: str, field: str | None, word: str | None) -> None:
    st = status("FAILED", {1: "FAILED"}, {1: {"errorMessage": message}})
    st["overallErrorMessage"] = message
    act = next_action(server_row(servers()[0]), summary(st))
    assert act["action"] == "update_entry" and act["field"] == field and act["why"] == message
    if word:
        assert word in act["detail"]
    else:
        assert "detail" not in act


def test_next_action_waiting_complete_pxgrid_and_running() -> None:
    row = server_row(servers()[0])
    assert next_action(row, summary(WAITING))["action"] == "accept_certificate"
    trusted = copy.deepcopy(servers()[0])
    trusted["state"], trusted["ciscoIseDtos"][0]["trustState"] = "ACTIVE", "TRUSTED"
    trusted["ciscoIseDtos"][0].pop("failureReason")
    assert next_action(server_row(trusted), summary(COMPLETE)) == {"action": "none"}
    px_failed = status(
        "FAILED",
        {1: "COMPLETE", 2: "COMPLETE", 3: "COMPLETE", 4: "FAILED"},
        {4: {"errorMessage": "pxGrid client approval pending"}},
    )
    act = next_action(row, summary(px_failed))
    assert act["action"] == "approve_pxgrid_on_ise" and act["subscriber"] == "catalyst-center1792201681"
    running = status("INPROGRESS", {1: "COMPLETE", 2: "COMPLETE", 3: "INPROGRESS"})
    assert next_action(row, summary(running))["action"] == "wait"
    px_running = status("INPROGRESS", {1: "COMPLETE", 2: "COMPLETE", 3: "COMPLETE", 4: "INPROGRESS"})
    assert next_action(row, summary(px_running))["action"] == "approve_pxgrid_on_ise"
    plain = {"ipAddress": "10.0.0.9", "isIseEnabled": False, "state": "ACTIVE", "instanceUuid": "x"}
    assert next_action(server_row(plain), None) == {"action": "none"}


async def test_get_policy_servers_next_action_without_site_walk(api: respx.MockRouter) -> None:
    api.get(POLICY).respond(json=FIX["servers_failed"])
    api.get(STATUS).respond(json=FIX["status_failed"])
    walk = api.get("/dna/intent/api/v1/sites")
    async with Client(rw()) as c:
        out = await run(c, "catc_get_policy_servers", {})
    srv = out["servers"][0]
    assert srv["next_action"]["action"] == "update_entry" and srv["next_action"]["field"] == "fqdn"
    assert "sites" not in srv and walk.call_count == 0


async def test_get_policy_servers_include_sites(api: respx.MockRouter) -> None:
    api.get(POLICY).respond(json=FIX["servers_failed"])
    api.get(STATUS).respond(json=COMPLETE)
    mock_sites(api, [GLOBAL, AREA])
    api.get(f"/dna/intent/api/v1/sites/{GLOBAL['id']}/aaaSettings").respond(
        json={"response": {"aaaNetwork": {}, "aaaClient": {}}}
    )
    area = api.get(f"/dna/intent/api/v1/sites/{AREA['id']}/aaaSettings").respond(
        json={
            "response": {
                "aaaNetwork": {},
                "aaaClient": {"serverType": "ISE", "protocol": "RADIUS", "primaryServerIp": "198.18.134.35"},
            }
        }
    )
    async with Client(rw()) as c:
        out = await run(c, "catc_get_policy_servers", {"include_sites": True})
    assert out["servers"][0]["sites"] == [{"site": "Global/AU", "roles": ["client"]}]
    assert out["sites_checked"] == 2
    assert area.calls.last.request.url.params["_inherited"] == "false"


# --- catc_update_policy_server -------------------------------------------------------------------


def mock_update(
    api: respx.MockRouter, states: list[dict[str, Any]], after: dict[str, Any] | None = None
) -> Any:
    """The recorded FAILED entry; the PUT starts a task and the status moves through `states` (the first
    one is what the appliance still shows right after the PUT)."""
    current = {"rows": servers()}
    queue = [FIX["status_failed"]]

    def get_status(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=queue.pop(0) if len(queue) > 1 else queue[0])

    def put(request: httpx.Request) -> httpx.Response:
        queue.clear()
        queue.extend([FIX["status_failed"], *states])
        if after is not None:
            current["rows"] = [after]
        return httpx.Response(202, json={"response": {"taskId": "t-upd", "url": "/api/v1/task/t-upd"}})

    api.get(POLICY).mock(side_effect=lambda r: httpx.Response(200, json={"response": current["rows"]}))
    api.get(STATUS).mock(side_effect=get_status)
    task_ok(api, "t-upd", progress="Operation Successful")
    return api.put(f"{POLICY}/{SID}").mock(side_effect=put)


async def test_update_fqdn_masks_password_waits_for_certificate(api: respx.MockRouter) -> None:
    waiting_row = servers()[0]
    waiting_row["state"] = "INPROGRESS"
    waiting_row["ciscoIseDtos"][0] |= {"fqdn": "ise.mitchcloud.lab", "failureReason": ""}
    put = mock_update(api, [status("INPROGRESS", {1: "INPROGRESS"}), WAITING], after=waiting_row)
    args = {"server": "198.18.134.35", "fqdn": "ise.mitchcloud.lab", "ise_password": PASSWORD}
    async with Client(rw()) as c:
        preview = await run(c, "catc_update_policy_server", args)
        assert preview["status"] == "preview" and PASSWORD not in json.dumps(preview)
        p = preview["preview"]
        assert p["changes"] == {"fqdn": {"from": "ise.demo.mitchcloud.lab", "to": "ise.mitchcloud.lab"}}
        assert p["body"]["ciscoIseDtos"][0]["password"] != PASSWORD
        assert any("catc_accept_ise_certificate" in e for e in p["effects"])
        assert any("shared secret" in e for e in p["effects"]) and put.call_count == 0
        done = await run(c, "catc_update_policy_server", {**args, "confirm": preview["confirm"]})
    sent = json.loads(put.calls.last.request.content)
    assert sent == {
        "protocol": "RADIUS_TACACS",
        "retries": "3",
        "timeoutSeconds": "4",
        "authenticationPort": 1812,
        "accountingPort": 1813,
        "port": 49,
        "pxgridEnabled": True,
        "useDnacCertForPxgrid": False,
        "ciscoIseDtos": [{"fqdn": "ise.mitchcloud.lab", "userName": "admin", "password": PASSWORD}],
    }
    res = done["result"]
    assert PASSWORD not in json.dumps(done)
    # The stale FAILED status left from before the edit is not taken as the result.
    assert res["integration"]["status"] == "WAITING_USER_INPUT"
    assert res["integration"]["certificate_to_accept"][0]["subjectDn"] == "CN=ise.mitchcloud.lab"
    assert res["next_action"]["action"] == "accept_certificate"


async def test_update_ise_needs_password(api: respx.MockRouter) -> None:
    put = mock_update(api, [WAITING])
    async with Client(rw()) as c:
        out = await run(c, "catc_update_policy_server", {"server": SID, "fqdn": "ise.mitchcloud.lab"})
    assert out["status"] == "blocked" and "ise_password" in json.dumps(out["blockers"])
    assert put.call_count == 0


async def test_update_pxgrid_off_and_password_reentry(api: respx.MockRouter) -> None:
    put = mock_update(api, [COMPLETE])
    args = {"server": "198.18.134.35", "pxgrid": False, "ise_password": PASSWORD, "wait": False}
    async with Client(rw()) as c:
        preview = await run(c, "catc_update_policy_server", args)
        assert preview["preview"]["changes"] == {"pxgridEnabled": {"from": True, "to": False}}
        assert any("pxGrid off" in e for e in preview["preview"]["effects"])
        await run(c, "catc_update_policy_server", {**args, "confirm": preview["confirm"]})
        again = await run(c, "catc_update_policy_server", {"server": SID, "ise_password": PASSWORD})
    assert json.loads(put.calls.last.request.content)["pxgridEnabled"] is False
    # Password only: no field changes, still a valid edit (re-entry), said so in the preview.
    assert again["status"] == "preview" and again["preview"]["changes"] == {}
    assert any("re-enters the ISE password" in e for e in again["preview"]["effects"])


async def test_update_blocks_protocol_narrowing_and_running_integration(api: respx.MockRouter) -> None:
    api.get(POLICY).respond(json=FIX["servers_failed"])
    api.get(STATUS).respond(json=status("INPROGRESS", {1: "INPROGRESS"}))
    async with Client(rw()) as c:
        out = await run(
            c, "catc_update_policy_server", {"server": SID, "protocol": "RADIUS", "ise_password": PASSWORD}
        )
    text = json.dumps(out["blockers"])
    assert out["status"] == "blocked" and "RADIUS_TACACS" in text and "running" in text


async def test_update_plain_aaa_server(api: respx.MockRouter) -> None:
    plain = {
        "ipAddress": "10.0.0.9",
        "protocol": "RADIUS",
        "authenticationPort": 1812,
        "accountingPort": 1813,
        "retries": 3,
        "timeoutSeconds": 4,
        "isIseEnabled": False,
        "instanceUuid": "aaaa0000-1111-2222-3333-444455556666",
        "state": "ACTIVE",
    }
    api.get(POLICY).respond(json={"response": [plain]})
    put = api.put(f"{POLICY}/{plain['instanceUuid']}").respond(202, json={"response": {"taskId": "t-p"}})
    task_ok(api, "t-p")
    status_route = api.get(STATUS)
    async with Client(rw()) as c:
        res = await c.call_tool(
            "catc_update_policy_server", {"server": "10.0.0.9", "fqdn": "x.lab"}, raise_on_error=False
        )
        assert res.is_error and "fqdn" in res.content[0].text
        preview = await run(c, "catc_update_policy_server", {"server": "10.0.0.9", "timeout_seconds": 10})
        assert preview["preview"]["changes"] == {"timeoutSeconds": {"from": 4, "to": 10}}
        done = await run(
            c,
            "catc_update_policy_server",
            {"server": "10.0.0.9", "timeout_seconds": 10, "confirm": preview["confirm"]},
        )
    assert json.loads(put.calls.last.request.content) == {
        "protocol": "RADIUS",
        "retries": "3",
        "timeoutSeconds": "10",
        "authenticationPort": 1812,
        "accountingPort": 1813,
    }
    assert status_route.call_count == 0 and done["result"]["next_action"] == {"action": "none"}


async def test_update_changed_password_invalidates_token(api: respx.MockRouter) -> None:
    put = mock_update(api, [WAITING])
    args = {"server": SID, "fqdn": "ise.mitchcloud.lab", "ise_password": PASSWORD}
    async with Client(rw()) as c:
        preview = await run(c, "catc_update_policy_server", args)
        res = await c.call_tool(
            "catc_update_policy_server",
            {**args, "ise_password": "other", "confirm": preview["confirm"]},
            raise_on_error=False,
        )
    assert put.call_count == 0
    assert res.is_error or (res.structured_content or {}).get("status") != "applied"


def test_next_action_recorded_waiting_and_complete() -> None:
    """The live run (2026-10-21): after the FQDN edit 3.2.2 waits at step 1 for ISE's admin certificate; after
    the accept the entry is ACTIVE with a PRIMARY and a PXGRID node, both TRUSTED."""
    st = summary(FIX["status_waiting"])
    assert (
        st
        and st["certificate_to_accept"][0]["fingerPrints"]["SHA-1"]
        == "01B37DD8104BF6FB14DB08008FD538D6C3A28ACC"
    )
    assert next_action(server_row(servers()[0]), st)["action"] == "accept_certificate"
    row = server_row(FIX["servers_complete"]["response"][0])
    assert {n["role"] for n in row["ise_nodes"]} == {"PRIMARY", "PXGRID"}
    assert next_action(row, summary(FIX["status_complete"])) == {"action": "none"}


async def test_update_complete_entry_resends_the_primary_node(api: respx.MockRouter) -> None:
    api.get(POLICY).respond(json=FIX["servers_complete"])
    api.get(STATUS).respond(json=FIX["status_complete"])
    async with Client(rw()) as c:
        out = await run(
            c, "catc_update_policy_server", {"server": SID, "ise_password": PASSWORD, "retries": 2}
        )
    body = out["preview"]["body"]
    assert out["status"] == "preview" and out["preview"]["changes"] == {"retries": {"from": 3, "to": 2}}
    assert body["ciscoIseDtos"] == [
        {"fqdn": "ise.mitchcloud.lab", "userName": "admin", "password": "********"}
    ]
