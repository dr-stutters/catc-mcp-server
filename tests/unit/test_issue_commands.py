"""D64: catc_run_issue_commands runs an issue's suggested commands (execute-suggested-actions-commands).

Payloads are synthetic, built from the bundled 3.2.2 spec (ExecuteSuggestedActionsCommandsRequest:
entity_type=issue_id, entity_value) and the documented result rows (actionInfo, stepsCount, entityId,
hostname, stepsDescription, command, commandOutput). The issue record has the data-API shape catc_get_issue
reads; its suggestedActions mirror an OSPF_Down issue on 3.2.2 (a ping, then show commands)."""

import json
from typing import Any

import httpx
import pytest
import respx
from fastmcp.exceptions import ToolError

from catc_mcp.tools.issue_commands import group_results, issue_commands, result_rows

from .test_read_tools import call

IID = "11112222-3333-4444-5555-666677778888"
DEV_ID = "aaaabbbb-cccc-dddd-eeee-000000000064"
ISSUE_PATH = f"/dna/data/api/v1/assuranceIssues/{IID}"
EXECUTE = "/dna/intent/api/v1/execute-suggested-actions-commands"
EXEC_STATUS = "/dna/platform/management/business-api/v1/execution-status/ex-64"
READ_REQUEST = "/dna/intent/api/v1/network-device-poller/cli/read-request"
HOST = "bcp1.example.com"

OSPF_ACTIONS = [
    {"message": "Ping the neighbor IP to verify connectivity.", "steps": [{"command": "ping 192.0.2.2"}]},
    {
        "message": "Check OSPF neighbors.",
        "steps": [{"command": "show ip ospf neighbor"}, {"command": "show ipv6 ospf neighbor"}],
    },
    {"message": "Check authentication.", "steps": [{"command": "show run | sec ospf"}]},
    {"message": "Contact Cisco TAC World Wide"},
]


def issue(actions: list[dict[str, Any]] | None = None, **kw: Any) -> dict[str, Any]:
    return {
        "issueId": IID,
        "name": "OSPF_Down",
        "summary": "OSPF Adjacency Failed on Device bcp1 Interface GigabitEthernet1/0/2",
        "priority": "P2",
        "status": "active",
        "entityType": "network device",
        "entityId": DEV_ID,
        "additionalAttributes": [{"key": "nwDeviceName", "value": HOST}],
        "suggestedActions": OSPF_ACTIONS if actions is None else actions,
        **kw,
    }


def row(command: str, output: Any, action: str = "Check OSPF neighbors.") -> dict[str, Any]:
    return {
        "actionInfo": action,
        "stepsCount": 1,
        "entityId": DEV_ID,
        "hostname": HOST,
        "stepsDescription": action,
        "command": command,
        "commandOutput": output,
    }


def mock_issue(api: respx.MockRouter, data: dict[str, Any] | None = None) -> None:
    api.get(ISSUE_PATH).respond(json={"response": [data or issue()]})


def mock_execute(api: respx.MockRouter, rows: list[dict[str, Any]], status: str = "SUCCESS") -> respx.Route:
    route = api.post(EXECUTE).respond(
        202, json={"executionId": "ex-64", "executionStatusUrl": "/x", "message": "accepted"}
    )
    api.get(EXEC_STATUS).respond(
        json={
            "bapiName": "Execute Suggested Actions Commands",
            "status": status,
            "bapiSyncResponse": json.dumps(rows),
        }
    )
    return route


OK_ROWS = [
    row(
        "ping 192.0.2.2",
        {"ping 192.0.2.2": "ping 192.0.2.2\nSuccess rate is 100 percent (5/5)\nbcp1#"},
        "Ping the neighbor IP to verify connectivity.",
    ),
    row(
        "show ip ospf neighbor",
        "show ip ospf neighbor\nNeighbor ID  Pri State  Dead Time  Address  Interface\n"
        "192.0.2.2  0  FULL/ -  00:00:35  192.0.2.2  GigabitEthernet1/0/2\nbcp1#",
    ),
    row("show ipv6 ospf neighbor", ""),
    row(
        "show run | sec ospf",
        "router ospf 1\n ip ospf message-digest-key 1 md5 7 0822455D0A16\nbcp1#",
        "Check authentication.",
    ),
]


async def test_runs_suggested_commands(api: respx.MockRouter) -> None:
    mock_issue(api)
    post = mock_execute(api, OK_ROWS)
    out = await call("catc_run_issue_commands", {"issue_id": IID})
    assert json.loads(post.calls.last.request.content) == {"entity_type": "issue_id", "entity_value": IID}
    assert out["via"] == "execute-suggested-actions-commands" and out["execution_id"] == "ex-64"
    assert out["issue"]["device"] == HOST and out["issue"]["name"] == "OSPF_Down"
    assert out["commands"] == [
        "ping 192.0.2.2",
        "show ip ospf neighbor",
        "show ipv6 ospf neighbor",
        "show run | sec ospf",
    ]
    (dev,) = out["results"]
    assert dev["device"] == HOST
    output = dev["output"]
    assert output["ping 192.0.2.2"] == "Success rate is 100 percent (5/5)"
    assert (
        output["show ip ospf neighbor"].startswith("Neighbor ID")
        and "bcp1#" not in output["show ip ospf neighbor"]
    )
    assert output["show ipv6 ospf neighbor"] == "(no output)"
    assert "0822455D0A16" not in output["show run | sec ospf"]
    assert out["suggested_actions"][-1] == {"action": "Contact Cisco TAC World Wide", "commands": []}


async def test_partial_failure_and_sync_answer(api: respx.MockRouter) -> None:
    """A synchronous list answer; one command in the runner's own shape failed, the others ran."""
    mock_issue(api)
    rows = [
        OK_ROWS[1],
        row(
            "show ipv6 ospf neighbor",
            {
                "SUCCESS": {},
                "FAILURE": {"show ipv6 ospf neighbor": "% Invalid input detected"},
                "BLACKLISTED": {},
            },
        ),
    ]
    api.post(EXECUTE).respond(200, json={"response": rows})
    out = await call("catc_run_issue_commands", {"issue_id": IID})
    (dev,) = out["results"]
    assert "show ip ospf neighbor" in dev["output"]
    assert dev["failed"] == {"show ipv6 ospf neighbor": "% Invalid input detected"}
    assert "execution_id" not in out


async def test_no_suggested_commands_runs_nothing(api: respx.MockRouter) -> None:
    mock_issue(api, issue([{"message": "Contact Cisco TAC World Wide"}]))
    post = api.post(EXECUTE).respond(500)
    out = await call("catc_run_issue_commands", {"issue_id": IID})
    assert not post.called
    assert out["results"] == [] and "nothing was run" in out["note"]
    assert out["suggested_actions"] == [{"action": "Contact Cisco TAC World Wide", "commands": []}]


async def test_unknown_issue(api: respx.MockRouter) -> None:
    api.get(ISSUE_PATH).respond(
        404, json={"response": {"errorCode": "NOT_FOUND", "message": "Issue not found"}}
    )
    post = api.post(EXECUTE).respond(500)
    with pytest.raises(ToolError):
        await call("catc_run_issue_commands", {"issue_id": IID})
    assert not post.called


async def test_empty_issue_answer_is_not_found(api: respx.MockRouter) -> None:
    api.get(ISSUE_PATH).respond(json={"response": []})
    post = api.post(EXECUTE).respond(500)
    with pytest.raises(ToolError, match="No assurance issue"):
        await call("catc_run_issue_commands", {"issue_id": IID})
    assert not post.called


@pytest.mark.parametrize(
    "bad", ["clear ip ospf process", "debug ip ospf adj", "show run | redirect flash:x", "conf t"]
)
async def test_refuses_when_any_command_is_not_read_only(api: respx.MockRouter, bad: str) -> None:
    mock_issue(api, issue([*OSPF_ACTIONS, {"message": "Reset", "steps": [{"command": bad}]}]))
    post = api.post(EXECUTE).respond(500)
    with pytest.raises(ToolError, match="not read-only"):
        await call("catc_run_issue_commands", {"issue_id": IID})
    assert not post.called


async def test_execute_refused_falls_back_to_command_runner(api: respx.MockRouter) -> None:
    mock_issue(api, issue([OSPF_ACTIONS[1]]))
    api.post(EXECUTE).respond(
        400, json={"response": {"errorCode": "BAD_REQUEST", "message": "Invalid issue id"}}
    )
    sent: list[dict[str, Any]] = []

    def start(request: httpx.Request) -> httpx.Response:
        sent.append(json.loads(request.content))
        return httpx.Response(202, json={"response": {"taskId": "t-64"}})

    api.post(READ_REQUEST).mock(side_effect=start)
    api.get("/dna/intent/api/v1/task/t-64").respond(
        json={"response": {"progress": '{"fileId":"f-64"}', "endTime": 1}}
    )
    api.get("/dna/intent/api/v1/file/f-64").respond(
        json=[
            {
                "deviceUuid": DEV_ID,
                "commandResponses": {
                    "SUCCESS": {"show ip ospf neighbor": "show ip ospf neighbor\nFULL\nbcp1#"},
                    "FAILURE": {},
                    "BLACKLISTED": {},
                },
            }
        ]
    )
    out = await call("catc_run_issue_commands", {"issue_id": IID})
    (body,) = sent
    assert body["deviceUuids"] == [DEV_ID] and body["commands"] == [
        "show ip ospf neighbor",
        "show ipv6 ospf neighbor",
    ]
    assert out["via"].startswith("command runner on the issue's device")
    assert out["results"][0]["output"]["show ip ospf neighbor"] == "FULL"


async def test_client_issue_does_not_fall_back(api: respx.MockRouter) -> None:
    mock_issue(api, issue([OSPF_ACTIONS[1]], entityType="client", entityId="52:54:00:00:00:01"))
    api.post(EXECUTE).respond(400, json={"response": {"message": "Invalid issue id"}})
    runner = api.post(READ_REQUEST).respond(500)
    with pytest.raises(ToolError):
        await call("catc_run_issue_commands", {"issue_id": IID})
    assert not runner.called


def test_issue_commands_dedupes_and_splits() -> None:
    allowed, refused = issue_commands(
        [
            {"commands": ["show  ip ospf neighbor", "ping 192.0.2.2"]},
            {"commands": ["show ip ospf neighbor", "clear counters"]},
        ]
    )
    assert allowed == ["show ip ospf neighbor", "ping 192.0.2.2"] and refused == ["clear counters"]


def test_result_rows_shapes() -> None:
    rows = [row("show clock", "12:00")]
    assert result_rows(rows) == rows
    assert result_rows({"response": rows}) == rows
    assert result_rows({"execution_id": "e", "bapiSyncResponse": rows}) == rows
    assert result_rows({"result": json.dumps(rows)}) == rows
    assert result_rows({"result": None}) == []
    assert group_results([{"entityId": DEV_ID, "command": "show clock", "commandOutput": None}], None) == [
        {"device": DEV_ID, "output": {"show clock": "(no output)"}}
    ]
